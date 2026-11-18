"""端到端测试：真实进程启动 uvicorn 管理面与 TLS 演示服务。

覆盖：
  E2E-1 启动即用自签演示证书，/docs 可访问，指纹与管理面一致；
  E2E-2 经管理 API 成功换证，新握手呈现新证书指纹；
  E2E-3 换证期间在途慢请求不中断，且整条连接始终使用旧证书；
  E2E-4 交错换证（CAS）：晚到的旧 expected_version 被 409 拒绝；
  E2E-5 校验失败（私钥不匹配 / SAN 不符 / 过期）返回 400，旧证书继续服务；
  E2E-6 重启 TLS 服务后使用最后完整保存的版本；
  E2E-7 探测成功路径：并发新连接全部成功，按实际指纹归组，无 unknown；
  E2E-8 探测与换证交错：换证前后样本各自归属握手时实际取得的证书；
  E2E-9 探测失败：目标不可达时失败计入 unknown，不产生任何成功；
  E2E-10 单轮限制：第二轮在运行期发起返回 409；参数越界返回 422；
  E2E-11 管理面进程被杀死后已完成样本仍可查，未完成标为 interrupted；
  E2E-12 /docs 与 openapi 包含探测端点。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
# 支持 `python -I`：隔离模式忽略 PYTHONPATH，显式加入外部依赖目录（若存在）
_deps = Path("/tmp/pydeps")
if _deps.is_dir():
    sys.path.insert(0, str(_deps))

from app.cert_store import fingerprint_sha256, generate_self_signed_cert  # noqa: E402
from tests.helpers import (  # noqa: E402
    http_get,
    http_post_json,
    post_rotate,
    slow_request_on_dedicated_connection,
    tls_handshake_fingerprint,
    wait_probe_done,
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class E2ETestCase(unittest.TestCase):
    procs: list[subprocess.Popen] = []
    log_handles: list = []
    data_dir: str = ""
    mgmt_port = 0
    tls_port = 0
    log_dir = ""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="certrotate-e2e-data-")
        cls.log_dir = tempfile.mkdtemp(prefix="certrotate-e2e-logs-")
        cls.mgmt_port = free_port()
        cls.tls_port = free_port()
        base_env = os.environ.copy()
        base_env["CERT_DATA_DIR"] = cls.data_dir
        base_env["CERT_POLL_INTERVAL"] = "0.3"
        # 探测默认目标显式指向本套用例的 TLS 演示服务
        base_env["PROBE_TARGET_HOST"] = "127.0.0.1"
        base_env["PROBE_TARGET_PORT"] = str(cls.tls_port)
        base_env["PROBE_TARGET_HOSTNAME"] = "api.local"
        # 把当前解释器可用的路径（含隔离模式下显式加入的依赖目录）传给子进程
        extra_paths = [str(REPO_ROOT)] + [
            p for p in sys.path if p and Path(p).is_dir() and p != str(REPO_ROOT)
        ]
        base_env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(extra_paths))

        cls._spawn(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(cls.mgmt_port)],
            base_env,
            "mgmt.log",
        )
        cls._wait_http(f"http://127.0.0.1:{cls.mgmt_port}/health", timeout=30)

        cls._spawn(
            [sys.executable, "-m", "app.tls_service"],
            {**base_env, "TLS_HOST": "127.0.0.1", "TLS_PORT": str(cls.tls_port)},
            "tls.log",
        )
        cls._wait_tls(timeout=30)

    @classmethod
    def _spawn(cls, cmd, env, log_name):
        log = open(Path(cls.log_dir) / log_name, "wb")
        cls.log_handles.append(log)
        proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT), env=env, stdout=log, stderr=subprocess.STDOUT
        )
        cls.procs.append(proc)
        return proc

    @classmethod
    def _wait_http(cls, url, timeout=20):
        import urllib.request

        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                urllib.request.urlopen(url, timeout=2).read()
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(0.3)
        raise RuntimeError(f"管理面未就绪: {last_err}")

    @classmethod
    def _wait_tls(cls, timeout=20):
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                tls_handshake_fingerprint(cls.tls_port)
                return
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                time.sleep(0.3)
        raise RuntimeError(f"TLS 服务未就绪: {last_err}")

    @classmethod
    def tearDownClass(cls):
        for proc in cls.procs:
            proc.terminate()
        for proc in cls.procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for handle in cls.log_handles:
            handle.close()

    def _wait_handshake_fp(self, expected_fp: str, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        seen = ""
        while time.time() < deadline:
            try:
                seen = tls_handshake_fingerprint(self.tls_port)
                if seen == expected_fp:
                    return
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)
        self.fail(f"新握手未在 {timeout}s 内呈现期望指纹，最后见到: {seen}")

    def _new_cert(self, dns=("api.local",), days=365):
        cert_pem, key_pem, cert = generate_self_signed_cert(list(dns), days)
        return cert_pem, key_pem, fingerprint_sha256(cert)

    # ------------------------------------------------------------------ #

    def test_01_docs_and_bootstrap_fingerprint(self):
        # /docs Swagger UI 可访问
        status, body = http_get(self.mgmt_port, "/docs")
        self.assertEqual(status, 200)
        self.assertIn("swagger", body.lower())
        status, spec = http_get(self.mgmt_port, "/openapi.json")
        self.assertEqual(status, 200)
        self.assertIn("/certificates/rotate", spec["paths"])
        self.assertIn("/certificates/current", spec["paths"])

        status, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(status, 200)
        self.assertEqual(current["version"], 0)
        self.assertEqual(
            tls_handshake_fingerprint(self.tls_port),
            current["fingerprint_sha256"],
        )

    def test_02_successful_rotation_takes_effect_on_new_handshakes(self):
        _, before = http_get(self.mgmt_port, "/certificates/current")
        cert_pem, key_pem, new_fp = self._new_cert()

        status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["changed"])
        self.assertEqual(payload["current"]["version"], before["version"] + 1)
        self.assertEqual(payload["current"]["fingerprint_sha256"], new_fp)

        self._wait_handshake_fp(new_fp)
        status, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["fingerprint_sha256"], new_fp)

    def test_03_inflight_request_completes_on_old_cert(self):
        # 先确认当前基线
        _, current = http_get(self.mgmt_port, "/certificates/current")
        old_fp = current["fingerprint_sha256"]
        self._wait_handshake_fp(old_fp)

        # 在专用连接上发起 6 秒慢请求，连接保持打开
        import threading

        result = {}

        def runner():
            result["value"] = slow_request_on_dedicated_connection(self.tls_port, 6)

        t = threading.Thread(target=runner)
        t.start()
        time.sleep(1.0)  # 确保请求已在服务端处理中

        # 慢请求进行期间换证
        cert_pem, key_pem, new_fp = self._new_cert()
        status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
        self.assertEqual(status, 200, payload)

        # 新握手立即（轮询周期内）使用新证书
        self._wait_handshake_fp(new_fp, timeout=8)

        # 等待在途请求完成
        t.join(timeout=15)
        self.assertIn("value", result, "慢请求线程异常结束")
        peer_fp, status_code, response = result["value"]
        self.assertEqual(status_code, 200)
        self.assertIn(b'"status": "ok"', response)
        # 整条连接握手时拿到的是旧证书 → 在途请求未被换证打断
        self.assertEqual(peer_fp, old_fp)
        self.assertNotEqual(old_fp, new_fp)

    def test_04_interleaved_rotation_cas_conflict(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        base_version = current["version"]

        # A：基于现役版本，成功
        cert_a, key_a, fp_a = self._new_cert()
        status, payload = post_rotate(
            self.mgmt_port, cert_a, key_a, expected_version=base_version
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["current"]["version"], base_version + 1)
        self._wait_handshake_fp(fp_a)

        # B：较早发起（仍拿着 base_version），此时才到达 → 409，不能覆盖 A
        cert_b, key_b, fp_b = self._new_cert()
        status, payload = post_rotate(
            self.mgmt_port, cert_b, key_b, expected_version=base_version
        )
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["detail"]["current_version"], base_version + 1)

        # 现役仍是 A 的版本与指纹
        _, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["version"], base_version + 1)
        self.assertEqual(current["fingerprint_sha256"], fp_a)
        self.assertEqual(tls_handshake_fingerprint(self.tls_port), fp_a)

        # B 用最新 expected_version 重试则成功
        status, payload = post_rotate(
            self.mgmt_port, cert_b, key_b, expected_version=base_version + 1
        )
        self.assertEqual(status, 200, payload)
        self._wait_handshake_fp(fp_b)

    def test_05_validation_failures_keep_old_cert_serving(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        old_fp = current["fingerprint_sha256"]

        good_cert, _, _ = self._new_cert()
        _, wrong_key, _ = self._new_cert()
        bad_san_cert, bad_san_key, _ = self._new_cert(dns=("wrong.host",))
        expired_cert, expired_key, _ = self._new_cert(days=-5)

        cases = [
            (good_cert, wrong_key, "不匹配"),
            (bad_san_cert, bad_san_key, "SAN"),
            (expired_cert, expired_key, "有效期"),
        ]
        for cert_pem, key_pem, keyword in cases:
            status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
            self.assertEqual(status, 400, (keyword, payload))
            self.assertIn(keyword, payload["detail"])

        # 管理面与 TLS 都仍是旧版本
        _, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["fingerprint_sha256"], old_fp)
        self.assertEqual(tls_handshake_fingerprint(self.tls_port), old_fp)

        # 无临时残留；版本列表未增长
        leftovers = list(Path(self.data_dir).glob("versions/.tmp-*"))
        self.assertEqual(leftovers, [])
        status, listing = http_get(self.mgmt_port, "/certificates/versions")
        self.assertEqual(status, 200)
        self.assertEqual(listing["versions"][-1]["fingerprint_sha256"], old_fp)

        # 健康检查仍正常
        import ssl as _ssl
        import urllib.request

        ctx = _ssl._create_unverified_context()
        body = urllib.request.urlopen(
            f"https://127.0.0.1:{self.tls_port}/health", context=ctx, timeout=5
        ).read()
        self.assertIn(b"ok", body)

    def test_06_restart_uses_last_fully_saved_version(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        expected_fp = current["fingerprint_sha256"]
        expected_version = current["version"]

        # 找到 TLS 进程并重启
        tls_proc = self.procs[-1]
        tls_proc.terminate()
        tls_proc.wait(timeout=10)
        self.procs.pop()
        self.log_handles.pop().close()

        env = os.environ.copy()
        env["CERT_DATA_DIR"] = self.data_dir
        env["CERT_POLL_INTERVAL"] = "0.3"
        env["TLS_HOST"] = "127.0.0.1"
        env["TLS_PORT"] = str(self.tls_port)
        env["PYTHONPATH"] = os.pathsep.join(
            dict.fromkeys(
                [str(REPO_ROOT)]
                + [p for p in sys.path if p and Path(p).is_dir() and p != str(REPO_ROOT)]
            )
        )
        self._spawn([sys.executable, "-m", "app.tls_service"], env, "tls-restart.log")
        self._wait_tls(timeout=30)

        # 重启后直接呈现最后完整保存的版本
        self.assertEqual(tls_handshake_fingerprint(self.tls_port), expected_fp)
        _, current = http_get(self.mgmt_port, "/certificates/current")
        self.assertEqual(current["version"], expected_version)
        self.assertEqual(current["fingerprint_sha256"], expected_fp)

        # 磁盘上 current.json 与版本目录完整
        pointer = json.loads((Path(self.data_dir) / "current.json").read_text())
        self.assertEqual(pointer["version"], expected_version)
        base = Path(self.data_dir) / f"versions/v{expected_version}"
        for name in ("cert.pem", "key.pem", "meta.json"):
            self.assertTrue((base / name).is_file())

    # ------------------------------------------------------------------ #
    # 一次性 TLS 并发探测
    # ------------------------------------------------------------------ #

    def _start_probe(self, **payload):
        body = {
            "concurrency": 4,
            "total_requests": 8,
            "slow_seconds": 0.2,
            "timeout_seconds": 10.0,
        }
        body.update(payload)
        status, resp = http_post_json(self.mgmt_port, "/probes", body)
        self.assertEqual(status, 201, resp)
        return resp["probe_id"]

    def test_07_probe_success_grouped_by_actual_fingerprint(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        fp = current["fingerprint_sha256"]

        probe_id = self._start_probe(total_requests=8, concurrency=4, slow_seconds=0.1)
        report = wait_probe_done(self.mgmt_port, probe_id)

        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["counters"]["total"], 8)
        self.assertEqual(report["counters"]["success"], 8)
        self.assertEqual(report["counters"]["interrupted"], 0)
        # 全部样本归到当前现役证书这一组，没有 unknown
        known = [g for g in report["groups"] if not g["is_unknown"]]
        unknown = [g for g in report["groups"] if g["is_unknown"]]
        self.assertEqual(len(known), 1)
        self.assertEqual(unknown, [])
        self.assertEqual(known[0]["fingerprint"], fp)
        # 展示用证书元信息已附加，但归组只看样本指纹
        self.assertIsNotNone(known[0]["certificate"])
        self.assertEqual(known[0]["certificate"]["fingerprint_sha256"], fp)
        # 每条记录都是独立握手，耗时字段齐备
        self.assertEqual(len(report["records"]), 8)
        for rec in report["records"]:
            self.assertEqual(rec["fingerprint"], fp)
            self.assertEqual(rec["outcome"], "success")
            self.assertIsNotNone(rec["elapsed_ms"])

    def test_08_probe_interleaved_with_rotation_keeps_actual_groups(self):
        _, current = http_get(self.mgmt_port, "/certificates/current")
        old_fp = current["fingerprint_sha256"]
        cert_pem, key_pem, new_fp = self._new_cert()

        # 用 /slow 拉长探测窗口，确保探测进行中发生换证
        probe_id = self._start_probe(
            total_requests=12, concurrency=3, slow_seconds=1.2
        )
        # 等第一批样本完成（归属旧证书）
        self._wait_probe_completed_count(probe_id, minimum=3, timeout=15)

        # 探测期间换证
        status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
        self.assertEqual(status, 200, payload)
        self._wait_handshake_fp(new_fp, timeout=8)

        report = wait_probe_done(self.mgmt_port, probe_id, timeout=60)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["counters"]["success"], 12)

        fps = {g["fingerprint"] for g in report["groups"] if not g["is_unknown"]}
        # 换证发生在探测中途：两组指纹都应当出现，各自只归属实际握手所得
        self.assertIn(old_fp, fps)
        self.assertIn(new_fp, fps)
        total_grouped = sum(g["samples"] for g in report["groups"])
        self.assertEqual(total_grouped, 12)
        for rec in report["records"]:
            self.assertIn(rec["fingerprint"], (old_fp, new_fp))

        # 再次换证后查询旧报告：归组纹丝不动（不按查询时现役证书重算）
        cert2, key2, fp2 = self._new_cert()
        status, _ = post_rotate(self.mgmt_port, cert2, key2)
        self.assertEqual(status, 200)
        status, report_again = http_get(self.mgmt_port, f"/probes/{probe_id}")
        self.assertEqual(status, 200)
        fps2 = {g["fingerprint"] for g in report_again["groups"] if not g["is_unknown"]}
        self.assertEqual(fps2, fps)
        self.assertNotIn(fp2, fps2)

    def _wait_probe_completed_count(self, probe_id, minimum, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, report = http_get(self.mgmt_port, f"/probes/{probe_id}")
            if report["counters"].get("completed", 0) >= minimum:
                return report
            time.sleep(0.2)
        raise AssertionError("探测已完成样本数未达到预期")

    def test_09_probe_failures_go_to_unknown_and_rotation_not_blocked(self):
        body = {
            "concurrency": 3,
            "total_requests": 6,
            "slow_seconds": 0.0,
            "timeout_seconds": 3.0,
        }
        # 探测目标在进程启动时固定为 TLS 演示服务（127.0.0.1:tls_port）；
        # 杀掉 TLS 服务制造不可达，验证失败语义与“探测不阻住换证”。
        tls_proc = self.procs[-1]
        tls_proc.terminate()
        tls_proc.wait(timeout=10)
        self.procs.pop()
        self.log_handles.pop().close()
        try:
            # PROBE_TARGET_HOST/PORT 在进程启动时固定，这里端口仍是原 tls_port，
            # 服务已停 -> connect refused
            probe_id = self._start_probe(**body)
            report = wait_probe_done(self.mgmt_port, probe_id, timeout=40)
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["counters"]["success"], 0)
            self.assertEqual(
                report["counters"]["request_failed"]
                + report["counters"]["timeout"]
                + report["counters"]["handshake_failed"],
                6,
            )
            self.assertEqual(len(report["groups"]), 1)
            self.assertTrue(report["groups"][0]["is_unknown"])
            for rec in report["records"]:
                self.assertIsNone(rec["fingerprint"])
                self.assertNotEqual(rec["outcome"], "success")

            # 探测不能阻住换证：TLS 离线期间管理面换证照常成功
            cert_pem, key_pem, new_fp = self._new_cert()
            status, payload = post_rotate(self.mgmt_port, cert_pem, key_pem)
            self.assertEqual(status, 200, payload)
            self.assertEqual(payload["current"]["fingerprint_sha256"], new_fp)
        finally:
            # 恢复 TLS 服务供后续测试使用
            env = os.environ.copy()
            env["CERT_DATA_DIR"] = self.data_dir
            env["CERT_POLL_INTERVAL"] = "0.3"
            env["TLS_HOST"] = "127.0.0.1"
            env["TLS_PORT"] = str(self.tls_port)
            env["PYTHONPATH"] = os.pathsep.join(
                dict.fromkeys(
                    [str(REPO_ROOT)]
                    + [p for p in sys.path if p and Path(p).is_dir() and p != str(REPO_ROOT)]
                )
            )
            self._spawn([sys.executable, "-m", "app.tls_service"], env, "tls-restore.log")
            self._wait_tls(timeout=30)

    def test_10_single_running_probe_and_param_validation(self):
        # 第一轮探测占住运行槽
        probe_id = self._start_probe(
            total_requests=10, concurrency=2, slow_seconds=1.0
        )
        try:
            status, resp = http_post_json(
                self.mgmt_port,
                "/probes",
                {"concurrency": 1, "total_requests": 2, "slow_seconds": 0.0},
            )
            self.assertEqual(status, 409, resp)
            self.assertEqual(resp["detail"]["active_probe_id"], probe_id)
        finally:
            wait_probe_done(self.mgmt_port, probe_id)

        # 越界参数被 Pydantic 拒绝（422）
        for bad in (
            {"concurrency": 0},
            {"concurrency": 1000},
            {"total_requests": 0},
            {"total_requests": 10000},
            {"slow_seconds": 999},
            {"timeout_seconds": 0.0},
        ):
            status, resp = http_post_json(self.mgmt_port, "/probes", bad)
            self.assertEqual(status, 422, (bad, resp))

        # 上一轮结束后可以再开
        new_id = self._start_probe(total_requests=2, slow_seconds=0.0)
        report = wait_probe_done(self.mgmt_port, new_id)
        self.assertEqual(report["status"], "completed")

        # 列表与 latest 端点
        status, listing = http_get(self.mgmt_port, "/probes")
        self.assertEqual(status, 200)
        self.assertIsNone(listing["active_probe_id"])
        self.assertGreaterEqual(listing["count"], 2)
        status, latest = http_get(self.mgmt_port, "/probes/latest")
        self.assertEqual(status, 200)
        self.assertEqual(latest["probe_id"], listing["runs"][0]["probe_id"])
        # 不存在的轮次 404
        status, _ = http_get(self.mgmt_port, "/probes/probe-does-not-exist")
        self.assertEqual(status, 404)

    def test_11_killed_mgmt_process_completed_samples_survive_inflight_marked_interrupted(self):
        # 启动一个独立的管理面实例（独立端口，共享同一数据卷）
        extra_port = free_port()
        env = os.environ.copy()
        env["CERT_DATA_DIR"] = self.data_dir
        env["CERT_POLL_INTERVAL"] = "0.3"
        env["PROBE_TARGET_HOST"] = "127.0.0.1"
        env["PROBE_TARGET_PORT"] = str(self.tls_port)
        env["PROBE_TARGET_HOSTNAME"] = "api.local"
        env["PYTHONPATH"] = os.pathsep.join(
            dict.fromkeys(
                [str(REPO_ROOT)]
                + [p for p in sys.path if p and Path(p).is_dir() and p != str(REPO_ROOT)]
            )
        )
        proc = self._spawn(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(extra_port)],
            env,
            "mgmt-extra.log",
        )
        self._wait_http(f"http://127.0.0.1:{extra_port}/health", timeout=30)
        try:
            # 发起一轮足够长的探测后 SIGKILL，模拟进程中断
            body = {
                "concurrency": 4,
                "total_requests": 40,
                "slow_seconds": 0.5,
                "timeout_seconds": 10.0,
            }
            status, resp = http_post_json(extra_port, "/probes", body)
            self.assertEqual(status, 201, resp)
            probe_id = resp["probe_id"]

            # 等到至少有样本落盘
            deadline = time.time() + 15
            done = 0
            while time.time() < deadline:
                _, report = http_get(extra_port, f"/probes/{probe_id}")
                done = report["counters"].get("completed", 0)
                if done >= 2:
                    break
                time.sleep(0.2)
            self.assertGreaterEqual(done, 2)

            proc.kill()  # 硬杀，没有优雅停机机会
            proc.wait(timeout=10)
            self.procs.remove(proc)
            self.log_handles.pop().close()

            # 持久化文件已在共享卷上：直接核对 records.jsonl
            run_dir = Path(self.data_dir) / "probes" / probe_id
            records = [
                json.loads(line)
                for line in (run_dir / "records.jsonl").read_text().splitlines()
                if line.strip()
            ]
            self.assertGreaterEqual(len(records), 2)
            for rec in records:
                self.assertEqual(rec["outcome"], "success")

            # 通过原管理面查询同一轮：启动恢复把它标记为 interrupted，
            # 已完成样本保留，缺失序号合成 interrupted
            status, recovered = http_get(self.mgmt_port, f"/probes/{probe_id}")
            self.assertEqual(status, 200)
            self.assertEqual(recovered["status"], "interrupted")
            self.assertTrue(recovered["recovered_at_startup"])
            self.assertEqual(recovered["counters"]["completed"], len(records))
            self.assertEqual(
                recovered["counters"]["interrupted"],
                40 - len(records),
            )
            # 中断样本没有指纹，且绝无一个被算作成功
            interrupted_recs = [
                r for r in recovered["records"] if r["outcome"] == "interrupted"
            ]
            self.assertEqual(len(interrupted_recs), 40 - len(records))
            self.assertTrue(all(r["fingerprint"] is None for r in interrupted_recs))
            self.assertEqual(
                recovered["counters"]["success"] + recovered["counters"]["interrupted"],
                40,
            )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    def test_12_docs_and_openapi_include_probe_endpoints(self):
        status, spec = http_get(self.mgmt_port, "/openapi.json")
        self.assertEqual(status, 200)
        for path in ("/probes", "/probes/latest", "/probes/{probe_id}"):
            self.assertIn(path, spec["paths"])
        status, body = http_get(self.mgmt_port, "/docs")
        self.assertEqual(status, 200)
        self.assertIn("swagger", body.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
