"""ProbeManager / 探测持久化单元测试。

覆盖：
  P-1  配置硬上限与 Pydantic 之外的 ProbeConfig 校验路径
  P-2  成功探测：全部样本成功、按指纹归组、unknown 不出现
  P-3  目标不可达：连接失败计入有结果的失败组（unknown），不是成功
  P-4  同一时刻只允许一轮探测（ProbeBusyError -> 409 语义）
  P-5  总连接数/并发数上限
  P-6  中断恢复：records 已落盘样本保留，缺失序号合成 interrupted
  P-7  换证交错：归组只认样本握手时实际指纹，cert_index 变化不重算
  P-8  半行 JSONL 损坏行被跳过，该序号按中断处理
  P-9  优雅 shutdown：未完成轮次标记 interrupted
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_deps = Path("/tmp/pydeps")
if _deps.is_dir():
    sys.path.insert(0, str(_deps))

from app.cert_store import (  # noqa: E402
    CertificateStore,
    generate_self_signed_cert,
)
from app.probe import (  # noqa: E402
    MAX_CONCURRENCY,
    MAX_TOTAL_CONNECTIONS,
    OUTCOME_HANDSHAKE_FAILED,
    OUTCOME_INTERRUPTED,
    OUTCOME_REQUEST_FAILED,
    OUTCOME_SUCCESS,
    OUTCOME_TIMEOUT,
    ProbeBusyError,
    ProbeConfig,
    ProbeManager,
    ProbeStore,
    build_report,
    compute_counters,
    run_single_sample,
    synthesize_interrupted,
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TLSDemoServer:
    """测试用最小 TLS 服务，支持运行中热切换证书（模拟 tls_service）。"""

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    def __init__(self, cert_pem: bytes, key_pem: bytes):
        self.tmp = tempfile.mkdtemp()
        self.cert_path = Path(self.tmp) / "cert.pem"
        self.key_path = Path(self.tmp) / "key.pem"
        self.cert_path.write_bytes(cert_pem)
        self.key_path.write_bytes(key_pem)
        self.port = free_port()
        self._ctx_lock = threading.Lock()
        self._ctx = self._make_ctx()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), self._Handler)
        self.httpd.daemon_threads = True

        original_get_request = self.httpd.get_request

        def get_request():
            sock, addr = original_get_request()
            with self._ctx_lock:
                ctx = self._ctx
            return ctx.wrap_socket(sock, server_side=True), addr

        self.httpd.get_request = get_request
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def _make_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
        return ctx

    def rotate(self, cert_pem: bytes, key_pem: bytes) -> None:
        self.cert_path.write_bytes(cert_pem)
        self.key_path.write_bytes(key_pem)
        with self._ctx_lock:
            self._ctx = self._make_ctx()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def make_manager() -> tuple[ProbeManager, CertificateStore, str]:
    data_dir = tempfile.mkdtemp(prefix="probe-unit-")
    store = CertificateStore(data_dir)
    store.bootstrap()
    manager = ProbeManager(store)
    return manager, store, data_dir


def wait_status(manager: ProbeManager, probe_id: str, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        report = manager.get_report(probe_id)
        if report["status"] != "running":
            return report
        time.sleep(0.05)
    raise AssertionError(f"probe {probe_id} 未在 {timeout}s 内结束")


class SingleSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_pem, cls.key_pem, cls.cert = generate_self_signed_cert(["api.local"])
        cls.server = TLSDemoServer(cls.cert_pem, cls.key_pem)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_01_success_records_actual_fingerprint(self):
        from app.cert_store import fingerprint_sha256

        result = run_single_sample(
            "127.0.0.1", self.server.port, "api.local", 0.0, 5.0
        )
        self.assertEqual(result["outcome"], OUTCOME_SUCCESS, result)
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["fingerprint"], fingerprint_sha256(self.cert))
        self.assertGreaterEqual(result["elapsed_ms"], 0)

    def test_02_connection_refused_is_unknown_failure_not_success(self):
        dead_port = free_port()
        result = run_single_sample(
            "127.0.0.1", dead_port, "api.local", 0.0, 2.0
        )
        self.assertNotEqual(result["outcome"], OUTCOME_SUCCESS)
        self.assertIsNone(result["fingerprint"])
        self.assertIn("connect", result["phase"])

    def test_03_timeout_outcome(self):
        # 连一个“黑洞口”：保留 SYN 不响应的地址不好造，改用极短超时打
        # 不可路由地址；环境若直接拒连则退化为连接失败，二者都必须非成功
        result = run_single_sample(
            "10.255.255.1", free_port() + 1, "api.local", 0.0, 0.5
        )
        self.assertIn(
            result["outcome"], (OUTCOME_TIMEOUT, OUTCOME_REQUEST_FAILED)
        )
        self.assertIsNone(result["fingerprint"])

    def test_04_handshake_failure_on_plain_http_port(self):
        # 对明文 HTTP 端口发起 TLS 握手 -> SSLError，归握手失败
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            result = run_single_sample(
                "127.0.0.1", port, "api.local", 0.0, 3.0
            )
            self.assertEqual(result["outcome"], OUTCOME_HANDSHAKE_FAILED, result)
            self.assertIsNone(result["fingerprint"])
        finally:
            httpd.shutdown()
            httpd.server_close()


class ProbeManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_pem, cls.key_pem, cls.cert = generate_self_signed_cert(["api.local"])
        cls.server = TLSDemoServer(cls.cert_pem, cls.key_pem)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _config(self, **kw) -> ProbeConfig:
        defaults = dict(
            concurrency=4,
            total_requests=12,
            slow_seconds=0.0,
            timeout_seconds=5.0,
            target_host="127.0.0.1",
            target_port=self.server.port,
            server_hostname="api.local",
        )
        defaults.update(kw)
        return ProbeConfig(**defaults)

    def test_01_full_success_grouped_by_fingerprint(self):
        manager, _, _ = make_manager()
        probe_id = manager.start(self._config())
        report = wait_status(manager, probe_id)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["counters"]["success"], 12)
        self.assertEqual(report["counters"]["interrupted"], 0)
        # 全部样本同一指纹 -> 仅一个已知组，没有 unknown 组
        known = [g for g in report["groups"] if not g["is_unknown"]]
        unknown = [g for g in report["groups"] if g["is_unknown"]]
        self.assertEqual(len(known), 1)
        self.assertEqual(unknown, [])
        self.assertEqual(known[0]["samples"], 12)
        self.assertEqual(known[0]["outcomes"]["success"], 12)
        self.assertEqual(len(report["records"]), 12)

    def test_02_only_one_running_probe_allowed(self):
        manager, _, data_dir = make_manager()
        # 用不存在的目标制造长时间运行的轮次
        slow_cfg = self._config(total_requests=20, concurrency=2, target_port=free_port())
        probe_id = manager.start(slow_cfg)
        with self.assertRaises(ProbeBusyError):
            manager.start(self._config())
        report = wait_status(manager, probe_id, timeout=30)
        self.assertIn(report["status"], ("completed", "interrupted"))
        # 前一轮结束后可以再开
        new_id = manager.start(self._config(total_requests=2))
        report2 = wait_status(manager, new_id)
        self.assertEqual(report2["status"], "completed")

    def test_03_limits_constants_and_env_override(self):
        import importlib

        import app.probe as probe_mod

        self.assertLessEqual(probe_mod.MAX_TOTAL_CONNECTIONS, 200)
        self.assertLessEqual(probe_mod.MAX_CONCURRENCY, 32)
        # 环境变量只能收紧上限
        os.environ["PROBE_MAX_TOTAL"] = "5"
        os.environ["PROBE_MAX_CONCURRENCY"] = "2"
        try:
            importlib.reload(probe_mod)
            self.assertEqual(probe_mod.MAX_TOTAL_CONNECTIONS, 5)
            self.assertEqual(probe_mod.MAX_CONCURRENCY, 2)
        finally:
            del os.environ["PROBE_MAX_TOTAL"]
            del os.environ["PROBE_MAX_CONCURRENCY"]
            importlib.reload(probe_mod)
        self.assertEqual(probe_mod.MAX_TOTAL_CONNECTIONS, 200)
        self.assertEqual(probe_mod.MAX_CONCURRENCY, 32)

    def test_04_unreachable_target_all_samples_failure_in_unknown(self):
        manager, _, _ = make_manager()
        cfg = self._config(total_requests=6, concurrency=3, target_port=free_port())
        probe_id = manager.start(cfg)
        report = wait_status(manager, probe_id, timeout=30)
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

    def test_05_interrupted_recovery_marks_missing_seqs(self):
        manager, store, data_dir = make_manager()
        # 手工构造一轮 running 探测，只落盘 3 条记录，模拟进程被杀
        ps = ProbeStore(data_dir)
        probe_id = ps.new_probe_id()
        cfg = self._config(total_requests=10).to_dict()
        meta = {
            "probe_id": probe_id,
            "status": "running",
            "target": {"host": "127.0.0.1", "port": 1, "server_hostname": "api.local"},
            "config": cfg,
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": None,
            "counters": {},
        }
        ps.create_run(probe_id, meta)
        for seq in range(3):
            ps.append_record(
                probe_id,
                {
                    "seq": seq,
                    "outcome": OUTCOME_SUCCESS,
                    "phase": "request",
                    "fingerprint": "abc",
                    "http_status": 200,
                    "error": None,
                    "elapsed_ms": 1.0,
                    "started_at": "t",
                    "finished_at": "t",
                },
            )
        recovered = manager.startup_recover()
        self.assertIn(probe_id, recovered)
        report = manager.get_report(probe_id)
        self.assertEqual(report["status"], OUTCOME_INTERRUPTED)
        self.assertEqual(report["counters"]["success"], 3)
        self.assertEqual(report["counters"]["interrupted"], 7)
        self.assertTrue(report["recovered_at_startup"])
        # 中断样本绝不可能被记为成功
        self.assertEqual(
            [r for r in report["records"] if r["outcome"] == OUTCOME_INTERRUPTED].__len__(),
            7,
        )
        for rec in report["records"]:
            if rec["outcome"] == OUTCOME_INTERRUPTED:
                self.assertIsNone(rec["fingerprint"])

    def test_06_rotation_does_not_recompute_groups(self):
        from app.cert_store import fingerprint_sha256

        manager, store, _ = make_manager()
        cert2_pem, key2_pem, cert2 = generate_self_signed_cert(["api.local"])
        new_fp = fingerprint_sha256(cert2)
        # 先用当前证书跑一轮成功探测
        probe_id = manager.start(self._config(total_requests=4, concurrency=2))
        report = wait_status(manager, probe_id)
        old_fp = report["groups"][0]["fingerprint"]
        self.assertEqual(report["counters"]["success"], 4)
        self.assertNotEqual(old_fp, new_fp)

        # 模拟换证：TLS 服务切证书 + 管理面落新版本
        self.server.rotate(cert2_pem, key2_pem)
        store.rotate(cert2_pem, key2_pem)

        # 重新生成报告：旧样本仍归旧指纹组，certificate 信息按当前索引附加，
        # 但绝不重算归组
        report2 = manager.get_report(probe_id)
        fps = {g["fingerprint"] for g in report2["groups"]}
        self.assertEqual(fps, {old_fp})
        self.assertNotIn(new_fp, fps)

    def test_07_corrupt_jsonl_half_line_skipped_and_counted_interrupted(self):
        manager, _, data_dir = make_manager()
        ps = ProbeStore(data_dir)
        probe_id = ps.new_probe_id()
        cfg = self._config(total_requests=3).to_dict()
        meta = {
            "probe_id": probe_id,
            "status": "running",
            "target": {"host": "h", "port": 1, "server_hostname": "api.local"},
            "config": cfg,
            "started_at": "t",
            "finished_at": None,
            "counters": {},
        }
        ps.create_run(probe_id, meta)
        ps.append_record(
            probe_id,
            {"seq": 0, "outcome": OUTCOME_SUCCESS, "phase": "request",
             "fingerprint": "fp", "http_status": 200, "error": None,
             "elapsed_ms": 1.0, "started_at": "t", "finished_at": "t"},
        )
        # 追加半行损坏数据（模拟写入中途进程被杀）
        with open(ps.run_dir(probe_id) / "records.jsonl", "a") as fh:
            fh.write('{"seq": 1, "outcome": "succ')
        manager.startup_recover()
        report = manager.get_report(probe_id)
        self.assertEqual(report["counters"]["success"], 1)
        self.assertEqual(report["counters"]["interrupted"], 2)

    def test_08_graceful_shutdown_marks_probe_interrupted(self):
        manager, _, _ = make_manager()
        # 用钩子确定性地制造在途样本：前 2 个快速落盘，其余阻塞到停机事件
        gate = threading.Event()

        def hook(seq):
            if seq < 2:
                return {
                    "outcome": OUTCOME_SUCCESS, "phase": "request",
                    "fingerprint": "fp", "http_status": 200, "error": None,
                    "elapsed_ms": 1.0,
                }
            gate.wait(timeout=10)
            return {
                "outcome": OUTCOME_SUCCESS, "phase": "request",
                "fingerprint": "fp", "http_status": 200, "error": None,
                "elapsed_ms": 1.0,
            }

        cfg = self._config(total_requests=10, concurrency=4)
        probe_id = manager.start(cfg, sample_hook=hook)
        # 等至少 2 个样本落盘，确认“已完成样本仍可查”；其余 worker 已取走
        # 序号但阻塞在钩子中，属于在途任务
        deadline = time.time() + 5
        while time.time() < deadline:
            done = len(manager._probe_store.load_records(probe_id))
            if done >= 2:
                break
            time.sleep(0.05)
        done_before = len(manager._probe_store.load_records(probe_id))
        self.assertGreaterEqual(done_before, 2)
        # 短 join：在途样本仍阻塞在钩子中，shutdown 不等待它们，直接终结状态
        manager.shutdown(join_timeout=1.0)
        gate.set()
        report = manager.get_report(probe_id)
        self.assertEqual(report["status"], OUTCOME_INTERRUPTED)
        # 已完成样本数 + 中断数 == 总数；停机信号送达前完成的样本保留为
        # 成功（>= 停机前已落盘数），信号后在途的全部算中断，无一冒充成功
        c = report["counters"]
        self.assertEqual(c["completed"] + c["interrupted"], c["total"])
        self.assertGreaterEqual(c["success"], done_before)
        self.assertLess(c["success"], c["total"])
        self.assertEqual(c["interrupted"], c["total"] - c["completed"])
        self.assertIsNone(manager.active_id)

    def test_09_latest_and_listing(self):
        manager, _, _ = make_manager()
        self.assertRaises(Exception, manager.latest_report)
        id1 = manager.start(self._config(total_requests=2))
        wait_status(manager, id1)
        id2 = manager.start(self._config(total_requests=3))
        wait_status(manager, id2)
        self.assertEqual(manager.latest_report()["probe_id"], id2)
        runs = manager.list_runs()
        self.assertEqual([r["probe_id"] for r in runs], [id2, id1])


class ReportHelperTests(unittest.TestCase):
    def test_synthesize_and_counters(self):
        meta = {"config": {"total_requests": 5}}
        records = [
            {"seq": 0, "outcome": OUTCOME_SUCCESS},
            {"seq": 2, "outcome": OUTCOME_TIMEOUT},
        ]
        counters = compute_counters(meta, records)
        self.assertEqual(counters["success"], 1)
        self.assertEqual(counters["timeout"], 1)
        self.assertEqual(counters["interrupted"], 3)
        placeholders = synthesize_interrupted(meta, records)
        self.assertEqual([p["seq"] for p in placeholders], [1, 3, 4])
        self.assertTrue(all(p["outcome"] == OUTCOME_INTERRUPTED for p in placeholders))

    def test_report_unknown_group_sorted_last(self):
        meta = {
            "probe_id": "x",
            "status": "completed",
            "target": {},
            "config": {"total_requests": 3},
            "started_at": "t",
            "finished_at": "t",
        }
        records = [
            {"seq": 0, "outcome": OUTCOME_SUCCESS, "fingerprint": "fp-b",
             "elapsed_ms": 5.0, "http_status": 200, "phase": "request", "error": None},
            {"seq": 1, "outcome": OUTCOME_HANDSHAKE_FAILED, "fingerprint": None,
             "elapsed_ms": 1.0, "http_status": None, "phase": "handshake", "error": "e"},
            {"seq": 2, "outcome": OUTCOME_SUCCESS, "fingerprint": "fp-a",
             "elapsed_ms": 2.0, "http_status": 200, "phase": "request", "error": None},
        ]
        report = build_report(meta, records, {})
        self.assertTrue(report["groups"][-1]["is_unknown"])
        self.assertEqual([g["fingerprint"] for g in report["groups"]][:-1],
                         sorted(g["fingerprint"] for g in report["groups"][:-1]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
