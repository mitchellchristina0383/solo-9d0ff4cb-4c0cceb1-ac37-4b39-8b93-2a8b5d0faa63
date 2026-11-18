"""一次性 TLS 探测：并发建立新连接，按握手实际取得的证书指纹归组。

需求要点与实现对应：
* 每个样本都新建 TCP 连接并重新握手（``socket.create_connection`` +
  ``SSLContext.wrap_socket``），握手完成后立即抓取对端叶子证书的
  SHA256 指纹；样本自始至终只归属这枚“实际取得”的指纹，报告按指纹
  归组，换证发生在探测中途也不会按任务开始/查询时的现役证书重算。
* 取不到证书的失败（连接失败、握手失败、握手阶段超时等）指纹为 None，
  统一归入 unknown 组。
* 每个样本一条 JSONL 记录，落盘后 flush+fsync；进程被杀时已完成样本
  仍可从 records.jsonl 读出，缺失的序号在恢复/报告时合成为 interrupted，
  绝不当成成功。
* 同一进程只允许一轮探测在跑（ProbeManager 内锁 + active_id 判定），
  总连接数与并发数有硬上限；探测在后台线程运行，不持有换证锁，
  不阻塞 /certificates/rotate。

存储布局（DATA_DIR/probes/）::

    probes/<probe_id>/meta.json       轮次配置、状态、汇总计数（原子替换）
    probes/<probe_id>/records.jsonl   每样本一行，仅追加
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import queue
import secrets
import socket
import ssl
import threading
import time
from pathlib import Path

from .cert_store import CertificateStore

# --------------------------------------------------------------------------- #
# 硬上限（可由环境变量收紧，不能被请求体放大）
# --------------------------------------------------------------------------- #
MAX_TOTAL_CONNECTIONS = int(os.environ.get("PROBE_MAX_TOTAL", "200"))
MAX_CONCURRENCY = int(os.environ.get("PROBE_MAX_CONCURRENCY", "32"))
MAX_SLOW_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 60.0

# 探测目标默认指向本机/同 Compose 网络内的 TLS 演示服务
DEFAULT_TARGET_HOST = os.environ.get("PROBE_TARGET_HOST", "127.0.0.1")
DEFAULT_TARGET_PORT = int(os.environ.get("PROBE_TARGET_PORT", "8443"))
DEFAULT_SERVER_HOSTNAME = os.environ.get("PROBE_TARGET_HOSTNAME", "api.local")

# 结果状态取值
OUTCOME_SUCCESS = "success"
OUTCOME_HANDSHAKE_FAILED = "handshake_failed"
OUTCOME_REQUEST_FAILED = "request_failed"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_INTERRUPTED = "interrupted"
OUTCOME_ERROR = "error"

# 轮次状态取值
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_INTERRUPTED = "interrupted"

COUNTED_OUTCOMES = (
    OUTCOME_SUCCESS,
    OUTCOME_HANDSHAKE_FAILED,
    OUTCOME_REQUEST_FAILED,
    OUTCOME_TIMEOUT,
    OUTCOME_INTERRUPTED,
    OUTCOME_ERROR,
)


class ProbeBusyError(Exception):
    """已有一轮探测在运行，拒绝再开一轮。"""


class ProbeNotFoundError(Exception):
    """探测轮次不存在。"""


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# 单样本探测（纯函数式，便于单测）
# --------------------------------------------------------------------------- #

def run_single_sample(
    host: str,
    port: int,
    server_hostname: str,
    slow_seconds: float,
    timeout_seconds: float,
) -> dict:
    """建立一条全新 TLS 连接并完成一次 GET /slow，返回样本结果。

    返回字段：outcome / phase / fingerprint / http_status / error /
    elapsed_ms。每个样本都从新的裸 socket 开始，因此必然产生一次新握手；
    指纹在握手成功的第一时间抓取，之后不再改变。
    """
    started = time.monotonic()
    phase = "connect"
    fingerprint: str | None = None
    http_status: int | None = None
    error: str | None = None
    raw: socket.socket | None = None
    ssock: ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout_seconds)
        # 自签演示证书：不校验链，只看服务端实际给出的证书
        ctx = ssl._create_unverified_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        phase = "handshake"
        ssock = ctx.wrap_socket(raw, server_hostname=server_hostname)
        # 指纹取自本次握手实际收到的叶子证书，后续任何换证都与本样本无关
        der = ssock.getpeercert(binary_form=True)
        if der:
            fingerprint = hashlib.sha256(der).hexdigest()
        phase = "request"
        request = (
            f"GET /slow?seconds={slow_seconds} HTTP/1.1\r\n"
            f"Host: {server_hostname}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        ssock.settimeout(timeout_seconds)
        ssock.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks)
        status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = status_line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            outcome = OUTCOME_REQUEST_FAILED
            error = f"无法解析响应状态行: {status_line!r}"
        else:
            http_status = int(parts[1])
            if 200 <= http_status < 300:
                outcome = OUTCOME_SUCCESS
            else:
                outcome = OUTCOME_REQUEST_FAILED
                error = f"HTTP {http_status}"
    except (socket.timeout, TimeoutError) as exc:
        outcome = OUTCOME_TIMEOUT
        error = f"{phase} 阶段超时: {exc!r}"
    except ssl.SSLError as exc:
        # 握手阶段的 SSL 错误归握手失败；请求阶段的 SSL 错误归请求失败
        if phase == "handshake":
            outcome = OUTCOME_HANDSHAKE_FAILED
        else:
            outcome = OUTCOME_REQUEST_FAILED
        error = f"{phase} 阶段 SSL 失败: {exc!r}"
    except OSError as exc:
        # connect/request 阶段的连接类问题（含 ConnectionRefusedError）
        outcome = OUTCOME_REQUEST_FAILED
        error = f"{phase} 阶段连接失败: {exc!r}"
    except Exception as exc:  # noqa: BLE001 - 任何意外都要留下结果而不是丢样本
        outcome = OUTCOME_ERROR
        error = f"{phase} 阶段未预期异常: {exc!r}"
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except OSError:
                pass
        elif raw is not None:
            try:
                raw.close()
            except OSError:
                pass
    return {
        "outcome": outcome,
        "phase": phase,
        "fingerprint": fingerprint,
        "http_status": http_status,
        "error": error,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }


# --------------------------------------------------------------------------- #
# 持久化
# --------------------------------------------------------------------------- #

class ProbeStore:
    """探测轮次的本地持久化，所有写入均在 DATA_DIR/probes 下。"""

    def __init__(self, data_dir: str | os.PathLike):
        self.probes_dir = Path(data_dir) / "probes"
        self.probes_dir.mkdir(parents=True, exist_ok=True)
        self._file_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        # 进程内单调序号，嵌入 probe_id 保证词序即创建顺序（同秒也可排序）
        self._seq_counter = 0
        self._seq_lock = threading.Lock()

    def _lock_for(self, path: Path) -> threading.Lock:
        key = str(path)
        with self._locks_guard:
            lock = self._file_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._file_locks[key] = lock
            return lock

    def new_probe_id(self) -> str:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d%H%M%S")
        with self._seq_lock:
            self._seq_counter += 1
            seq = self._seq_counter
        return f"probe-{ts}-{seq:06d}-{secrets.token_hex(3)}"

    def run_dir(self, probe_id: str) -> Path:
        return self.probes_dir / probe_id

    def create_run(self, probe_id: str, meta: dict) -> None:
        run_dir = self.run_dir(probe_id)
        run_dir.mkdir(parents=True, exist_ok=False)
        self.write_meta(run_dir, meta)
        # 预创建 records.jsonl，保证轮次目录结构完整
        (run_dir / "records.jsonl").touch()

    @staticmethod
    def write_meta(run_dir: Path, meta: dict) -> None:
        tmp = run_dir / "meta.json.new"
        tmp.write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        os.replace(tmp, run_dir / "meta.json")

    def append_record(self, probe_id: str, record: dict) -> None:
        path = self.run_dir(probe_id) / "records.jsonl"
        line = json.dumps(record, ensure_ascii=False) + "\n"
        lock = self._lock_for(path)
        with lock:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())

    def load_meta(self, probe_id: str) -> dict:
        path = self.run_dir(probe_id) / "meta.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ProbeNotFoundError(probe_id) from exc

    def load_records(self, probe_id: str) -> list[dict]:
        path = self.run_dir(probe_id) / "records.jsonl"
        records: list[dict] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        # 半行写入（进程在 write 中途被杀）：跳过最后坏行，
                        # 该序号会按中断处理而不是被当成成功
                        continue
        except FileNotFoundError as exc:
            raise ProbeNotFoundError(probe_id) from exc
        records.sort(key=lambda r: r.get("seq", 0))
        return records

    def list_run_ids(self) -> list[str]:
        ids = [p.name for p in self.probes_dir.iterdir() if p.is_dir()]
        return sorted(ids, reverse=True)

    def recover_interrupted(self) -> list[str]:
        """启动恢复：status 仍为 running 的轮次按实际落盘样本重新定性。

        已完成样本保留在 records.jsonl 中。若全部序号都有记录则说明工作
        实际已完成（只是终结状态没来得及写），如实标 completed；否则未完成
        序号由报告逻辑合成为 interrupted。返回被恢复的轮次 id。
        """
        recovered: list[str] = []
        for probe_id in self.list_run_ids():
            run_dir = self.run_dir(probe_id)
            meta_path = run_dir / "meta.json"
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if meta.get("status") != STATUS_RUNNING:
                continue
            records = self.load_records(probe_id)
            total = int(meta["config"]["total_requests"])
            done_seqs = {r.get("seq") for r in records}
            all_done = len(done_seqs) == total and all(
                isinstance(s, int) and 0 <= s < total for s in done_seqs
            )
            meta["status"] = STATUS_COMPLETED if all_done else STATUS_INTERRUPTED
            meta["finished_at"] = _utcnow_iso()
            meta["recovered_at_startup"] = True
            meta["counters"] = compute_counters(meta, records)
            self.write_meta(run_dir, meta)
            recovered.append(probe_id)
        return recovered


# --------------------------------------------------------------------------- #
# 汇总与归组
# --------------------------------------------------------------------------- #

def _empty_outcome_counts() -> dict:
    return {name: 0 for name in COUNTED_OUTCOMES}


def compute_counters(meta: dict, records: list[dict]) -> dict:
    """按实际记录统计；缺失序号计为 interrupted，不计成功。"""
    counters = _empty_outcome_counts()
    total = int(meta["config"]["total_requests"])
    done_seqs = set()
    for rec in records:
        outcome = rec.get("outcome")
        if outcome in counters:
            counters[outcome] += 1
        done_seqs.add(rec.get("seq"))
    missing = total - len(done_seqs)
    if missing > 0:
        counters[OUTCOME_INTERRUPTED] += missing
    counters["total"] = total
    counters["completed"] = len(done_seqs)
    return counters


def synthesize_interrupted(meta: dict, records: list[dict]) -> list[dict]:
    """为没有落盘记录的序号生成 interrupted 占位样本（仅用于展示）。"""
    total = int(meta["config"]["total_requests"])
    done_seqs = {rec.get("seq") for rec in records}
    placeholders = []
    for seq in range(total):
        if seq not in done_seqs:
            placeholders.append(
                {
                    "seq": seq,
                    "outcome": OUTCOME_INTERRUPTED,
                    "phase": None,
                    "fingerprint": None,
                    "http_status": None,
                    "error": "进程中断，任务未完成",
                    "elapsed_ms": None,
                    "started_at": None,
                    "finished_at": None,
                }
            )
    return placeholders


def build_cert_index(store: CertificateStore) -> dict[str, dict]:
    """指纹 -> 版本元信息，仅用于报告展示，不参与归组判定。"""
    index: dict[str, dict] = {}
    versions_dir = store.versions_dir
    if not versions_dir.exists():
        return index
    for meta_path in versions_dir.glob("v*/meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        fp = meta.get("fingerprint_sha256")
        if fp:
            index[fp] = meta
    return index


def build_report(meta: dict, records: list[dict], cert_index: dict[str, dict]) -> dict:
    """按握手实际指纹归组生成报告；无指纹样本进 unknown 组。"""
    counters = compute_counters(meta, records)
    all_records = records + synthesize_interrupted(meta, records)
    all_records.sort(key=lambda r: r["seq"])

    grouped: dict[str | None, list[dict]] = {}
    for rec in all_records:
        grouped.setdefault(rec.get("fingerprint"), []).append(rec)

    groups = []
    for fingerprint, items in grouped.items():
        counts = _empty_outcome_counts()
        elapsed = [
            r["elapsed_ms"]
            for r in items
            if isinstance(r.get("elapsed_ms"), (int, float))
        ]
        for r in items:
            outcome = r.get("outcome")
            if outcome in counts:
                counts[outcome] += 1
        groups.append(
            {
                "fingerprint": fingerprint,
                "is_unknown": fingerprint is None,
                "certificate": cert_index.get(fingerprint) if fingerprint else None,
                "samples": len(items),
                "outcomes": counts,
                "elapsed_ms": {
                    "min": min(elapsed) if elapsed else None,
                    "max": max(elapsed) if elapsed else None,
                    "avg": round(sum(elapsed) / len(elapsed), 3) if elapsed else None,
                },
            }
        )
    # 已知指纹组按指纹排序，unknown 固定放最后
    groups.sort(key=lambda g: (g["fingerprint"] is None, g["fingerprint"] or ""))

    return {
        "probe_id": meta["probe_id"],
        "status": meta["status"],
        "target": meta["target"],
        "config": meta["config"],
        "started_at": meta.get("started_at"),
        "finished_at": meta.get("finished_at"),
        "recovered_at_startup": meta.get("recovered_at_startup", False),
        "counters": counters,
        # 归组只依据各样本握手时实际取得的指纹；certificate 信息是查询时
        # 附加的展示数据，换证不会导致样本被重新归组
        "groups": groups,
        "records": all_records,
    }


# --------------------------------------------------------------------------- #
# 调度管理
# --------------------------------------------------------------------------- #

@dataclasses.dataclass(frozen=True)
class ProbeConfig:
    concurrency: int
    total_requests: int
    slow_seconds: float
    timeout_seconds: float
    target_host: str = DEFAULT_TARGET_HOST
    target_port: int = DEFAULT_TARGET_PORT
    server_hostname: str = DEFAULT_SERVER_HOSTNAME

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class ProbeManager:
    """进程内单轮探测调度器：后台线程池执行，持久化由 ProbeStore 负责。"""

    HEARTBEAT_INTERVAL = 0.5

    def __init__(self, store: CertificateStore):
        self._cert_store = store
        self._probe_store = ProbeStore(store.data_dir)
        self._guard = threading.Lock()
        self._active_id: str | None = None
        self._stop = threading.Event()
        self._runner: threading.Thread | None = None

    @property
    def active_id(self) -> str | None:
        with self._guard:
            return self._active_id

    # ---------------- 生命周期 ---------------- #

    def startup_recover(self) -> list[str]:
        return self._probe_store.recover_interrupted()

    def shutdown(self, join_timeout: float = 5.0) -> None:
        """优雅停机：通知 worker 停止，未完成轮次按实际样本数定性。"""
        with self._guard:
            active_id = self._active_id
            runner = self._runner
        if active_id is None or runner is None:
            return
        self._stop.set()
        runner.join(timeout=join_timeout)
        # 线程未在超时内退出也直接终结：以实际落盘样本数定性，
        # daemon 线程不会阻止进程退出，缺失序号按 interrupted 合成
        self._finalize(active_id)

    def start(
        self,
        config: ProbeConfig,
        sample_hook: "callable | None" = None,
    ) -> str:
        """启动一轮探测。sample_hook 仅供测试注入样本执行函数，生产路径恒为 None。"""
        probe_id = self._probe_store.new_probe_id()
        with self._guard:
            if self._active_id is not None:
                raise ProbeBusyError(f"探测 {self._active_id} 仍在运行")
            meta = {
                "probe_id": probe_id,
                "status": STATUS_RUNNING,
                "target": {
                    "host": config.target_host,
                    "port": config.target_port,
                    "server_hostname": config.server_hostname,
                },
                "config": config.to_dict(),
                "started_at": _utcnow_iso(),
                "finished_at": None,
                "counters": _empty_outcome_counts() | {"total": config.total_requests, "completed": 0},
            }
            self._probe_store.create_run(probe_id, meta)
            self._stop.clear()
            runner = threading.Thread(
                target=self._run,
                args=(probe_id, config, sample_hook),
                name=f"probe-{probe_id}",
                daemon=True,
            )
            self._active_id = probe_id
            self._runner = runner
            runner.start()
        return probe_id

    # ---------------- 执行 ---------------- #

    def _run(
        self,
        probe_id: str,
        config: ProbeConfig,
        sample_hook: "callable | None" = None,
    ) -> None:
        seqs: queue.Queue[int] = queue.Queue()
        for seq in range(config.total_requests):
            seqs.put(seq)

        def worker() -> None:
            while not self._stop.is_set():
                try:
                    seq = seqs.get_nowait()
                except queue.Empty:
                    return
                started_iso = _utcnow_iso()
                if sample_hook is not None:
                    # 测试钩子：可阻塞/抛错，用于确定性模拟在途与异常
                    result = sample_hook(seq)
                else:
                    result = run_single_sample(
                        config.target_host,
                        config.target_port,
                        config.server_hostname,
                        config.slow_seconds,
                        config.timeout_seconds,
                    )
                record = {
                    "seq": seq,
                    "started_at": started_iso,
                    "finished_at": _utcnow_iso(),
                    **result,
                }
                try:
                    self._probe_store.append_record(probe_id, record)
                except OSError as exc:
                    # 落盘失败不能让 worker 静默消失：重试一次，仍失败则放弃该样本，
                    # 它会在最终汇总时按 interrupted 处理
                    print(f"[probe] 样本 {seq} 落盘失败，将重试: {exc!r}", flush=True)
                    try:
                        self._probe_store.append_record(probe_id, record)
                    except OSError as exc2:
                        print(f"[probe] 样本 {seq} 重试落盘仍失败: {exc2!r}", flush=True)
                seqs.task_done()

        threads = [
            threading.Thread(target=worker, name=f"probe-{probe_id}-w{i}", daemon=True)
            for i in range(config.concurrency)
        ]
        for t in threads:
            t.start()

        # 心跳：周期性刷新 meta 计数，查询接口可看到进度
        last_beat = 0.0
        while any(t.is_alive() for t in threads):
            if time.monotonic() - last_beat >= self.HEARTBEAT_INTERVAL:
                self._heartbeat(probe_id)
                last_beat = time.monotonic()
            time.sleep(0.1)
        for t in threads:
            t.join()

        # 以实际落盘样本定性：全部序号齐全即 completed，有缺失才 interrupted
        self._finalize(probe_id)

    def _heartbeat(self, probe_id: str) -> None:
        try:
            meta = self._probe_store.load_meta(probe_id)
            if meta.get("status") != STATUS_RUNNING:
                return
            records = self._probe_store.load_records(probe_id)
            meta["counters"] = compute_counters(meta, records)
            self._probe_store.write_meta(self._probe_store.run_dir(probe_id), meta)
        except (OSError, ProbeNotFoundError, json.JSONDecodeError, KeyError) as exc:
            print(f"[probe] 心跳刷新失败（已忽略）: {exc!r}", flush=True)

    def _finalize(self, probe_id: str) -> None:
        with self._guard:
            if self._active_id == probe_id:
                self._active_id = None
        try:
            meta = self._probe_store.load_meta(probe_id)
            if meta.get("status") != STATUS_RUNNING:
                return
            records = self._probe_store.load_records(probe_id)
            done = len(records)
            total = int(meta["config"]["total_requests"])
            # 以实际落盘样本定性：序号齐全即完成，有缺失才中断；
            # 缺失序号在 compute_counters 中计为 interrupted
            meta["status"] = STATUS_COMPLETED if done >= total else STATUS_INTERRUPTED
            meta["finished_at"] = _utcnow_iso()
            meta["counters"] = compute_counters(meta, records)
            self._probe_store.write_meta(self._probe_store.run_dir(probe_id), meta)
        except (OSError, ProbeNotFoundError, json.JSONDecodeError, KeyError) as exc:
            # 最坏情况：进程重启后 startup_recover 仍能兜底标记
            print(f"[probe] 轮次 {probe_id} 终结写盘失败: {exc!r}", flush=True)

    # ---------------- 查询 ---------------- #

    def list_runs(self) -> list[dict]:
        # 查询路径同样兜底恢复：即便启动恢复未跑（如轮次目录后出现），
        # 残留 running 状态也会在此被纠正为 interrupted
        self.startup_recover()
        summary = []
        for probe_id in self._probe_store.list_run_ids():
            try:
                meta = self._probe_store.load_meta(probe_id)
            except (ProbeNotFoundError, json.JSONDecodeError):
                continue
            summary.append(
                {
                    "probe_id": meta["probe_id"],
                    "status": meta["status"],
                    "started_at": meta.get("started_at"),
                    "finished_at": meta.get("finished_at"),
                    "config": meta["config"],
                    "counters": meta.get("counters", {}),
                }
            )
        return summary

    def get_report(self, probe_id: str) -> dict:
        meta = self._probe_store.load_meta(probe_id)
        # 进程外残留的 running 轮次：查询时按中断恢复，缺失序号合成 interrupted
        if meta.get("status") == STATUS_RUNNING and self._active_id != probe_id:
            self._probe_store.recover_interrupted()
            meta = self._probe_store.load_meta(probe_id)
        records = self._probe_store.load_records(probe_id)
        cert_index = build_cert_index(self._cert_store)
        return build_report(meta, records, cert_index)

    def latest_report(self) -> dict:
        ids = self._probe_store.list_run_ids()
        if not ids:
            raise ProbeNotFoundError("尚无探测轮次")
        return self.get_report(ids[0])
