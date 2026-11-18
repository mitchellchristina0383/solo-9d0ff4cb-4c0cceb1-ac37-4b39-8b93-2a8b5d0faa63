# api.local 证书热轮换演示（FastAPI + Python ssl）

值班场景：给 `api.local` 的 HTTPS 入口换证，不中断正在处理的请求。

## 组成

| 组件 | 技术 | 端口 | 职责 |
| --- | --- | --- | --- |
| `mgmt` | FastAPI + uvicorn | 8000 | 管理接口，`/docs` 上传 PEM 证书/私钥、查看现役指纹、发起 TLS 探测 |
| `tls` | Python 标准库 `ssl` + `http.server` | 8443 | `api.local` HTTPS 演示服务，轮询热加载证书 |
| 共享卷 `cert-data` | Docker volume | — | 原子化的证书版本存储 `/data/certs`（探测记录在 `probes/` 子目录） |

## 快速开始

```bash
docker compose up --build
# 管理接口（Swagger UI，可直接上传文件）：
#   http://localhost:8000/docs
# HTTPS 演示服务（自签证书）：
curl -k https://localhost:8443/health
curl -k https://localhost:8443/slow?seconds=5
```

首次启动自动生成覆盖 `api.local` 的自签演示证书 `v0`。

## 换证规则（不满足任意一条即 400，旧证书继续服务）

1. PEM 可解析，私钥为无加密 PEM；
2. 私钥与叶子证书公钥匹配；
3. 叶子证书 SAN 覆盖 `api.local`（支持 `*.local` 通配）；
4. 证书当前处于有效期内；
5. 落盘前再用 `ssl.SSLContext.load_cert_chain` 试加载，OpenSSL 不接受即拒绝。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/certificates/current` | 现役版本号、SHA256 指纹、有效期、SAN |
| GET | `/certificates/versions` | 所有已完整保存的版本 |
| POST | `/certificates/rotate` | multipart 上传 `cert`（PEM 链）、`key`（PEM 私钥）、可选 `expected_version` |
| POST | `/probes` | 发起一次性 TLS 并发探测（JSON：`concurrency`/`total_requests`/`slow_seconds`/`timeout_seconds`） |
| GET | `/probes` | 探测轮次列表与当前在跑轮次 |
| GET | `/probes/latest` | 最新一轮探测报告 |
| GET | `/probes/{probe_id}` | 指定轮次报告（按握手实际指纹归组） |

```bash
curl -k -X POST http://localhost:8000/certificates/rotate \
  -F cert=@new.pem -F key=@new.key
# 乐观锁/CAS：发起时看到的版本号，过期则 409
curl -k -X POST http://localhost:8000/certificates/rotate \
  -F cert=@new.pem -F key=@new.key -F expected_version=2

# 一次性探测：8 条全新 TLS 连接、4 并发，每条请求 /slow?seconds=1
curl -X POST http://localhost:8000/probes \
  -H 'Content-Type: application/json' \
  -d '{"concurrency":4,"total_requests":8,"slow_seconds":1,"timeout_seconds":15}'
curl http://localhost:8000/probes/latest
```

## 一次性 TLS 探测（换证后核对实际生效证书）

`POST /probes` 在后台发起一轮探测，每个样本都**新建 TCP 连接并重新握手**，
按握手完成那一刻实际取得的服务端叶子证书 SHA256 指纹归组：

- **归组不可重算**：指纹在握手成功后立即抓取并随样本落盘，探测中途换证、
  查询时再次换证都不会改变样本归属；报告里的 `certificate` 版本信息只是
  查询时附加的展示数据。
- **结果分类**：`success`（2xx）、`handshake_failed`（握手阶段 SSL 失败）、
  `request_failed`（连接/请求阶段失败或非 2xx）、`timeout`（各阶段超时）；
  取不到证书的失败指纹为 `null`，统一进 `is_unknown=true` 的 unknown 组。
- **单轮与上限**：同一时刻只允许一轮探测，重复发起返回 409；
  单轮连接总数上限 200、并发上限 32（可用 `PROBE_MAX_TOTAL` /
  `PROBE_MAX_CONCURRENCY` 环境变量收紧），`slow_seconds` 上限 30s、
  `timeout_seconds` 上限 60s，越界请求 422。
- **不阻住换证**：探测跑在后台线程，不持有换证锁，`/certificates/rotate`
  随时可用。
- **中断语义**：每条样本以 JSONL 追加写入并 fsync。进程被杀死后，已完成
  样本仍可从 `probes/<id>/records.jsonl` 查询；缺失序号在启动恢复
  （或下次查询）时合成为 `interrupted`，绝不会被计为成功。优雅停机时
  在途轮次同样落盘为 `interrupted`。
- 报告含每轮汇总计数、按指纹分组的样本数/各类失败数/耗时（min/max/avg）、
  以及全量样本明细。探测目标由 `PROBE_TARGET_HOST` / `PROBE_TARGET_PORT` /
  `PROBE_TARGET_HOSTNAME` 配置（Compose 内默认指向 `tls:8443`）。

## 不中断与一致性设计

- **新握手用新证，老连接跑完老请求**：TLS 服务每条新连接从当前
  `SSLContext` 包装；上下文热切换后，已建立连接仍持有旧上下文。
  `ThreadingHTTPServer` 每连接一线程，`/slow` 可验证在途请求不受影响。
- **原子落盘**：新版本先写临时目录（含 fsync）并试加载，再
  `os.replace` 切换 `current.json`；失败清理半成品，绝不触碰现役版本。
- **交错保护（CAS）**：`expected_version` 与现役版本不符返回 409；
  较早发起的换证无法覆盖较晚已成功的版本。并发写由 `fcntl.flock` 串行化。
- **重启语义**：进程重启后读取最后完整保存的 `current.json` 指向的版本。

## 测试

```bash
pip install -r requirements.txt
PYTHONPATH=. python -m unittest tests.test_cert_store -v   # 单元/并发
PYTHONPATH=. python -m unittest tests.test_probe -v         # 探测单元（含中断恢复）
PYTHONPATH=. python -m unittest tests.test_e2e -v           # 端到端（真实进程）
```

E2E 覆盖：换证生效、在途慢请求不中断、CAS 交错 409、三类校验失败回退、
重启恢复；探测覆盖成功归组、与换证交错时各样本归属实际握手证书、
TLS 停摆失败进 unknown 且换证不被阻塞、单轮 409 与参数 422、
管理面被 SIGKILL 后已完成样本可查且在途任务标为 interrupted。

## 目录

```
app/cert_store.py   校验、版本化持久化、CAS、并发锁
app/tls_service.py  ssl 热加载 HTTPS 服务（/health、/slow）
app/probe.py        一次性 TLS 并发探测、指纹归组、持久化与中断恢复
app/main.py         FastAPI 管理接口（换证 + 探测）
tests/              单元与端到端测试
docker-compose.yml  mgmt + tls 双服务，共享 cert-data 卷
```
