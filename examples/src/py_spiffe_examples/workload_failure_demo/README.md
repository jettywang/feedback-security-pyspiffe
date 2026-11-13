# Workload API 短暂断开：本地 SVID 与联邦 bundle 的保留策略

本目录是可运行的故障时序演示。它不连接 SPIRE、不监听端口，但使用真实的
`spiffe` 重试状态机、真实 `spiffetls` 信任根装载路径和真实 pyOpenSSL 握手。

运行：

```bash
uv run --package py-spiffe-examples workload-failure-demo
uv run --package py-spiffe-examples workload-failure-demo --json
cd examples && uv run pytest tests/test_workload_failure_demo.py -q
```

## 1. 当前状态机实际做了什么

结论先说：**短暂断开时继续用最后一份材料是现状；但“永久授权错误”并不会让
py-spiffe 停止重连，而且本地 SVID 与联邦 bundle 在现状里都没有独立的新鲜度边界。**

| 事实 | 位置 |
| --- | --- |
| 仅 `CANCELLED` 和 `INVALID_ARGUMENT` 视为不可重试 | `spiffe/src/spiffe/workloadapi/workload_api_client.py:77` |
| `PERMISSION_DENIED` 不在其中，因此会一直重试 | 同上 |
| 默认无限重试，退避 `0.1 × 2^n`，上限 5s | `workload_api_client.py:139-152` |
| 流正常结束也重连；只有拿到有效 update 才 `reset()` | `workload_api_client.py:615-623` |
| 重试耗尽或流结束时调用 `on_error` | `workload_api_client.py:692-705` |
| `X509Source._on_error` 永久关闭 source | `spiffe/src/spiffe/workloadapi/x509_source.py:309` |
| source 只在读取时做锁保护，没有 notAfter/年龄检查 | `x509_source.py:138` |
| `spiffetls` 每次更新只 `add_cert`，从不移除旧根 | `spiffe-tls/src/spiffetls/context.py:128-143` |
| `dial()` 每次新建 `SSL.Context`；`listen()` 的 context 长生命周期 | `dial.py:31`、`listen.py:62` |

两个容易误判的点：

1. **`PERMISSION_DENIED` 是“永久授权错误”，但当前状态机把它当临时错误。**
   演示中它在 60s 内以 5s 上限持续重试，`X509Source` 始终可用，新连接继续使用
   最后一份 SVID。
2. **`spiffetls` 的 trust-store 更新是 add-only。** 更新一个“已创建过连接”的
   `SSL.Context` 会直接抛
   `Context has already been used to create a Connection, it cannot be mutated again`；
   该异常被 `X509Source._notify_subscribers` 记录后吞掉。未被使用过的 context
   则会把新根加入，但**不会删掉旧根**。因此 `listen()` 场景下“移除联邦根”对
   新握手不一定立即生效。

## 2. 方案比较

把“继续使用最后一份身份材料”拆成两件不同的事，不能共用一个 TTL：

### 2.1 本地 SVID（我们向对端证明自己）

| 方案 | 行为 | 优点 | 缺点 |
| --- | --- | --- | --- |
| A. 立即停止 | 任何流中断即拒绝新 dial | 语义最简单；不会用旧身份 | 短暂 agent 重启造成不必要的全量中断 |
| B. 短期保留（推荐） | 在 `min(local_grace, notAfter - margin)` 内继续 | 覆盖秒级抖动；仍受证书本身到期约束 | 需要额外定时器与指标 |
| C. 无限保留（现状） | 永远复用最后 SVID，直到 OpenSSL 拒绝 | 无状态改动 | 到期前无法主动止损；撤销只能等证书自然过期 |

停止条件（B）：
- `now >= leaf.notAfter`：硬停止。
- `notAfter - now <= local_expiry_margin`：提前停止，避免握手途中过期。
- 授权类永久错误（`PERMISSION_DENIED` / `UNAUTHENTICATED`）：立即停止。
- 连续不可达超过 `local_grace`：停止。

恢复条件：
- 任意一次成功 update 送达：清零重试计数、刷新 `notAfter`、解除停止。
- 仅“TCP/UDS 连通但无 update”不算恢复；`_watch` 的 `reset()` 只在
  `on_success` 之后发生。

旧连接边界：
- 已建立的 TLS 会话不会因为 Workload API 断开而失效；TLS 不在应用数据上重新
  校验证书。若要求撤销后立即断流，只能主动关闭连接。
- 建议在新 dial 停止后给 `established_drain`（默认 30s）排空期，然后关闭；
  这是策略选择，不是 TLS 协议行为。

### 2.2 联邦 bundle（我们验证对端）

| 方案 | 行为 | 优点 | 缺点 |
| --- | --- | --- | --- |
| A. 随本地 SVID 一起停 | 共用一个 grace | 实现简单 | 信任判断被本地身份可用性绑架 |
| B. 独立短期保留（推荐） | `federated_grace` 内继续验证既有联邦域 | 联邦短暂中断不影响已授权的跨域流量 | 需要区分“观察到的移除”与“没收到更新” |
| C. 无限保留（现状） | 永远信任最后 bundle | 无改动 | 移除信任根后仍可能接受旧域对端；add-only context 加剧问题 |

停止条件（B）：
- **显式移除立即生效**：update 中消失的 trust domain 立即进入拒绝集合，并保留
  tombstone，直到进程重启；后续旧快照不能把它“复活”。
- 连续不可达超过 `federated_grace`：停止使用该 bundle 做新握手。
- bundle 年龄超过 `federated_max_age`：即使期间有短暂恢复，也强制刷新。
- 永久授权错误：与本地 SVID 同步停止。

恢复条件：
- 新 update 重新包含该 trust domain，且该域没有 tombstone。
- 收到更新即刷新 bundle 年龄；不因“流重新建立”而刷新。

旧连接边界：
- 与本地 SVID 相同：已建立的 mTLS 会话不会重新验证对端证书链。移除信任根只
  影响新握手；若要求旧连接也失效，必须应用层主动关闭或依赖短连接。

## 3. 故障时序（演示输出摘要）

### 3.1 临时网络错误（UNAVAILABLE，10s 与 10.3s）

- 重试按真实序列 `0.1, 0.2, 0.4, ...`，30s 的 update 使计数归零。
- 两个方案都继续新 dial；`guarded` 的本地窗口为 120s，联邦窗口为 60s。
- 恢复条件：**收到 update**，不是“连接成功”。

### 3.2 永久授权错误（PERMISSION_DENIED）

- 现状：不停止，每 5s 重试；`X509Source` 保持打开，新 dial 继续成功。
- 推荐：立即停止新 dial；旧连接在 30s 排空后关闭。
- 这是两者差异最大的场景：现状无法在撤销注册后及时收敛。

### 3.3 证书到期（本地 SVID notAfter）

- 现状：没有主动检查；到期后新 dial 由 OpenSSL 拒绝（演示中 `FAIL`），
  但在“到期瞬间”之前仍会尝试，且错误发生在握手阶段而非策略阶段。
- 推荐：`notAfter - 30s` 即停止新 dial，把失败提前到决策点。
- 旧连接：仍可收发应用数据，除非应用主动关闭。

### 3.4 移除联邦信任根后断连

演示用真实的 `create_ssl_context` 得到四个结果：

| 路径 | 结果 |
| --- | --- |
| 移除前，`other.test` 对端 | 通过 |
| 移除后，**同一个未使用过的** SSL.Context | **仍通过**（add-only） |
| 移除后，新建 SSL.Context | 拒绝 |
| 移除后，已经用过一次的 SSL.Context | **仍通过**，且更新回调抛错被吞 |
| 移除后，仍保留的 `foreign.test` 对端（新建 context） | 通过 |

推荐的策略是“移除立即生效 + tombstone + 重建 context”，而不是继续往旧
`cert_store` 里 `add_cert`。注意 tombstone 必须跨恢复保留：演示中 120s 的恢复
update 仍然只包含 `foreign.test`，所以 `other.test` 继续被拒绝；这是刻意行为，
不是恢复失败。

## 4. 推荐参数及依据

| 参数 | 值 | 依据 |
| --- | --- | --- |
| `local_grace` | 120s | 覆盖 agent 重启与短暂网络抖动；远小于常见 1h SVID TTL，留出轮换余量 |
| `local_expiry_margin` | 30s | 至少覆盖一次握手 + 一次重试；避免“决策时有效、握手时过期” |
| `federated_grace` | 60s | 信任判断比身份证明更敏感；比本地窗口更短，优先收敛信任面 |
| `federated_max_age` | 3600s | 即使断续恢复，也强制每天至少刷新一次信任根 |
| `established_drain` | 30s | 给在途请求排空；超过后主动关闭，避免撤销后长期残留 |
| 重试策略 | 沿用 `0.1/2/5s` | 与现有 py-spiffe 行为一致；区分永久错误的收益大于调整退避曲线 |

这些值是**策略默认值**，不是协议常量。若 SVID TTL 更短（如 5 分钟），
`local_grace` 必须按比例缩小，且始终以 `notAfter - margin` 为硬上限。

## 5. 与“直接改 py-spiffe”的边界

当前库没有暴露“保留窗口”这个概念，因此本演示把策略放在应用侧
（`policy.py`），不修改库代码。若要内置，最小改动是：

1. 把 `PERMISSION_DENIED`/`UNAUTHENTICATED` 纳入永久错误分类（或允许调用方注入
   分类函数），并在 `_watch_*` 中触发“停新 dial”而非静默重试。
2. 在 `X509Source` 的 update 路径记录 `received_at` 与 `notAfter`，暴露只读快照；
   是否拒绝由调用方决定，避免库替应用做信任决策。
3. `spiffetls.context` 的更新应支持**替换**信任集合，并明确已使用 context 不可变；
   否则应在文档中要求长生命周期 server 使用可重建的 context 工厂。

本演示不实现这三项库改动，只给出可验证的行为基线与策略对照。
