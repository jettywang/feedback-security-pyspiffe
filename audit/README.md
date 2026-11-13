# py-spiffe X.509-SVID 验证边界审计

审计对象：`spiffe/src/spiffe/svid/x509_svid.py` 的 `X509Svid.parse` / `parse_raw`（`load` 只是文件读取 + 这两个入口）。
诊断脚本：`audit/x509_svid_boundary.py`（仓库根目录运行 `python3 audit/x509_svid_boundary.py`，证书现场生成，无外部依赖）。

## 核心结论

`parse`/`parse_raw` 是**结构校验器**，不是信任判定器。它成功只说明"这是一份形状合规的 X.509-SVID 材料"，
绝不说明"对端工作负载身份可信"。身份可信性只能在 TLS 握手（对信任域 bundle 的链验证 + 私钥持有证明）之后成立。

## parse/parse_raw 成功时已确认的事实（L1）

- 证书链字节可解析为 X.509（PEM 或拼接 DER），私钥可解析为未加密 PKCS#8。
- 叶子（`chain[0]`，纯按位置认定）：有 BasicConstraints 且 CA=false；有 KeyUsage 且
  `digitalSignature=true`、`keyCertSign=false`、`cRLSign=false`。
- 叶子 SAN 扩展存在，且**恰好一个** URI SAN，以 `spiffe://` 开头、是合法 SPIFFE ID、路径非空（非信任域根）。
- 链上其余每一张证书：BasicConstraints CA=true 且 KeyUsage 含 `keyCertSign`（按"中间 CA"角色校验）。

## parse/parse_raw 不检查、必须等后续层的事实

| 事实 | parse 是否检查 | 由谁兜底 |
|---|---|---|
| 私钥与叶子证书公钥匹配 | 否（全库无任何对应检查） | TLS 层：`ssl.load_cert_chain` 即抛 `KEY_VALUES_MISMATCH`；握手更不可能完成 |
| 链上签名链接（每张证书确由下一证书签发） | 否（只做逐张角色校验） | 链验证 / TLS 握手：`CERTIFICATE_VERIFY_FAILED` |
| 链终止于受信根（trust bundle） | 否（parse 根本不接触 bundle） | 链验证 / TLS 握手 |
| 有效期 notBefore/notAfter | 否 | 链验证 / TLS 握手 |
| EKU（clientAuth/serverAuth） | 否 | TLS 握手 |
| 吊销状态 | 否 | 依赖短 TTL + bundle 轮换（SPIFFE 模型） |

## 逐层对照（本地测试证书，全部带合法 SPIFFE URI 与合规用途，每个场景只破坏一个关系）

| 场景 | L1 parse/parse_raw | L2 私钥↔证书 | L3 对 bundle 链验证 | L4 TLS 握手 |
|---|---|---|---|---|
| ok（对照组） | ACCEPT | MATCH | VERIFIED | ACCEPT (TLSv1.3) |
| key_mismatch（私钥不配对） | **ACCEPT** | MISMATCH | VERIFIED | REJECT（`load_cert_chain`: KEY_VALUES_MISMATCH） |
| broken_link（叶子由中间CA-A签发，链里放的却是中间CA-B） | **ACCEPT** | MATCH | FAILED | REJECT（CERTIFICATE_VERIFY_FAILED） |
| reversed（中间CA排在叶子前） | REJECT（`InvalidLeafCertificateError`） | — | — | — |
| untrusted_ca（链完好但根不在 bundle） | **ACCEPT** | MATCH | FAILED | REJECT（CERTIFICATE_VERIFY_FAILED） |
| expired（叶子已过期，附加坡坏项） | **ACCEPT** | MATCH | FAILED | REJECT（CERTIFICATE_VERIFY_FAILED） |

要点解读：

- **私钥不匹配**：`parse` 照样返回一个"看起来完整"的 `X509Svid`（spiffe_id、链、私钥俱全）。
  该对象若被拿去 `save()` 落盘或塞进 TLS 配置，错误要到 `load_cert_chain` 才爆。
  这是三个场景中最隐蔽的：不碰 TLS 就完全无感。
- **链顺序错误**要分两种：
  - 叶子不在首位（reversed）：parse 拒绝——但原因是"位置 0 的证书没通过叶子角色校验"，
    属于结构检查的副产品，不是签名链接检查。
  - 叶子在首位但链接断裂（broken_link）：parse **接受**。逐张角色校验全部通过，
    因为它从不验证 `cert[i]` 的签名能被 `cert[i+1]` 的公钥解开。
- **不受信 CA**：parse 与 bundle 完全解耦，形态完美的敌对面链照收不误。
  信任锚只在 TLS 握手（spiffe-tls 用 `X509Source`/bundle 构建 verify 上下文）时才介入。
- **过期证书** parse 也接受——连有效期都不在结构校验范围内。

## 调用方建议

1. **不要用 `parse`/`load` 的成功作为授权依据。** 它只是解包 Workload API 响应或磁盘文件的手段。
   对端身份只在 TLS 握手完成、并用 authorizer（如 `spiffetls.tlsconfig.authorize`）核对
   对端 SPIFFE ID 之后才可信。
2. **本端 SVID 优先走 `X509Source` + spiffe-tls**（`spiffetls.listen`/`dial` 或
   `create_ssl_context`），让 bundle 验证、私钥匹配、自动轮换都发生在 TLS 层，
   而不是手工 `parse` 后自拼 `ssl` 上下文。
3. **如果必须手工 `parse`**（如自定义 TLS 栈），在信任解析结果前至少补两道闸：
   - 私钥匹配：`leaf.public_key().public_bytes(...) == private_key.public_key().public_bytes(...)`
     （诊断脚本 `layer2_key_match` 即参考实现）；
   - 对当前 bundle 做链验证：`cryptography.x509.verification.PolicyBuilder().store(Store(bundle_roots)).build_client_verifier().verify(leaf, intermediates)`，
     它同时覆盖签名链接、信任锚与有效期。
4. **永远不要在验证对端时使用本端 `parse` 出的 SVID 做类比推理**：
   "我的 SVID 能 parse" 与 "对端证书链可验证到信任域根" 是两条独立路径，前者不含任何后者的事实。
5. `hint` 字段是 Workload API 附加的未认证元数据，不得用于授权判断（`x509_svid.py:111` 的 docstring 已明确）。
