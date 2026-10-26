# 受限线协议的独立跨语言验证

本轮为公开轨迹与持久化见证增加第二种语言的协议检查。Python 原有运行时与独立 Node 实现对 **1,598 个确定性案例全部一致**；归档输入重新执行也全部一致。六种故意引入的语义错误均被指定案例识别。本轮没有发现需要修改生产协议代码的问题。

研究基线为 `732d21329dc90d96deb6ce69d9e846d8a5ccda48`（紧凑见证重提交）。此次新增测试工具、验证入口和证据；默认关闭的 `reassert` 行为及生产协议实现保持原样。该证据推进独立互操作验收，但仅覆盖以下受限子集。

## 实现与独立性边界

[Node 实现](../../tests/node/wire-profile.mjs)自行完成 CBOR 编解码、COSE Sign1 消息构造、公开签名响应、见证请求和签名回复的字段校验。它只使用 Node 内置模块，没有调用 Python、导入生产代码或安装共享协议库。驱动只向它传入输入，不传入预期接受标记、预期字节或 Python 输出。

[Python 驱动](../../outputs/agent-cryptography-design-20261025/prototype/wire_interop.py)调用实际 `wire`、`public_gateway` 与 `TLSWitnessClient.call` 路径。见证回复检查替换传输函数来注入归档报文，并固定合成挑战；本轮不建立真实网络连接。Node 与 Python 的接受/拒绝结果、成功解码结果、编码及签名字节、已认证错误码分别比较。普通无效报文的错误文案不要求一致，内部异常不能冒充协议拒绝。

Node 使用 BigInt 保留 64 位整数，严格检查 UTF-8 并保留 U+FEFF，拒绝重复键、非最短编码、不定长形式、未支持类型及越界容器。键顺序采用编码字节的字典序，与本项目选择的核心确定性编码一致；不能替换为先按长度排序的另一配置。参见 [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)。

两侧独立构造 COSE `Signature1` 签名结构和本项目外部 AAD，固定 Ed25519 算法编号 `-19`。测试包含具有正确签名但算法、受保护头或字段政策不合规的报文，避免无效签名掩盖解析政策错误。参见 [RFC 9052 §4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4)、[RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2)。Node 的 Ed25519 调用采用其[官方 crypto 接口](https://nodejs.org/docs/latest-v24.x/api/crypto.html)。

独立性限于协议实现层：Node 和 Python cryptography 的底层密码原语都依赖 OpenSSL 家族，不构成独立数学实现或密码学证明。Node 校验规则仍由同一项目契约实现，也可能与 Python 共同误读规范；人工预期和负对照只减少部分共同错误风险。

## 语料与结果

| 操作 | 案例数 |
|---|---:|
| CBOR 解码 | 976 |
| CBOR 编码 | 223 |
| COSE 验签 | 94 |
| COSE 签名 | 20 |
| 公开响应校验 | 83 |
| 见证请求校验 | 91 |
| 见证签名回复校验 | 111 |
| 合计 | 1,598 |

其中 878 个案例带显式预期接受结果，其余用于两实现差分比较；618 个输入被两侧接受。语料包含 37 个已冻结公开响应向量（包括 F2 audience 回归），整数/容器边界、Unicode、确定性生成对象、位翻转与截断、400 个随机字节输入、见证正文上限，以及 `reassert` 的空正文与签名绑定。固定生成种子为 20261026。

20 个 Node 签名均与 Python 的确定性签名字节完全相等，并经 Python 实际验签；Python 生成的签名也由 Node 验证。签名域包括多个对象类型，但这不表示其完整业务对象契约均已实现。见证错误回复同时覆盖允许的已签名拒绝和未授权错误码。

| 临时 Node 副本中的故意错误 | 差异案例数 |
|---|---:|
| 将 uint64 转为 Number 后再转回 | 13 |
| 丢弃 UTF-8 BOM | 1 |
| 改为先按编码长度排序键 | 2 |
| 放行通用 EdDSA 编号 -8 | 1 |
| 将固定 audience 放宽为普通标识符 | 1 |
| 把签名对象域合并为同一个域 | 52 |

六个负对照均触发指定语义或接受性差异，不以程序崩溃作为成功。这些是测试工具临时副本中的人为缺陷，不是本轮发现的 Python 漏洞。上述计数可能重叠，不能相加为安全覆盖度。

## 运行环境与证据

统一验证通过 **30 个原有测试套件、148 项仓库回归和 7 个模型入口**。本轮 5 项专项测试包含在 148 项内；语料与负对照也会在这些测试中执行，计数不能相加为独立覆盖。

本机运行 Node v26.6.0 / OpenSSL 3.6.3、Python 3.9.6 / cryptography 49.0.0；cryptography 后端为 OpenSSL 4.0.1。Python 标准库 TLS 版本与 cryptography 后端不是同一个信息项。CI 为两组 Python 依赖配置安装 Node 24；本机报告不替代该版本的 CI 结果。

- [汇总与源码哈希](wire-interop-evidence-20261026/summary.json)
- [完整输入和两侧结果，XZ 无损压缩](wire-interop-evidence-20261026/cases.jsonl.xz)
- [负对照与变异源码哈希](wire-interop-evidence-20261026/negative-controls.json)
- [全部归档输入的执行重放](wire-interop-evidence-20261026/replay.json)
- [完整验证](wire-interop-evidence-20261026/run.json)、[证据清单](wire-interop-evidence-20261026/manifest.json)

语料中包含固定的合成私钥，仅用于复现，不是部署凭据。报告将执行的 Node 文件、Python 驱动、实际生产解析器、冻结向量和候选 CDDL 绑定到源码摘要；记录 CDDL 摘要不表示运行过独立 CDDL 验证器。

在仓库根目录安装 Node（CI 使用 24）和 Python 依赖后执行；输出目录须为新路径：

```sh
python3 -m unittest discover -s tests -p 'test_node_interop.py' -v
python3 outputs/agent-cryptography-design-20261025/prototype/wire_interop.py --output /tmp/agentsec-wire-new
python3 scripts/replay_wire_interop.py /tmp/agentsec-wire-new --output /tmp/agentsec-wire-replay-new.json
python3 scripts/verify.py --models --output /tmp/agentsec-wire-verify-new
```

重放先核对源码摘要，然后重新执行两种实现并比较归档结果；不是只比较文件摘要。缺少 Node 时统一验证明确失败，不跳过跨语言测试。

## 尚未覆盖

本轮没有实现完整 Grant/Delegation、action、delivery、retention 等对象家族的独立业务契约，也没有独立 CDDL 引擎验证、跨语言线上客户端、TLS 帧互操作、任意输入穷举或持续模糊测试。它检查公开轨迹所依赖的部分报文边界与见证回复，不证明一般运行时精化、并发恢复、完整网络观察隐私、差分隐私组合或跨主机不可回滚。

此前持久化成本结果仍适用其原始工作负载与源码绑定；本轮没有新性能结论。下一阶段应继续补齐对象家族及独立契约验证，再扩展交付/恢复中断下的状态关系，并用实际部署与强基线测量验证成本主张。
