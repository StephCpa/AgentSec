# AgentSec

Agent 密码学系统研究：受约束的委托、可验证的行动、可计量的信息释放。

本次审核修复 F1（凭证命名空间）、F2（响应契约）和 D1（草稿期限）；说明与兼容性边界见 [修复记录](docs/reviews/2026-10-25-resolution.md)。旧数据库不自动迁移。适配器仍未完成完整轨迹精化验收。

## 项目内容

- [完整详细设计](docs/design.zh-CN.md)：从 ChatGPT Page 导出的设计正文（2026-10-25）。
- [原型说明与运行方法](outputs/agent-cryptography-design-20261025/prototype/README.md)：事务状态机、共享隐私预算、签名委托、见证恢复、交付与公开网关。
- [阶段验收矩阵](outputs/agent-cryptography-design-20261025/phase_acceptance_matrix.json)：已完成证据与尚未完成的目标。
- [交付清单与源码摘要](outputs/agent-cryptography-design-20261025/delivery_manifest.json)：v37 / 提交 8a35b4b 的历史验证快照，其摘要不用于验证修复后的源码。

保留原有 `outputs/agent-cryptography-design-20261025/` 路径，方便按原型说明复现。

## 状态与边界

这是研究设计和合成数据原型，不是生产可部署的安全服务，也没有完整安全证明。已有报告记录 30 组通过的测试套件；它们包含重叠证据，不能相加解释为独立故障覆盖。这些报告是原工作环境的历史结果，不代表所有环境都已重新验证。

`prototype/public_trace_adapter.py` 已修复审核指出的期限错误并增加局部回归，但仍是未完整验收草稿，不属于 v37 已验收源码清单。完整观察归约、真实部署隔离、强基线比较和生产保证仍有待完成。

测试中的固定密钥和身份均为合成材料，仅用于复现。测试依赖见 [requirements.txt](outputs/agent-cryptography-design-20261025/prototype/requirements.txt)。部分测试需要 OpenSSL 命令和本机网络端口；详细命令见原型说明。

示例：在仓库根目录运行：

```sh
python3 -m pip install -r outputs/agent-cryptography-design-20261025/prototype/requirements.txt
python3 outputs/agent-cryptography-design-20261025/test_public_transcript.py
```

原始在线设计：[Agent 密码学系统详细设计与验证方案](https://chatgpt.com/space/page_5c2a42360c80819188315c2158d8bb59)。仓库中的 Markdown 副本可独立阅读。

## 不覆盖历史报告的验证

```sh
python3 scripts/verify.py --models --output /tmp/agentsec-verification-new
```

该命令在临时副本中执行所有测试入口和模型，报告绑定运行时源码与依赖版本。GitHub Actions 将固定依赖与升级依赖分开运行。

本次修复的本地结果与源码绑定见 [验证摘要](docs/reviews/evidence/summary.json)：原有 30 套件、7 个模型入口通过；最终审核回归 15 项通过。

## 后续研究：公开轨迹与持久化成本

PR #1 已合并。新的受限轨迹检查与成本实验见 [2026-10-26 研究记录](docs/research/2026-10-26-progress.md) 和 [范围契约](docs/research/restricted-trace-contract.json)。它们提供有限条件对应和本机实测，不代表完整精化证明或生产性能验收。

```sh
python3 outputs/agent-cryptography-design-20261025/prototype/restricted_trace.py --output /tmp/agentsec-traces-new
python3 outputs/agent-cryptography-design-20261025/prototype/persistence_experiment.py --output /tmp/agentsec-cost-new.json
```

进一步的[构造性模拟记录](docs/research/2026-10-26-constructive-simulation.md)增加从公开输入生成签名报文的候选模拟器：200 个有限案例逐字节匹配，包含首项输出 0–3 的自适应分支。它依赖显式签名资源，并共享部分转换规则，仍不是完整精化证明。

```sh
python3 outputs/agent-cryptography-design-20261025/prototype/constructive_trace.py --output /tmp/agentsec-constructed-new
python3 scripts/replay_constructive.py docs/research/public-failure-evidence-20261026/constructive --output /tmp/agentsec-replay-new.json
```

[逐步状态关系检查](docs/research/2026-10-26-stepwise-relation.md)继续把 R1–R4 转成可执行断言：每个已完成事件后分别比较请求/凭证、预留与支出、公开调度、发布决定和原始期限。该诊断读取真实账本的指定字段，读数不传给生成器；仍需完成一般归纳和故障模型扩展。

```sh
python3 outputs/agent-cryptography-design-20261025/prototype/stepwise_trace.py --output /tmp/agentsec-stepwise-new
```

[公开失败边界修复](docs/research/2026-10-26-public-failure-boundaries.md)纠正了超长请求、错误长度证书指纹和未知分派错误被模型误转为正常拒绝的问题。当前重放入口使用针对修复后源码重新运行的证据；此前报告保留原源码绑定。

[交付状态关系](docs/research/2026-10-26-delivery-state-relation.md)进一步检查已准备报文、接收首次事实、发送确认、路由确认根和全局最终前缀，并增加回执可见但尚未确认的执行路径。

```sh
python3 outputs/agent-cryptography-design-20261025/prototype/delivery_relation_trace.py --output /tmp/agentsec-delivery-relations-new
```

[见证帧压缩与成本对照](docs/research/2026-10-26-witness-compression.md)增加可选有界压缩：六组执行期镜像的编码字节减少约 79%–82%，原始摘要、提交次数与恢复后的 R1–R8 投影保持一致；本机 mTLS 快照耗时增加，默认继续使用原始帧。

```sh
python3 outputs/agent-cryptography-design-20261025/prototype/compression_experiment.py --output /tmp/agentsec-compression-cost-new.json
```

[镜像行编码复用](docs/research/2026-10-26-canonical-row-reuse.md)进一步消除单次状态镜像内的重复编码：六组本机对照中，快照构造 CPU 中位耗时降低约 15%–25%，查询执行阶段降低约 8%–24%；镜像字节、完整状态检查和 CAS 次数保持不变。

```sh
python3 outputs/agent-cryptography-design-20261025/prototype/image_serialization_experiment.py --output /tmp/agentsec-row-reuse-cost-new.json
```
