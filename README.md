# AgentSec

Agent 密码学系统研究：受约束的委托、可验证的行动、可计量的信息释放。

## 项目内容

- [完整详细设计](docs/design.zh-CN.md)：从 ChatGPT Page 导出的设计正文（2026-10-25）。
- [原型说明与运行方法](outputs/agent-cryptography-design-20261025/prototype/README.md)：事务状态机、共享隐私预算、签名委托、见证恢复、交付与公开网关。
- [阶段验收矩阵](outputs/agent-cryptography-design-20261025/phase_acceptance_matrix.json)：已完成证据与尚未完成的目标。
- [交付清单与源码摘要](outputs/agent-cryptography-design-20261025/delivery_manifest.json)：v37 验证快照，附各模型与测试报告。

保留原有 `outputs/agent-cryptography-design-20261025/` 路径，方便按原型说明复现。

## 状态与边界

这是研究设计和合成数据原型，不是生产可部署的安全服务，也没有完整安全证明。已有报告记录 30 组通过的测试套件；它们包含重叠证据，不能相加解释为独立故障覆盖。这些报告是原工作环境的历史结果，不代表所有环境都已重新验证。

`prototype/public_trace_adapter.py` 是暂停时保存的未验证草稿，尚未接入测试，不属于 v37 已验收源码清单。完整观察归约、真实部署隔离、强基线比较和生产保证仍有待完成。

测试中的固定密钥和身份均为合成材料，仅用于复现。测试依赖见 [requirements.txt](outputs/agent-cryptography-design-20261025/prototype/requirements.txt)。部分测试需要 OpenSSL 命令和本机网络端口；详细命令见原型说明。

示例：在仓库根目录运行：

```sh
python3 -m pip install -r outputs/agent-cryptography-design-20261025/prototype/requirements.txt
python3 outputs/agent-cryptography-design-20261025/test_public_transcript.py
```

原始在线设计：[Agent 密码学系统详细设计与验证方案](https://chatgpt.com/space/page_5c2a42360c80819188315c2158d8bb59)。仓库中的 Markdown 副本可独立阅读。
