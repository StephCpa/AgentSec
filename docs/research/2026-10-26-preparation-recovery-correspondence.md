# 发送准备中断与恢复后的公开轨迹对应

本轮检查发送方在准备信封或终止消息时退出，恢复后究竟应保留哪些证据。关键区别是“准备调用没有返回”与“没有持久化信封”：如果见证已接受该事务，即使调用方未得到结果、接收方尚未接触信封，到期终止消息也必须绑定该信封的哈希。若见证尚未接受首次准备，则不能凭一次未完成调用创造这项证据。

研究基线为 `b5fceedf48fc6bbbd8231ebb6254fc3b96e41fe5`。本轮新增独立准备模拟器、实际退出驱动、归档重放和回归；复用既有 R1–R8 状态投影及空接收端初始化。没有修改准备协议、恢复算法、预算规则或持久化粒度。完整边界见[配置契约](preparation-recovery-contract.json)。

## 输入、观察与状态

[生成器](../../outputs/agent-cryptography-design-20261025/prototype/preparation_recovery_simulator.py)只使用公开配置、批准输出、显式签名资源及与数据无关的环境计划。`PREPARE` 指定操作、时间与 DELIVERY/TERMINAL；`PREPARE_CUT` 另指定切点；`PREPARE_RECOVER` 指定继续运行前恢复的操作。生成器不读取真实响应、见证头、镜像或数据库。签名回调是显式理想资源，不是从公钥推导私钥。

成功准备产生 `PREPARATION`，带已生成的签名 body。已到期、尚未到期或后续路由顺序不满足时产生 `PREPARATION_REJECTED`，带该参考方法的拒绝原因。退出产生 `PREPARATION_UNAVAILABLE`，仅含操作、时间及准备种类，没有 body、提交位或见证信息。同一计划的六个切点在该失败观察上完全相同。

这些观察包含可信协调方的方法返回和恢复通知，以及既有签名网关/交付流量；它们不是一个新增的外部网关接口，也不是完整攻击者网络视图。切点是独立环境输入，不由实际失败反推。故障后暂停本配置中的其他事件，直到显式恢复；生产系统的一般调度不由这个限制推出。

模型内部的 `prepared` 按权威状态推进。它不把准备当成接收，不产生接收首次事实、回执或最终事件。完成后的 SEND 仍生成独立尝试挑战，接收事实由真实接收端形成，再由 CONFIRM 推进发送端最终前缀。发送前已准备的信封不会使 `FINAL` 提前完成。

## 事务边界与恢复关系

[实际驱动](../../outputs/agent-cryptography-design-20261025/prototype/preparation_recovery_trace.py)关闭发送方连接，在新子进程中执行原 `prepare_envelope` 或 `prepare_terminal`。指定钩子调用 `os._exit(96)`；未达到切点、不同退出码或超时均失败。六个切点为方法内提交前、见证接受前、见证接受后、本地 anchor 写入后、方法内提交后、返回结果丢失。

设原权威状态为 W，准备事务为 P。见证接受前保留 W，接受后保留 P(W)。这里的 W 可以已经包含同一个信封或终止消息：一次重试在见证提交前退出，不能删除前次已提交的证据。方法内提交后与返回丢失均对应完整本地提交；见证接受后、本地提交前退出则保留旧本地事务，并要求真实新鲜性检查阻止继续操作。

新增 R13 检查：

1. 子进程确实退出；见证头只在接受后增加一，本地镜像与 anchor 一起保持旧状态或提交新状态。
2. 本地落后时必须出现 `WITNESS_RECOVERY_REQUIRED`，包括重复准备的镜像未改变但见证序号增加的情况。
3. 准备及恢复不改变任何接收方权威头。诊断副本和继续执行的新副本分别从权威镜像恢复，镜像字节完全相同、审计通过，恢复不推进权威头。
4. 完成私有计算后的 operations、jobs、accounts、charges、发布决定、票据和描述符保持原值。随机带和结果按不透明存储字节比较，不解密也不输入生成器。归档只保留此比较的结果，不暴露这些字段。
5. 每个恢复权威检查点继续核对 R1–R8；R5 单独核对已准备签名 body 和 handoff 标志，R6–R8 核对接收首次事实、确认与最终前缀。正常准备的逐字节重试也得到检查。

这是一组有限执行的对应关系。对所有允许输入的归纳证明、见证不回滚假设的实际实现、一般并发和完整隐私证明仍未完成。R13 不把其他故障配置的 R9–R12 自动组合进来。

## 判别场景

原票据在 100 签发、160 到期。到期边界与后续恢复的主要结果如下：

| 准备前状态及退出位置 | 到期后终止消息绑定的信封 | 接收方最终首次事实 |
|---|---|---|
| 首次信封准备，见证接受前退出 | 空哈希 | CLOSED / 160 |
| 首次信封准备，见证接受后退出 | 原信封哈希 | CLOSED / 160 |
| 信封已准备，重复准备在任一切点退出 | 原信封哈希 | CLOSED / 170 |
| 接收方已 ACCEPTED，但发送方尚未确认；终止准备中退出 | 原信封哈希 | 保留 ACCEPTED / 100 |

恢复不会续期：在 160 或 170 再次准备 DELIVERY，即使已有信封也必须拒绝。终止消息可以在到期后创建，但不会撤销接收方已经存在的首次 ACCEPTED 事实。已存在终止消息的重复准备保留原 body。其他计划覆盖计数、四桶直方图、跨路由最终顺序、后续 WITHHELD 项；总计 11 个计划，每种准备的六个切点均实际可达。

四类负对照用于验证检查器有判别力：把见证前切点误判为已提交会改变后续终止证据；恢复时续期会错误允许到期 DELIVERY；丢弃模型中的已准备证据会触发 R5；篡改不透明 seed 会触发 R13。它们是测试注入的错误，不是对现有实现存在这些漏洞的主张。

## 证据与复现

14 项专项回归通过。完整矩阵完成 **66 个计划/切点组合 × 8 个数据集 = 528 次实际进程退出**，分别完成 528 次诊断恢复及 528 次继续执行的新副本恢复，累计核对 **77,232 个状态检查点**。每组八个合成用户数据集的条件轨迹和关系摘要相同。每组固定批准输出，相邻数据集相差一个用户；这不测量 DP 输出分布，也不证明时序、长度或完整可用性泄漏。

统一验证通过 **30 个原有测试入口、196 项仓库回归和 7 个模型入口**；14 项专项回归包含在 196 项中，不相加为独立覆盖。验证后逐项核对源码摘要与当前工作树一致。

528 个归档案例重放全部通过，显式比较 **1,584 个有向用户增删邻接对**。重放重新生成报文、签名调用及最终模型状态，核对输入和源码摘要，并比较每组三位用户掩码的有向邻接对。原运行的数据库投影摘要会绑定到重放结果，但重放不会重新读取那些已删除的数据库、也不会重新执行子进程。因此不能把归档重放算成另一轮实际崩溃实验。

- [矩阵汇总与源码摘要](preparation-recovery-evidence-20261026/summary.json)、[完整输入及检查点](preparation-recovery-evidence-20261026/cases.jsonl.xz)、[实际执行日志](preparation-recovery-evidence-20261026/matrix.log)
- [归档重放](preparation-recovery-evidence-20261026/replay.json)、[专项回归](preparation-recovery-evidence-20261026/targeted-tests.log)
- [统一验证](preparation-recovery-evidence-20261026/verification.json)、[全部验证日志](preparation-recovery-evidence-20261026/verification-logs.json.xz)、[证据清单](preparation-recovery-evidence-20261026/manifest.json)

```sh
python3 -m unittest discover -s tests -p 'test_preparation_recovery.py' -v
python3 outputs/agent-cryptography-design-20261025/prototype/preparation_recovery_trace.py --output /tmp/agentsec-preparation-new
python3 scripts/replay_preparation_recovery.py /tmp/agentsec-preparation-new --output /tmp/agentsec-preparation-replay-new.json
python3 scripts/verify.py --models --output /tmp/agentsec-preparation-verify-new
```

本轮不覆盖发送方已确认后的准备、retention 清理、恢复再次退出、权威竞争与准备退出的组合、跨主机、断电或 TLS 故障；不新增性能数据。下一步需要把清理与恢复后的可观察证据对应起来，并继续评估完整状态复制和历史增长的成本，不能用这一阶段的案例数量替代完整目标。

下一阶段的验收不能直接沿用本配置中 R5 的 `no_retirement` 断言。按当前实现，至少需要分别建模发送方准备 offer、接收方删除 live 行并提交 floor/root/last_offer、发送方确认 checkpoint 这三个事务；接收方删除后但见证接受前退出，恢复必须恢复完整旧窗口，接受后则恢复完整新窗口。R6 应区分逻辑历史首次事实与当前 live 窗口，R7 保留发送方归档，R8 的公开最终前缀不因清理倒退。清理后的 FINAL 查询拒绝与 RETIRED/checkpoint 响应也需进入观察，不能把 checkpoint 当成已删历史事实的重建证明。

成本对照应同时测接收方 live 表、发送方保留归档、见证镜像与 SQLite 物理文件；当前实现仅删除接收方 live 行，不能从该行数减少推断总存储有界。这些是下一阶段由当前代码导出的验收条件，尚未由本轮实验验证。
