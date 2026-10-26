# AgentSec 交互架构图集

直接打开 [index.html](index.html)，无需服务、联网或安装依赖；也可解压 [完整图集](AgentSec-architecture-atlas.zip)。六张图均内嵌在总览中。点击图内「静态」启用连线动画；系统的减少动态效果偏好会被尊重。动画表示逻辑关系，不表示实测流量或耗时。

| 视图 | 阅读问题 | 独立文件 |
|---|---|---|
| 系统架构 | 组件、可信边界与持久化关系 | [HTML](architecture.html) / [JSON](architecture.json) |
| 数据流 | 私有贡献怎样转化为受授权输出 | [HTML](dataflow.html) / [JSON](dataflow.json) |
| 请求时序 | 预留、执行、发布、确认如何排序 | [HTML](request-sequence.html) / [JSON](request-sequence.json) |
| 恢复时序 | 见证已提交而本地结果未知时如何恢复 | [HTML](recovery-sequence.html) / [JSON](recovery-sequence.json) |
| 模块层次 | 运行时、持久化与研究证据如何分工 | [HTML](hierarchy.html) / [JSON](hierarchy.json) |
| 生命周期 | 取消、预算消耗与交付终态如何分支 | [HTML](lifecycle.html) / [JSON](lifecycle.json) |

原生图支持节点详情、源码定位、搜索、缩放、路径探索、主题切换、演示与导出。总览支持键盘切换标签、专注阅读与下载当前图。源码链接固定到 AgentSec 提交 `2b596d41a2b9e217c1273a68f592dc71fcf76439`，打开链接需要网络。

## 图的口径

- 依据研究分支而非 main，包含尚未合并的研究增量。
- 架构图中的网关、内核、发布器是同一 Python 账本对象内的逻辑模块。发布器到见证的连线概括整个受保护事务提交路径，见证保护并不限于发布器。接收端独立见证在总图中省略。
- 数据流汇总贡献输入与公开网关等不同参考配置的逻辑血缘，不表示这些配置已被合并为单一服务。公开状态分支只传递元数据；最终事件另受 ACK 确认与连续前缀约束。
- 请求时序假设挑战已经完成，展示成功准入路径。可信控制器驱动后续工作；不是 SUBMIT 同步执行。重复守卫提交、准备信封及查询事务被压缩。
- 恢复时序限定在见证已接受、发送端本地未提交的分支。恢复不执行业务、不重新采样、不退预算；并发权威变化仍是开放研究项。
- 层次图按职责组织，不是继承图。生命周期图组合操作、发布与交付状态，不是单个字段的完整状态机。
- 合成角色不是真实 LLM，逻辑分组不代表强制进程隔离。完整证明、强基线、生产故障域、隐藏授权与 TEE/MPC 尚未完成。

## 生成与复现

使用 [Archify](https://github.com/tt-a1i/archify) 3.2.0，固定源码提交 `81c6be8d87090670c45d08a8f97f9d29c5af0bec`。未安装全局技能、未改动其渲染器。六个原生 HTML 由官方 `finalize` 生成，总览仅嵌入原文件。保留 JSON 输入、四阶段检查回执、源码与产物摘要以及许可文件。

在本仓库相同目录结构中，准备固定提交的 Archify checkout，然后运行：

```sh
python3 .archify/atlas-agentsec-20261026-100827/build_atlas.py --archify /path/to/archify
```

依赖 Node.js 18+、Python 3.9+ 与 Chrome/Chromium/Edge（浏览器检查）。每次修改输入后使用新的 `--evidence-dir`，保留旧回执。例如 `--evidence-dir rebuild-review-2`。原生 HTML 自身的查看不需要这些工具。

`build_atlas.py` 在打包前核对六张图的输入、HTML 摘要和四项通过门槛；它不把页面打开成功当作验证通过。`manifest.json` 记录固定源码、渲染器版本、每张图摘要与总览摘要。回执保留生成环境的绝对路径，源码链接只使用固定 GitHub 提交。

## 开源许可

嵌入的 Archify 运行时与模板按其上游许可分发；完整 Apache-2.0、历史 MIT、NOTICE 与第三方说明位于 [licenses](licenses/)，并嵌入总览的“使用与范围”面板。JetBrains Mono 字体许可保留于原生 HTML 中；另附原文。图集内容与外层导航不宣称得到 Archify 官方背书。
