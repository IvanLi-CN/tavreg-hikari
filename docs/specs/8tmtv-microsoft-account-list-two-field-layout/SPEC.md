# 微软账号列表双字段分组与图标化操作（#8tmtv）

## 状态

- 状态：已实现
- 负责人：Codex
- 更新时间：2026-04-18

## 背景

- 现有微软账号列表仍按大量单字段列横向展开，邮箱、密码、Proof 邮箱、状态和操作分散在多列里，导致横向占用过大，桌面与移动态都不利于快速浏览。
- 行内复制与操作入口主要依赖文字按钮和原生 `title`，不符合当前希望的“图标化 + 延迟 tooltip”交互口径。
- 默认列表排序仍回退到 `updatedAt`，与“按导入时间倒序查看账号池”这一运营使用习惯不一致。

## 目标

- 把账号列表桌面表格与移动卡片统一收敛为“每组两行字段”的紧凑布局。
- 将 `Proof 邮箱` 全量 owner-facing 改名为 `辅助邮箱`。
- 邮箱、辅助邮箱展示明文并提供复制图标；密码不展示文本，只保留复制图标与反馈。
- 所有行内操作按钮改为图标按钮，并统一使用第三方 tooltip 延迟提示用途，不再依赖浏览器原生 `title`。
- 列表默认按 `导入时间 desc` 展示，且恢复默认排序时回到该默认态。

## 非目标

- 不新增或修改账号相关 HTTP API、数据库字段和迁移。
- 不改造微软邮箱页、Keys 页、提号器主体或主流程控制台。
- 不新增密码 reveal / 解锁能力。

## 功能与行为规格

### 列表布局

- 桌面表格列固定收敛为：`账号 / 会话 / 收信 / 状态 / 时间 / 操作`。
- 每个业务列内部采用两行字段：第一行为主字段，第二行为副字段；主副字段都必须保持单行显示。
- `账号` 组展示 `邮箱 + 邮箱复制图标 + 密码复制图标` 与 `辅助邮箱 + 复制图标 + 分组 badge`。
- `会话` 组展示 `Session` 与 `Session Proxy + 行内编辑图标`。
- `收信` 组展示 `收信状态（含未读数）` 与 `Profile`。
- `状态` 组展示 `最近状态` 与 `项目复用/失败/废弃 badge`；当账号没有项目状态 badge 时，第二行回退为 `阻断 / 停用` 摘要。
- `时间` 组展示 `导入时间` 与 `最近使用`。
- 移动端继续使用卡片布局，但字段分组与桌面保持同一信息架构。

### 图标操作与复制

- 行内操作固定为图标按钮：`Bootstrap`、`设置辅助邮箱`、`恢复可用/标记不可用`、`收件箱`。
- 邮箱、密码、辅助邮箱复制统一使用图标按钮；密码复制图标采用钥匙图标并紧跟在邮箱复制图标之后。
- 复制成功或失败时，都必须在触发按钮附近显示气泡反馈，而不是弹窗；气泡内需要保留一块可点击全选的完整内容文本块，便于浏览器拦截剪贴板时手动复制。
- 所有图标按钮必须接入第三方 tooltip；hover / focus 后延迟显示用途文案。
- 账号列表相关图标按钮不得再使用原生 `title` 作为提示来源。

### 命名与默认排序

- 账号页列表、按钮、弹窗标题与字段标签中的 `Proof 邮箱` 统一改为 `辅助邮箱`。
- accounts 默认排序真相源改为 `导入时间 desc`。
- 点击 `导入时间` 或 `最近使用` 排序头后，仍保留 `降序 → 升序 → 恢复默认` 语义；其中“恢复默认”必须回到 `导入时间 desc`。

## 验收标准

- 首屏账号列表默认按 `导入时间` 倒序，且 `导入时间` 排序头在初始渲染时显示为激活降序。
- 桌面表格与移动卡片都只展示新的双字段分组，不再回退到旧的多独立列布局。
- 邮箱与辅助邮箱显示明文；密码不显示明文或掩码字符串，只保留复制入口。
- 所有行内操作入口为图标按钮，且 tooltip 来自第三方组件而非浏览器原生提示。
- 复制失败或浏览器拒绝自动复制时，按钮附近的气泡会展示失败原因与完整内容文本块，且文本块支持点击全选。
- 既有批量选择、批量 Bootstrap、Session Proxy 更换、恢复可用/标记不可用、打开收件箱能力保持可用。
- `bun run typecheck`、`bun test`、`bun run web:build`、`bun run build-storybook` 全部通过。

## Visual Evidence

- source_type: `storybook_canvas`
  story_id_or_title: `views-accountsview--desktop-tools-collapsed`
  state: `desktop tools collapsed`
  evidence_note: 证明桌面账号列表在左侧工具列收起后收敛为 `账号 / 会话 / 收信 / 状态 / 时间 / 操作` 六列，账号列已合并邮箱、密码复制、辅助邮箱与分组 badge，且默认排序态显示为导入时间降序。
  image:
  ![桌面账号列表双字段布局](./assets/accounts-table-desktop.png)

- source_type: `storybook_canvas`
  story_id_or_title: `views-accountsview--default-compact-cards`
  state: `mobile compact cards`
  evidence_note: 证明 375px 视口下改为双字段卡片布局，主副字段保持单行并通过截断吸收长值。
  image:
  ![移动账号卡片双字段布局](./assets/accounts-cards-mobile.png)

- source_type: `storybook_canvas`
  story_id_or_title: `views-accountsview--action-icon-tooltips-play`
  state: `tooltip hover`
  evidence_note: 证明账号列表图标按钮使用第三方 tooltip 延迟展示用途说明，不再依赖浏览器原生 title。
  image:
  ![图标按钮 tooltip 悬浮态](./assets/accounts-icon-tooltip.png)

- source_type: `storybook_canvas`
  story_id_or_title: `views-accountsview--copy-failure-fallback-play`
  state: `copy failure fallback bubble`
  evidence_note: 证明复制失败时会在按钮附近弹出气泡，展示失败原因与可点击全选的完整内容文本块，便于手动复制。
  image:
  ![复制失败反馈气泡](./assets/accounts-copy-failure-bubble.png)
