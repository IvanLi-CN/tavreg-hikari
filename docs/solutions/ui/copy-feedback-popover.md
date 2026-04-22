# 复制反馈气泡的正确实现

## 适用场景

适用于“点击复制图标后，显示一个带尾巴的短时反馈气泡”的界面，包括：

- 用户名 / 邮箱 / 邀请码等复制按钮
- 成功与失败两种反馈态
- 需要锚定到真实触发按钮
- 需要在窄视口和桌面视口下保持稳定定位

这类反馈不是纯提示文案，而是带失败兜底内容或手动复制内容的交互型浮层。

## 推荐方案

优先使用 `@floating-ui/react` 实现这类复制反馈气泡。

推荐原因：

- 主流、热门、持续维护
- React 生态成熟，适合做交互型浮层
- 原生支持 `arrow` middleware 和 `FloatingArrow`
- 可精细控制 `placement / offset / flip / shift / portal`
- 与 Tailwind CSS 兼容良好，样式层可完全自定义

## 不推荐的做法

### 不要把它当成 Tooltip

复制反馈带有明确状态、失败兜底内容时，它已经不是单纯 tooltip。

如果用 tooltip 承载：

- hover / focus 行为容易和反馈态冲突
- 成功 / 失败时容易出现双提示层
- 无法自然承载失败兜底内容

### 不要手搓尾巴补丁

不要通过下面这些方式“修”出一个尾巴：

- 额外绝对定位一个三角形或菱形块
- 用伪元素硬贴在主体边缘
- 通过 story 里的静态假气泡来冒充真实效果

这些做法的问题是：

- 尾巴和主体容易割裂
- 左右方向更容易出现遮挡和错位
- 真正换到真实组件或真实 portal 后，定位关系会失真

## 正确实现原则

### 1. 用真实触发元素作为锚点

尾巴必须指向真正的复制按钮，而不是：

- 指向一整块预览卡片
- 指向文本区域中心
- 指向 story 里人为摆出来的静态示意点

结论：验收“尾巴是否正确”时，必须让浮层锚定到真实复制图标按钮。

### 2. 用真实浮层，不用伪静态示意图

如果要做 Storybook 验证：

- 必须直接渲染真实 `CopyIconButton`
- 必须让真实浮层打开
- 必须让真实箭头参与定位

不要为了“集中展示”就手工画一个假气泡，因为那会绕开真正的定位链路。

### 3. 默认对齐优先用 `center`

复制图标通常很小，默认使用 `center` 对齐更容易满足“尾巴指向按钮中心”的直觉。

若默认使用 `start`：

- 上下方向容易偏到一侧
- 左右方向更容易让人感觉尾巴没指准

### 4. 让库处理碰撞与箭头定位

推荐交给 Floating UI 处理：

- `offset()`：控制气泡与触发按钮的距离
- `flip()`：空间不足时自动翻转
- `shift()`：避免超出视口
- `arrow()`：计算箭头位置
- `FloatingArrow`：渲染与位置同步的箭头

这样才能保证同一套实现能覆盖 `top / right / bottom / left`。

## 推荐实现骨架

```tsx
const arrowRef = useRef<SVGSVGElement | null>(null);

const { refs, floatingStyles, context } = useFloating({
  open,
  onOpenChange: setOpen,
  placement,
  whileElementsMounted: autoUpdate,
  middleware: [
    offset(8),
    flip({ padding: 12 }),
    shift({ padding: 12 }),
    arrow({ element: arrowRef }),
  ],
});
```

```tsx
<FloatingPortal>
  <div ref={refs.setFloating} style={floatingStyles}>
    {content}
    <FloatingArrow
      ref={arrowRef}
      context={context}
      width={16}
      height={8}
      tipRadius={2}
    />
  </div>
</FloatingPortal>
```

## 样式建议

### 主体

- 主体圆角、边框、阴影都由气泡自身承担
- 使用 Tailwind 直接控制背景、边框和阴影
- 成功态与失败态应区分视觉层级：成功态只做轻提示，失败态保留完整反馈

### 尾巴

- 直接使用 `FloatingArrow`
- 尾巴颜色与主体底色保持一致
- 边框颜色与主体边框保持一致
- 尺寸建议从 `width=16 / height=8` 起调
- `tipRadius` 可适当增加，让尾巴不要太尖锐

## Storybook 验收方式

需要同时提供两类 Story：

### 1. 状态矩阵

验证：

- success / failure
- default / compact / dense
- 文案密度
- 失败兜底内容

### 2. 尾巴方向验证

验证：

- `top / right / bottom / left`
- 每个方向都必须锚定到真实复制图标
- 不允许用伪静态气泡替代真实组件

## 验收标准

一个“正确的复制反馈气泡”至少满足：

- 只出现一个反馈层，不和 tooltip 叠加
- 成功态和失败态都能稳定显示
- 成功态文案应尽量短，默认只显示“已复制”
- 成功态应弱化视觉层级，不要做成与失败态同等显眼的大气泡
- 失败态能展示手动复制内容
- 尾巴明显指向真实复制图标
- 切换 `top / right / bottom / left` 时，尾巴方向和主体位置一致
- Storybook 中看到的效果与真实页面一致，不依赖伪造示意图

## 本项目结论

对于本项目里的复制反馈气泡：

- 最终应以 `@floating-ui/react` 作为实现基础
- Storybook 必须以真实组件实例作为验收面
- 尾巴是否正确，必须围绕“是否指向真实复制按钮”来判断，而不是只看形状

这套结论适用于后续账号页、邮箱抽屉、Keys 页等所有复制反馈交互。
