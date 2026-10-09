# NAS 网络动画

按项目所有者要求，从其 NasSimHub 源码直接迁移两张网络卡片：

- `web/src/components/NetworkGlobeCard.vue`、`DHTMeshCard.vue` 的模板。
- `networkCard.css` 的完整共享样式及两张卡片的画布配色。
- `web/src/i18n/networkCardNotes.ts` 与中文语言包中的标签及底部说明。
- `networkGlobeGeometry.ts`、`networkGlobePainter.ts`、`dhtMeshField.ts`、`dhtMeshPainter.ts` 的原始绘制代码。

原始 TypeScript 与去除类型后的浏览器 JavaScript 都保留在
`internal/app/dashboard/animations/`，按所有者要求随 NKNGuard 源码发布。
没有引入远程脚本、地图或新的动画绘图库。

保留原版的点阵地球、呼吸光晕、标记脉冲、漂移网格与黄色多跳信号。
画布尺寸、密度、旋转速度、色彩和卡片间距沿用原组件。
移除了后加的地球弧线、绿色流光和孤立状态下的蓝色流光。

只将 Vue 数据绑定适配为 NKNGuard 的状态事件：活跃数使用既有 NKN 匿名订阅统计；
DHT 连接与路由数使用本机状态。接口未提供的数字显示原版的 `—`，不编造计数。
黄色信号只在 DHT 有真实连接节点时展示。所有动画路径仍是示意，不表示真实地理位置或流量。
隐藏页面、滚出可视区域或切换出总览时暂停绘制，支持系统减少动态效果设置。

NKN 徽章和地球标记读取后台的 `nkn_connected`，不再以身份地址是否存在作为连接依据。
NAS 每 30 秒通过现有 NKN MultiClient 发送一个带随机数的加密自检消息给自身，
只有来源、随机数及有效期均匹配的返回消息才能确认连接；12 秒未返回时显示重新连接中。
状态、最近成功时间和往返耗时只放在内存，不额外写盘或提交链上交易。
