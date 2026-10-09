# NAS 网络动画

地球和网状连接的几何及绘制代码由项目所有者提供的 NasSimHub 本地源码迁移而来：
`web/src/components/networkGlobeGeometry.ts`、`networkGlobePainter.ts`、
`dhtMeshField.ts`、`dhtMeshPainter.ts`。按所有者要求随 NKNGuard 源码发布。
原始 TypeScript 与去除类型后的浏览器 JavaScript 都保留在
`internal/app/dashboard/animations/`。不引入远程脚本或在线地图。

动画只画示意；DHT 节点数来自本机 libp2p 连接和路由表，不是全网规模。
网状图沿用 NasSimHub 的多跳连线、渐隐光尾和到达节点光晕。DHT 启用但暂无节点时，
蓝色流光表示发现过程的示意；有真实连接节点时改为黄色。禁用后停止流光，节点数量始终来自实时状态。
地球上增加连接弧线和流光：绿色表示有直连，黄色表示中继，蓝色虚线表示等待连接。
这些光点的位置、路径和移动速度都是示意，不代表真实地理位置或实时流量。
NKN 地址存在时显示“身份地址已就绪”，
只有观察到可用的 NKN 中继路径才显示“中继可用”。
页面隐藏或切换出总览时停止绘制；最多每秒 20 帧，支持减少动态效果设置。
