Go4WOL - Wake-on-LAN PWA服务
一个功能强大的Wake-on-LAN服务，带有现代化的PWA前端界面，专为群晖NAS的Docker环境设计。

✨ 功能特点
🚀 高性能Go语言实现 - 快速稳定的后端服务
📱 PWA前端界面 - 支持离线使用，可安装到桌面/手机
🔐 密码认证保护 - 登录状态永久保存在设备
💾 SQLite数据库 - 持久化存储设备信息
🖥️ 设备管理 - 添加、删除、管理多个设备
🌐 一键唤醒 - 点击设备即可快速发送WOL包
🐳 Docker容器化 - 简单易部署
🛡️ 安全设计 - 非root用户运行
📊 健康监控 - 内置健康检查
🌏 CORS支持 - 便于前端集成
🎯 界面预览
登录界面：密码保护，一次登录长期有效
设备管理：直观的设备卡片展示
一键唤醒：点击设备卡片或唤醒按钮
设备添加：模态框快速添加新设备
响应式设计：支持手机、平板、桌面
🚀 快速开始
1. 准备文件
创建项目目录并保存以下文件：

bash
mkdir go4wol && cd go4wol
# 保存 main.go, Dockerfile, docker-compose.yml, deploy.sh
2. 设置管理密码
bash
# 设置环境变量（推荐）
export ADMIN_PASSWORD="your_secure_password"

# 或者修改 docker-compose.yml 中的密码
3. 一键部署
bash
# 给部署脚本添加执行权限
chmod +x deploy.sh

# 构建并部署服务
./deploy.sh deploy
4. 访问服务
打开浏览器访问：http://your-server-ip:52133

📋 API接口
原有WOL API（保持不变）
发送WOL包： POST /wol

json
{
    "mac": "AA:BB:CC:DD:EE:FF",
    "broadcast": "192.168.1.255",
    "port": 9
}
新增管理API
用户登录： POST /api/login

json
{
    "password": "your_password"
}
获取设备列表： GET /api/devices

bash
curl -H "Authorization: Bearer your_token" http://localhost:52133/api/devices
添加设备： POST /api/devices

json
{
    "name": "办公电脑",
    "mac": "AA:BB:CC:DD:EE:FF",
    "broadcast": "192.168.1.255",
    "port": 9,
    "description": "我的办公电脑"
}
删除设备： DELETE /api/devices?id=1

🐳 部署方式
方式1：Docker Compose（推荐）
bash
# 修改 docker-compose.yml 中的密码
ADMIN_PASSWORD=your_secure_password

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f go4wol
方式2：部署脚本
bash
# 设置密码并部署
ADMIN_PASSWORD=your_secure_password ./deploy.sh deploy

# 其他管理命令
./deploy.sh stop     # 停止服务
./deploy.sh restart  # 重启服务
./deploy.sh logs     # 查看日志
方式3：手动Docker命令
bash
# 创建数据目录
mkdir -p ./data

# 运行容器
docker run -d \
  --name go4wol \
  --restart unless-stopped \
  --network host \
  -e PORT=52133 \
  -e ADMIN_PASSWORD=your_secure_password \
  -e TZ=Asia/Shanghai \
  -v "$(pwd)/data:/data" \
  -p 52133:52133 \
  go4wol:latest
🏠 群晖NAS部署
通过Docker套件
构建镜像：
bash
   # SSH到群晖，上传文件到项目目录
   cd /volume1/docker/go4wol
   docker build -t go4wol:latest .
创建容器：
镜像：选择刚构建的 go4wol:latest
容器名称：go4wol
网络：使用与Docker Host相同的网络
端口设置：本地端口52133 -> 容器端口52133
环境变量：
PORT=52133
ADMIN_PASSWORD=your_secure_password
TZ=Asia/Shanghai
存储空间：挂载文件夹 /data 到宿主机路径
通过SSH部署
bash
# SSH连接到群晖
ssh admin@your-synology-ip

# 创建项目目录
mkdir -p /volume1/docker/go4wol
cd /volume1/docker/go4wol

# 上传文件并部署
chmod +x deploy.sh
ADMIN_PASSWORD=your_secure_password ./deploy.sh deploy
💾 数据管理
数据库位置
容器内路径：/data/devices.db
宿主机路径：./data/devices.db
备份数据
bash
# 备份数据库
cp ./data/devices.db ./data/devices_backup_$(date +%Y%m%d).db

# 恢复数据（停止容器后）
docker stop go4wol
cp ./data/devices_backup_20240101.db ./data/devices.db
docker start go4wol
数据库结构
sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mac TEXT NOT NULL UNIQUE,
    broadcast TEXT DEFAULT '255.255.255.255',
    port INTEGER DEFAULT 9,
    description TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
🔧 配置选项
环境变量
变量	默认值	说明
PORT	52133	服务监听端口
ADMIN_PASSWORD	admin123	管理员密码
TZ	Asia/Shanghai	时区设置
网络配置
推荐：使用host网络模式确保WOL广播包正常发送
备选：bridge模式（可能需要特权模式）
📱 PWA功能
安装到桌面/手机
使用Chrome/Edge/Safari打开服务地址
点击地址栏的"安装"图标
确认安装PWA应用
现在可以像原生应用一样使用
离线功能
界面支持离线访问
设备列表缓存在本地
登录状态持久保存
🛠️ 故障排除
常见问题
WOL包发送失败
bash
   # 检查网络模式
   docker inspect go4wol | grep NetworkMode
   
   # 确认目标设备支持WOL
   # 检查BIOS/UEFI设置
   # 确认网卡驱动支持WOL
无法访问前端页面
bash
   # 检查服务状态
   docker logs go4wol
   
   # 检查端口占用
   netstat -tlnp | grep 52133
   
   # 检查防火墙设置
数据库错误
bash
   # 检查数据目录权限
   ls -la ./data/
   
   # 重新创建数据库
   rm ./data/devices.db
   docker restart go4wol
登录问题
bash
   # 检查密码设置
   docker exec go4wol printenv ADMIN_PASSWORD
   
   # 清除浏览器存储
   # 开发者工具 > Application > Local Storage > 清除
调试命令
bash
# 查看容器状态
docker ps -a | grep go4wol

# 查看详细日志
docker logs -f go4wol

# 进入容器调试
docker exec -it go4wol sh

# 测试API
curl http://localhost:52133/health
curl -X POST http://localhost:52133/wol \
  -H 'Content-Type: application/json' \
  -d '{"mac":"AA:BB:CC:DD:EE:FF"}'
🔒 安全建议
设置强密码：ADMIN_PASSWORD=Complex_Password_123!
仅在内网环境中使用
定期备份设备数据库
如需外网访问，建议配置反向代理和SSL
🎯 使用场景
家庭网络：管理家里的台式机、服务器、NAS
办公环境：远程唤醒工作电脑、服务器
实验室：管理多台测试设备
网络管理：批量设备管理和唤醒
🚀 性能特点
启动速度：< 1秒启动时间
内存占用：< 20MB运行时内存
并发处理：支持多用户同时操作
数据库性能：SQLite提供快速查询
📄 更新日志
v2.0.0 (Current)
✅ 添加PWA前端界面
✅ 集成用户认证系统
✅ SQLite数据库存储
✅ 设备管理功能
✅ 端口改为52133
✅ 项目重命名为Go4WOL
v1.0.0
✅ 基础WOL API功能
✅ Docker容器化
✅ 健康检查
📝 许可证
本项目采用MIT许可证。

🤝 贡献
欢迎提交Issue和Pull Request来改进这个项目！

Go4WOL - 让设备唤醒变得简单高效！ 🚀

