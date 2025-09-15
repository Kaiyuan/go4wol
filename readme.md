# WOL (Wake-on-LAN) 服务

一个使用Go语言开发的Wake-on-LAN服务，专为群晖NAS的Docker环境设计。该服务可以接收MAC地址并发送WOL魔术包来唤醒网络设备。

## 功能特点

- 🚀 高性能的Go语言实现
- 🐳 Docker容器化部署
- 🌐 RESTful API接口
- 🛡️ 安全的非root用户运行
- 📊 健康检查和监控
- 🌏 支持自定义广播地址和端口
- 📱 CORS支持，便于前端集成

## 快速开始

### Docker Compost
**群晖直接在项目中新增一个项目即可**
```
version: '3.8'

services:
  go4wol:
    build: .
    container_name: go4wol
    restart: unless-stopped
    ports:
      - "52133:52133"
    environment:
      - PORT=52133
      - TZ=Asia/Shanghai
    network_mode: host
    # 给容器特权以发送网络广播包（仅在必要时使用）
    # privileged: true
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.wol.rule=Host(`wol.local`)"
      - "traefik.http.services.wol.loadbalancer.server.port=52133"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

    image: kaiyuan/go4wol:latest
```

### 1. 准备文件

将以下文件保存到同一目录：
- `main.go` - 主程序代码
- `Dockerfile` - Docker构建文件
- `docker-compose.yml` - Docker Compose配置
- `deploy.sh` - 构建和部署脚本

### 2. 构建和部署

```bash
# 给部署脚本添加执行权限
chmod +x deploy.sh

# 构建并部署服务
./deploy.sh deploy

# 或者单独构建
./deploy.sh build
```

### 3. 使用Docker Compose

```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

## API 接口

### 发送WOL包

**端点：** `POST /wol`

**请求体：**
```json
{
    "mac": "AA:BB:CC:DD:EE:FF",        // 必需：目标设备的MAC地址
    "broadcast": "192.168.1.255",      // 可选：广播地址，默认255.255.255.255
    "port": 9                          // 可选：端口号，默认9
}
```

**响应：**
```json
{
    "success": true,
    "message": "WOL packet sent successfully",
    "mac": "AA:BB:CC:DD:EE:FF"
}
```

### 健康检查

**端点：** `GET /health`

**响应：**
```json
{
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z",
    "service": "WOL Service"
}
```

## 使用示例

### cURL 命令

```bash
# 发送WOL包
curl -X POST http://localhost:52133/wol \
  -H 'Content-Type: application/json' \
  -d '{"mac":"AA:BB:CC:DD:EE:FF"}'

# 指定广播地址和端口
curl -X POST http://localhost:52133/wol \
  -H 'Content-Type: application/json' \
  -d '{"mac":"AA:BB:CC:DD:EE:FF","broadcast":"192.168.1.255","port":9}'
```

### JavaScript 示例

```javascript
async function wakeDevice(mac, broadcast = null, port = null) {
    const payload = { mac };
    if (broadcast) payload.broadcast = broadcast;
    if (port) payload.port = port;
    
    const response = await fetch('/wol', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });
    
    const result = await response.json();
    return result;
}

// 使用示例
wakeDevice('AA:BB:CC:DD:EE:FF')
    .then(result => console.log('WOL发送结果:', result))
    .catch(error => console.error('错误:', error));
```

## 群晖NAS部署指南

### 方法1：通过SSH部署

1. 启用群晖的SSH服务
2. 通过SSH连接到群晖
3. 创建项目目录并上传文件
4. 运行部署脚本

```bash
# SSH连接到群晖
ssh admin@your-synology-ip

# 创建项目目录
mkdir -p /volume1/docker/wol-service
cd /volume1/docker/wol-service

# 上传文件后执行部署
chmod +x deploy.sh
./deploy.sh deploy
```

### 方法2：通过Docker图形界面

1. 打开群晖的Docker套件
2. 在镜像选项卡中选择"新增" -> "从文件添加"
3. 上传构建好的Docker镜像
4. 创建容器时设置：
   - 端口映射：本地端口52133 -> 容器端口52133
   - 网络：使用host模式（推荐）
   - 环境变量：PORT=52133, TZ=Asia/Shanghai

### 网络配置注意事项

- **推荐使用host网络模式**：这样可以确保WOL广播包能够正确发送
- 如果必须使用bridge模式，确保Docker网络配置允许广播
- 确保目标设备的网卡支持Wake-on-LAN功能

## 管理命令

```bash
# 查看服务状态
docker ps | grep wol-service

# 查看日志
./deploy.sh logs
# 或者
docker logs -f wol-service

# 重启服务
./deploy.sh restart

# 停止服务
./deploy.sh stop
```

## 故障排除

### 常见问题

1. **WOL包发送失败**
   - 检查目标设备是否支持Wake-on-LAN
   - 确认网络配置和广播地址正确
   - 验证MAC地址格式是否正确

2. **服务无法访问**
   - 检查端口是否被占用
   - 确认防火墙设置
   - 验证Docker容器是否正常运行

3. **权限问题**
   - 确保部署脚本有执行权限
   - 检查Docker是否正常运行

### 调试方法

```bash
# 检查容器状态
docker ps -a | grep wol-service

# 查看详细日志
docker logs wol-service

# 进入容器调试
docker exec -it wol-service sh

# 测试网络连接
curl http://localhost:52133/health
```

## 安全考虑

- 服务以非root用户运行
- 支持CORS，但在生产环境中建议限制来源
- 建议在内网环境中使用
- 可以配置反向代理添加认证

## 性能优化

- 使用多阶段Docker构建减小镜像大小
- Alpine Linux基础镜像提供较小的攻击面
- Go语言提供高性能的并发处理

## 许可证

本项目采用MIT许可证。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 更新日志

- v1.0.0: 初始版本，支持基本的WOL功能
- 支持MAC地址验证和格式化
- 添加健康检查和监控
- 完整的Docker化部署方案