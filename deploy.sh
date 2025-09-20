#!/bin/bash

# WOL服务构建和部署脚本
# 适用于群晖NAS Docker环境

set -e

echo "=== WOL服务构建和部署脚本 ==="

# 配置变量
SERVICE_NAME="go4wol"
IMAGE_NAME="go4wol:latest"
CONTAINER_NAME="go4wol"
HOST_PORT="52133"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Docker是否运行
check_docker() {
    if ! docker --version > /dev/null 2>&1; then
        log_error "Docker未安装或未运行"
        exit 1
    fi
    log_info "Docker检查通过"
}

# 停止并删除现有容器
cleanup_existing() {
    if docker ps -a --format 'table {{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "停止并删除现有容器: ${CONTAINER_NAME}"
        docker stop ${CONTAINER_NAME} > /dev/null 2>&1 || true
        docker rm ${CONTAINER_NAME} > /dev/null 2>&1 || true
    fi
}

# 删除旧镜像
cleanup_image() {
    if docker images --format 'table {{.Repository}}:{{.Tag}}' | grep -q "^${IMAGE_NAME}$"; then
        log_info "删除旧镜像: ${IMAGE_NAME}"
        docker rmi ${IMAGE_NAME} > /dev/null 2>&1 || true
    fi
}

# 构建Docker镜像
build_image() {
    log_info "构建Docker镜像: ${IMAGE_NAME}"
    
    # 清理构建缓存并强制重新构建
    docker build --no-cache -t ${IMAGE_NAME} .
    
    if [ $? -eq 0 ]; then
        log_info "镜像构建成功"
    else
        log_error "镜像构建失败"
        exit 1
    fi
}

# 运行容器
run_container() {
    log_info "启动容器: ${CONTAINER_NAME}"
    
    # 创建数据目录并设置权限
    mkdir -p ./data
    chmod 755 ./data
    
    # 如果在Linux系统上，设置正确的用户权限
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # 尝试设置与容器内用户相同的权限（UID 1000）
        if command -v chown >/dev/null 2>&1; then
            sudo chown -R 1000:1000 ./data 2>/dev/null || {
                log_warn "无法设置数据目录权限，但这通常不会影响功能"
            }
        fi
    fi
    
    # 使用host网络模式以便发送广播包
    docker run -d \
        --name ${CONTAINER_NAME} \
        --restart unless-stopped \
        --network host \
        -p ${HOST_PORT}:52133 \
        -e PORT=52133 \
        -e ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin123} \
        -e TZ=Asia/Shanghai \
        -v "$(pwd)/data:/data" \
        ${IMAGE_NAME}
    
    if [ $? -eq 0 ]; then
        log_info "容器启动成功"
    else
        log_error "容器启动失败"
        exit 1
    fi
}

# 检查服务状态
check_service() {
    log_info "等待服务启动..."
    sleep 5
    
    # 检查容器状态
    if docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -q "${CONTAINER_NAME}.*Up"; then
        log_info "容器运行正常"
    else
        log_error "容器未正常运行"
        docker logs ${CONTAINER_NAME}
        exit 1
    fi
    
    # 检查服务健康状态
    local max_attempts=10
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s http://localhost:${HOST_PORT}/health > /dev/null 2>&1; then
            log_info "服务健康检查通过"
            break
        else
            log_warn "健康检查失败，尝试 $attempt/$max_attempts"
            sleep 3
            ((attempt++))
        fi
    done
    
    if [ $attempt -gt $max_attempts ]; then
        log_error "服务健康检查失败"
        docker logs ${CONTAINER_NAME}
        exit 1
    fi
}

# 显示服务信息
show_info() {
    log_info "=== 部署完成 ==="
    echo
    echo "服务地址: http://localhost:${HOST_PORT}"
    echo "健康检查: http://localhost:${HOST_PORT}/health"
    echo "PWA前端: http://localhost:${HOST_PORT}/"
    echo
    echo "API使用示例:"
    echo "curl -X POST http://localhost:${HOST_PORT}/wol \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '{\"mac\":\"AA:BB:CC:DD:EE:FF\",\"broadcast\":\"192.168.1.255\",\"port\":9}'"
    echo
    echo "管理密码: \${ADMIN_PASSWORD:-admin123}"
    echo "数据目录: $(pwd)/data"
    echo
    echo "查看日志: docker logs -f ${CONTAINER_NAME}"
    echo "停止服务: docker stop ${CONTAINER_NAME}"
    echo
}

# 主流程
main() {
    case "${1:-deploy}" in
        "build")
            check_docker
            cleanup_existing
            cleanup_image
            build_image
            ;;
        "deploy")
            check_docker
            cleanup_existing
            cleanup_image
            build_image
            run_container
            check_service
            show_info
            ;;
        "stop")
            log_info "停止服务"
            docker stop ${CONTAINER_NAME} > /dev/null 2>&1 || true
            docker rm ${CONTAINER_NAME} > /dev/null 2>&1 || true
            log_info "服务已停止"
            ;;
        "logs")
            docker logs -f ${CONTAINER_NAME}
            ;;
        "restart")
            log_info "重启服务"
            docker restart ${CONTAINER_NAME}
            check_service
            show_info
            ;;
        *)
            echo "用法: $0 [build|deploy|stop|logs|restart]"
            echo "  build   - 只构建镜像"
            echo "  deploy  - 构建并部署服务（默认）"
            echo "  stop    - 停止服务"
            echo "  logs    - 查看日志"
            echo "  restart - 重启服务"
            exit 1
            ;;
    esac
}

# 执行主流程
main "$@"