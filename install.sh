#!/bin/bash

# Go4WOL 一键安装脚本
# 支持架构: amd64, arm64, armv7

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[信息]${NC} $1"; }
log_success() { echo -e "${GREEN}[成功]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[警告]${NC} $1"; }
log_error() { echo -e "${RED}[错误]${NC} $1"; }

# 检查权限
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 root 权限运行此脚本 (sudo bash install.sh)"
    exit 1
fi

# 检查依赖
check_deps() {
    for cmd in curl jq tar; do
        if ! command -v $cmd &> /dev/null; then
            log_info "正在安装依赖: $cmd..."
            if command -v apt-get &> /dev/null; then
                apt-get update && apt-get install -y $cmd
            elif command -v yum &> /dev/null; then
                yum install -y $cmd
            else
                log_error "未找到软件包管理器，请手动安装 $cmd"
                exit 1
            fi
        fi
    done
}

# 检测架构
detect_arch() {
    local arch=$(uname -m)
    case $arch in
        x86_64)  ARCH="linux_amd64" ;;
        aarch64) ARCH="linux_arm64" ;;
        armv7l)  ARCH="linux_armv7" ;;
        *)
            log_error "不支持的架构: $arch"
            exit 1
            ;;
    esac
    log_info "检测到架构: $arch -> $ARCH"
}

# 获取最新版本
get_latest_release() {
    log_info "正在获取最新版本信息..."
    REPO="Kaiyuan/go4wol"
    local release_info=$(curl -s "https://api.github.com/repos/$REPO/releases/latest")
    VERSION=$(echo "$release_info" | jq -r .tag_name)
    
    if [ "$VERSION" == "null" ] || [ -z "$VERSION" ]; then
        log_error "无法获取最新版本，请稍后再试"
        exit 1
    fi
    log_info "发现最新版本: $VERSION"

    # 构建下载链接
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/go4wol_${ARCH}.tar.gz"
}

# 安装
install_bin() {
    log_info "正在下载: $DOWNLOAD_URL"
    local tmp_dir=$(mktemp -d)
    curl -L "$DOWNLOAD_URL" -o "$tmp_dir/go4wol.tar.gz"
    
    log_info "正在解压并安装..."
    tar -xzf "$tmp_dir/go4wol.tar.gz" -C "$tmp_dir"
    
    # 停止旧服务
    if systemctl is-active --quiet go4wol; then
        log_info "正在停止旧版服务..."
        systemctl stop go4wol
    fi

    mv "$tmp_dir/go4wol" /usr/local/bin/go4wol
    chmod +x /usr/local/bin/go4wol
    rm -rf "$tmp_dir"
    
    log_success "二进制文件已安装至 /usr/local/bin/go4wol"
}

# 配置服务
setup_service() {
    log_info "正在配置 Systemd 服务..."
    
    DATA_DIR="/var/lib/go4wol/data"
    mkdir -p "$DATA_DIR"
    chmod 755 "$DATA_DIR"

    # 获取当前用户输入的管理密码，默认为 admin123
    read -p "请设置管理密码 [默认: admin123]: " ADMIN_PASSWORD
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-admin123}

    cat > /etc/systemd/system/go4wol.service <<EOF
[Unit]
Description=Go4WOL Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/go4wol
Environment="ADMIN_PASSWORD=$ADMIN_PASSWORD"
Environment="PORT=52133"
ExecStart=/usr/local/bin/go4wol
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable go4wol
    systemctl start go4wol
    
    log_success "服务已启动并配置为开机自启"
}

# 运行主流程
main() {
    echo "====================================="
    echo "        Go4WOL 一键安装助手           "
    echo "====================================="
    check_deps
    detect_arch
    get_latest_release
    install_bin
    setup_service
    
    local ip=$(curl -s https://ifconfig.me || echo "localhost")
    echo ""
    log_success "安装完成！"
    echo "-------------------------------------"
    echo "访问地址: http://$ip:52133"
    echo "管理密码: $ADMIN_PASSWORD"
    echo "数据目录: /var/lib/go4wol/data"
    echo "查看日志: journalctl -u go4wol -f"
    echo "-------------------------------------"
}

main
