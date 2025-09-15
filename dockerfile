# 多阶段构建，优化镜像大小
# 阶段1：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制Go源代码文件
COPY main.go .

# 设置Go环境变量
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# 初始化Go模块并构建应用
RUN go mod init wol-service && \
    go mod tidy && \
    go build -a -installsuffix cgo -o wol-service main.go

# 阶段2：运行阶段
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk --no-cache add ca-certificates tzdata

# 设置时区为Asia/Shanghai（适合群晖用户）
RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

# 创建非root用户
RUN addgroup -g 1000 appgroup && \
    adduser -u 1000 -G appgroup -s /bin/sh -D appuser

# 设置工作目录
WORKDIR /app

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /app/wol-service .

# 修改权限
RUN chown -R appuser:appgroup /app && \
    chmod +x wol-service

# 切换到非root用户
USER appuser

# 暴露端口
EXPOSE 52133

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:52133/health || exit 1

# 启动应用
CMD ["./wol-service"]