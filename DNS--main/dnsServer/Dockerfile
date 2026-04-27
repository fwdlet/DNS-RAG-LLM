# 使用官方Go镜像构建
FROM golang:1.23.6-alpine AS builder
WORKDIR /app
COPY . .
ENV GOPROXY=https://goproxy.cn,direct
RUN go build -o dnsServer main.go

# 运行阶段
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/dnsServer .
COPY front ./front
COPY server.crt server.key ./
COPY jwt_secret.key ./
COPY config.yaml ./
EXPOSE 8443
CMD ["./dnsServer"]
