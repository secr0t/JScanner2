# 直接使用 Playwright 官方提供的 Python 3.11 镜像（基于长期支持、完美适配的 Ubuntu 环境）
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# 替换为阿里云镜像源 (Ubuntu Jammy 适用)
RUN sed -i 's|archive.ubuntu.com|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null; \
    sed -i 's|security.ubuntu.com|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null; \
    true

# 安装基础系统依赖：curl(飞书通知)
# 注意：官方镜像已经内置了完美的 CJK 中文字体、Chromium 以及底层全套依赖，无需再手动安装字体和浏览器依赖
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 通过 NodeSource 安装 Node.js（官方镜像带了 node，但为了确保符合你要求的 setup_20.x，这里依然保留你的覆盖安装逻辑）
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# 安装 prettier
RUN npm install -g prettier

WORKDIR /app

# 先复制依赖文件，利用 Docker 缓存层
COPY requirements.txt .
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ \
    && pip config set global.trusted-host mirrors.aliyun.com \
    && pip install --no-cache-dir -r requirements.txt

# 因为基础镜像里已经自带了 Chromium 浏览器，但为了确保 python 层的 playwright 能够正确驱动并对齐版本：
RUN playwright install chromium

# 复制项目代码
COPY . .

# 创建必要目录
RUN mkdir -p Result Overflow_Queue logs

# 默认入口：留空，由 docker-compose / 命令行指定
ENTRYPOINT []
CMD []

# Agent MCP Server 入口（可选）：
# docker run jscanner2 python agent/mcp_server.py
# docker run jscanner2 python agent/mcp_server.py --transport http --port 9000
