cat > test.sh << 'EOF'
#!/bin/bash

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
    echo "需要root权限"
    exit 1
fi

# 使用conda环境的python
PYTHON=$(which python)

# 安装必要的包
$PYTHON -m pip install scapy

# 设置权限
setcap cap_net_raw+eip $PYTHON

# 运行测试程序
echo "开始测试..."
$PYTHON test_sniffer.py "$1"
EOF

chmod +x test.sh