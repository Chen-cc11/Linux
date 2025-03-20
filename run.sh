cat > run.sh << 'EOF'
#!/bin/bash

# 启用调试模式和错误追踪
set -x
set -e

# 将所有输出重定向到日志文件
exec 1> >(tee -a debug.log)
exec 2>&1

echo "=== 开始执行 $(date) ==="

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then 
    echo "请使用root权限运行此程序"
    exit 1
fi

# 使用当前conda环境的Python
echo "正在查找Python解释器..."
PYTHON=$(which python)
echo "找到Python路径: $PYTHON"

# 显示Python版本和环境信息
echo "Python版本和环境信息:"
$PYTHON --version
echo "PYTHONPATH=$PYTHONPATH"
echo "CONDA_PREFIX=$CONDA_PREFIX"

# 显示当前工作目录和文件
echo "当前目录和文件列表:"
pwd
ls -la

# 检查所有必需的Python文件
for file in main.py sniffer.py packet.py; do
    if [ ! -f "$file" ]; then
        echo "错误: 找不到 $file"
        exit 1
    fi
    echo "找到文件: $file"
done

# 检查Python包
echo "检查Python包..."
$PYTHON << 'END'
import sys
print("Python路径:", sys.path)
print("\n尝试导入必要的包:")
try:
    import scapy
    print("scapy 已导入，版本:", scapy.__version__)
except Exception as e:
    print("导入scapy失败:", e)
    sys.exit(1)

try:
    import psutil
    print("psutil 已导入，版本:", psutil.__version__)
except Exception as e:
    print("导入psutil失败:", e)
    sys.exit(1)
END

# 检查网卡
echo "检查网络接口..."
ip link show
if ! ip link show "$2" >/dev/null 2>&1; then
    echo "警告: 找不到网卡 $2"
    echo "可用的网卡:"
    ip link show
fi

# 设置Python权限
echo "设置Python权限..."
setcap cap_net_raw+eip $PYTHON

# 运行程序
echo "=== 启动网络嗅探器 ==="
echo "完整命令: $PYTHON main.py $@"
echo "参数: $@"

# 使用strace追踪程序执行
echo "使用strace追踪程序执行..."
strace -f $PYTHON main.py "$@"

echo "=== 执行结束 $(date) ==="
EOF

chmod +x run.sh