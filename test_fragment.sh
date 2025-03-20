#!/bin/bash

# 创建测试目录
TEST_DIR="fragment_test"
mkdir -p "$TEST_DIR"

echo "=== 开始IP分片重组测试 ==="

# 1. 使用tcpdump捕获
echo "启动tcpdump捕获..."
PCAP_FILE="$TEST_DIR/capture.pcap"
rm -f "$PCAP_FILE"

# 使用tcpdump直接捕获
sudo tcpdump -i ens5f0 -w "$PCAP_FILE" -s 0 'icmp' &
TCPDUMP_PID=$!

# 检查tcpdump是否正常启动
sleep 2
if ! ps -p $TCPDUMP_PID > /dev/null; then
    echo "错误: tcpdump未能正常启动"
    exit 1
fi

echo "tcpdump正在运行 (PID: $TCPDUMP_PID)"

# 2. 生成大数据包触发分片
echo "生成分片数据包..."
sudo ping -s 65000 8.8.8.8 -c 3

# 等待捕获完成
sleep 5

# 3. 停止tcpdump
echo "停止tcpdump..."
sudo kill -INT $TCPDUMP_PID
sleep 2

# 检查捕获文件
if [ ! -f "$PCAP_FILE" ]; then
    echo "错误: 未生成捕获文件"
    exit 1
fi

# 检查文件大小
FILE_SIZE=$(ls -l "$PCAP_FILE" | awk '{print $5}')
echo "捕获文件大小: $FILE_SIZE 字节"

# 4. 分析捕获文件
echo -e "\n=== 分片分析结果 ==="
echo "详细分析："
sudo tcpdump -r "$PCAP_FILE" -vvv

# 5. 显示统计信息
echo -e "\n数据包统计："
PACKET_COUNT=$(sudo tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l)
echo "捕获的数据包数量: $PACKET_COUNT"

# 6. 分析分片
echo -e "\n分片分析："
sudo tcpdump -r "$PCAP_FILE" -v 'ip[6:2] & 0x3fff != 0 or ip[6:2] & 0x2000 != 0'

echo "捕获文件保存为: $PCAP_FILE"