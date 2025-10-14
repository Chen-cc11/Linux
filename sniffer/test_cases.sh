cat > test_cases.sh << 'EOF'
#!/bin/bash

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
    echo "请使用sudo运行此脚本"
    exit 1
fi

# 创建测试结果目录
TEST_DIR="test_results"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# 定义清理函数
cleanup() {
    echo "清理进程..."
    pkill -f "python.*main.py" || true
    sleep 1
}

# 注册清理函数
trap cleanup EXIT

# 定义测试函数
run_test() {
    local test_name="$1"
    local command="$2"
    local action="$3"
    local log_file="$TEST_DIR/${test_name}.log"
    
    echo "=== 测试: $test_name ==="
    echo "命令: $command"
    echo "开始时间: $(date)" | tee -a "$log_file"
    
    # 启动嗅探器
    eval "$command" > "$log_file" 2>&1 &
    local sniffer_pid=$!
    sleep 2
    
    # 执行测试动作
    echo "执行测试动作..." | tee -a "$log_file"
    eval "$action" >> "$log_file" 2>&1
    sleep 2
    
    # 终止嗅探器
    kill $sniffer_pid 2>/dev/null || true
    wait $sniffer_pid 2>/dev/null || true
    
    echo "结束时间: $(date)" | tee -a "$log_file"
    echo "测试完成，结果保存在: $log_file"
    echo
}

echo "=== 开始功能测试 $(date) ==="

# 1. ICMP测试
run_test "icmp" \
    "python main.py -i ens5f0 -p icmp" \
    "ping -c 3 8.8.8.8"

# 2. TCP测试
run_test "tcp" \
    "python main.py -i ens5f0 -p tcp --port 80" \
    "curl -s http://example.com > /dev/null"

# 3. UDP测试
run_test "udp" \
    "python main.py -i ens5f0 -p udp --port 53" \
    "dig @8.8.8.8 example.com"

# 4. 端口过滤测试
run_test "port_filter" \
    "python main.py -i ens5f0 --port 443" \
    "curl -sk https://example.com > /dev/null"

# 5. 用户ID过滤测试
run_test "uid_filter" \
    "python main.py -i ens5f0 --uid 1000" \
    "sleep 3"

# 显示测试结果摘要
echo "=== 测试结果摘要 ==="
for log in "$TEST_DIR"/*.log; do
    echo "=== $(basename "$log") ==="
    echo "前10行输出:"
    head -n 10 "$log"
    echo "..."
    echo
done

echo "=== 测试完成 $(date) ==="
echo "详细测试结果保存在 $TEST_DIR 目录"
EOF

chmod +x test_cases.sh