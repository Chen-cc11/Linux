#!/bin/bash

# CPU核数：通过计算 /proc/cpuinfo 中 "processor" 开头的行数来得到
cpu_num=$(grep -c '^processor' /proc/cpuinfo)

# 内存信息
memory_total=$(free -g | awk '/^Mem:/ {print $2}') # 总内存（GB）
memory_free=$(free -m | awk '/^Mem:/ {print $4}') # 可用内存（MB）

# 磁盘信息
disk_size=$(df -h / | awk '/\// {print $2}')

# 系统架构
system_bit=$(getconf LONG_BIT)

# 进程信息
process=$(ps -ef | wc -l)

# 软件包数量
software_num=$(dpkg-query -f '${binary:Package}\n' -W | wc -l)

# IP地址
ip=$(ip addr show eth0 | awk '/inet / {print $2}' | sed 's|/.*||')

echo "cpu num: $cpu_num"
echo "memory total: $memory_total G"
echo "memory free: $memory_free M"
echo "disk size: $disk_size"
echo "system bit: $system_bit"
echo "process: $((process - 1))"
echo "software num: $software_num"
echo "ip: $ip"