import sys
import argparse
import time
import os
from sniffer import Sniffer

def check_environment():
    """检查运行环境"""
    # 检查root权限
    if os.geteuid() != 0:
        print("错误: 需要root权限才能运行此程序")
        print("请使用 sudo 运行此程序")
        sys.exit(1)
    
    # 检查必要的系统工具
    required_tools = ['ip', 'sysctl']  # 移除 airmon-ng，因为它是可选的
    for tool in required_tools:
        if not any(os.path.exists(os.path.join(path, tool)) 
                  for path in os.environ["PATH"].split(os.pathsep)):
            print(f"警告: 未找到 {tool} 工具，某些功能可能无法使用")

    # 检查可选的系统工具
    optional_tools = ['airmon-ng', 'iwconfig', 'ifconfig']
    available_tools = []
    for tool in optional_tools:
        if any(os.path.exists(os.path.join(path, tool)) 
              for path in os.environ["PATH"].split(os.pathsep)):
            available_tools.append(tool)
    
    if not available_tools:
        print("警告: 未找到无线网卡管理工具，监控模式功能将不可用")

    # 检查必要的Python包
    try:
        import scapy
        import psutil
    except ImportError as e:
        print(f"错误: 缺少必要的Python包: {e}")
        print("请安装所需的包:")
        print("pip install scapy psutil")
        sys.exit(1)

def check_monitor_mode_support():
    """检查是否支持监控模式"""
    tools = []
    for tool in ['iwconfig', 'airmon-ng', 'iw']:
        if any(os.path.exists(os.path.join(path, tool)) 
               for path in os.environ["PATH"].split(os.pathsep)):
            tools.append(tool)
    return tools

def main():
    check_environment()  # 添加环境检查
    
    parser = argparse.ArgumentParser(description='Linux网络嗅探工具')
    
    # 基本选项
    parser.add_argument('-i', '--interface', help='指定网卡接口')
    parser.add_argument('-l', '--list', action='store_true', help='列出所有可用网卡接口')
    
    # Linux特有的网络选项
    parser.add_argument('--promiscuous', action='store_true', help='启用混杂模式')
    parser.add_argument('--monitor', action='store_true', help='启用监控模式(仅对无线网卡有效)')
    parser.add_argument('--no-arp', action='store_true', help='禁用ARP解析')
    parser.add_argument('--vlan', type=int, help='捕获特定VLAN ID的数据包')
    
    # 过滤选项
    parser.add_argument('-f', '--filter', help='设置BPF过滤规则')
    parser.add_argument('-p', '--protocol', 
                       choices=['tcp', 'udp', 'icmp', 'arp', 'ip6', 'raw'], 
                       help='只捕获指定协议的数据包')
    parser.add_argument('--port', type=int, help='只捕获指定端口的数据包')
    parser.add_argument('--src', help='只捕获指定源IP的数据包')
    parser.add_argument('--dst', help='只捕获指定目标IP的数据包')
    
    # Linux系统特有的过滤选项
    parser.add_argument('--pid', type=int, help='捕获指定进程ID的网络流量')
    parser.add_argument('--uid', type=int, help='捕获指定用户ID的网络流量')
    parser.add_argument('--tcp-state', choices=['ESTABLISHED', 'SYN-SENT', 'SYN-RECV',
                                              'FIN-WAIT-1', 'FIN-WAIT-2', 'TIME-WAIT',
                                              'CLOSED', 'CLOSE-WAIT', 'LAST-ACK',
                                              'LISTEN', 'CLOSING'],
                       help='只捕获特定TCP状态的连接')
    
    # 输出选项
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--pcap', help='将捕获的数据包保存为pcap格式')
    parser.add_argument('-c', '--count', type=int, help='限制捕获的数据包数量')
    parser.add_argument('-t', '--time', type=int, help='抓包时间(秒)')
    parser.add_argument('-q', '--quiet', action='store_true', help='安静模式，只显示基本信息')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细模式，显示数据包详情')
    
    # Linux系统监控选项
    parser.add_argument('--stats', action='store_true', help='显示网络统计信息')
    parser.add_argument('--netstat', action='store_true', help='显示类似netstat的连接信息')
    parser.add_argument('--socket-stats', action='store_true', help='显示套接字统计信息')
    
    args = parser.parse_args()
    
    # 如果要使用监控模式，先检查支持
    if args.monitor:
        tools = check_monitor_mode_support()
        if not tools:
            print("错误: 未找到支持监控模式的工具")
            print("请安装以下工具之一:")
            print("  - aircrack-ng (apt install aircrack-ng)")
            print("  - wireless-tools (apt install wireless-tools)")
            print("  - iw (apt install iw)")
            return
        print(f"找到支持监控模式的工具: {', '.join(tools)}")

    sniffer = Sniffer()

    # 如果使用 -l 参数，列出所有接口后退出
    if args.list:
        print("可用的网卡接口:")
        for iface in sniffer.get_interfaces():
            print(f"  - {iface}")
        return

    # 检查是否指定了网卡接口
    if not args.interface:
        print("错误: 请指定网卡接口 (-i 参数)")
        print("使用 -l 参数查看所有可用接口")
        return
    
    # 设置网卡接口
    if not sniffer.set_interface(args.interface):
        return

    # 构建过滤器
    filter_parts = []
    if args.filter:
        filter_parts.append(f"({args.filter})")
    if args.protocol:
        filter_parts.append(args.protocol)
    if args.port:
        filter_parts.append(f"port {args.port}")
    if args.src:
        filter_parts.append(f"src host {args.src}")
    if args.dst:
        filter_parts.append(f"dst host {args.dst}")
    
    if filter_parts:
        sniffer.set_filter(" and ".join(filter_parts))
    
    # 设置输出选项
    sniffer.set_quiet_mode(args.quiet)
    sniffer.set_verbose_mode(args.verbose)
    if args.count:
        sniffer.set_packet_count(args.count)
        
    # 设置Linux特有的选项
    if args.promiscuous:
        sniffer.set_promiscuous_mode(args.interface)
    if args.monitor:
        sniffer.set_monitor_mode(args.interface)
    if args.vlan:
        sniffer.set_vlan_filter(args.vlan)
    if args.pid:
        sniffer.set_pid_filter(args.pid)
    if args.uid:
        sniffer.set_uid_filter(args.uid)
    if args.tcp_state:
        sniffer.set_tcp_state_filter(args.tcp_state)
    
    try:
        sniffer.start()
        if args.time:
            time.sleep(args.time)
        elif args.count:
            while sniffer.is_running and sniffer.number < args.count:
                time.sleep(0.1)
        else:
            input("按回车停止抓包...")
    except KeyboardInterrupt:
        print("\n停止抓包...")
    finally:
        sniffer.stop()
        if args.output:
            sniffer.save_packets(args.output)

if __name__ == '__main__':
    main()
