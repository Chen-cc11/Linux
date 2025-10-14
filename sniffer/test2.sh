cat > test_sniffer.py << 'EOF'
from scapy.all import *
import sys

def packet_callback(pkt):
    print(f"捕获到数据包: {pkt.summary()}")

def main():
    print("开始抓包...")
    print(f"使用网卡: {sys.argv[1]}")
    sniff(iface=sys.argv[1], prn=packet_callback, count=1)
    print("抓包结束")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("使用方法: python test_sniffer.py <网卡名称>")
        sys.exit(1)
    main()
EOF