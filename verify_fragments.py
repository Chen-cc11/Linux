#!/usr/bin/env python3
from scapy.all import *

def analyze_fragments(pcap_file):
    """分析pcap文件中的IP分片"""
    print("分析IP分片...")
    
    # 读取pcap文件
    packets = rdpcap(pcap_file)
    
    # 统计分片信息
    fragments = {}
    for pkt in packets:
        if IP in pkt and pkt[IP].flags == 1 or pkt[IP].frag > 0:
            ip_id = pkt[IP].id
            if ip_id not in fragments:
                fragments[ip_id] = []
            fragments[ip_id].append(pkt)
    
    # 分析每组分片
    for ip_id, frags in fragments.items():
        print(f"\n分片组 ID: {ip_id}")
        print(f"分片数量: {len(frags)}")
        
        # 计算原始数据包大小
        total_size = sum(len(f[IP].payload) for f in frags)
        print(f"重组后大小: {total_size} 字节")
        
        # 验证分片完整性
        offsets = sorted(f[IP].frag for f in frags)
        print(f"分片偏移: {offsets}")
        
        # 检查是否有最后一个分片（MF=0）
        has_last = any(f[IP].flags == 0 for f in frags)
        print(f"包含最后分片: {'是' if has_last else '否'}")

if __name__ == "__main__":
    analyze_fragments("fragment_test/fragments.pcap") 