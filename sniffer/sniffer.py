from scapy.all import *
from packet import PacketInfo
import time
import threading
import os
import subprocess
import psutil
import socket
import re

class Sniffer:
    def __init__(self):
        self.nif = None
        self.filter = ''
        self.number = 0
        self.time = 0
        self.sniffer = None
        self.is_running = False
        self.packets = []
        self._stop_sniffing = threading.Event()
        self.quiet_mode = False
        self.verbose_mode = False
        self.max_packets = 0
        self.socket_stats = {}
        self.connection_stats = {}

    @staticmethod
    def get_interfaces():
        """获取所有可用的网卡接口"""
        interfaces = []
        try:
            # 使用 get_if_list() 获取所有接口
            interfaces = get_if_list()
        except Exception as e:
            print(f"获取网卡接口列表失败: {e}")
        return interfaces

    def set_interface(self, interface):
        if interface not in self.get_interfaces():
            available_interfaces = self.get_interfaces()
            print(f"错误: 接口 '{interface}' 不存在!")
            print("可用的网卡接口:")
            for iface in available_interfaces:
                print(f"  - {iface}")
            return False
        self.nif = interface
        return True
        
    def set_filter(self, filter_str):
        self.filter = filter_str

    def start(self):
        if not self.nif:
            print("请指定网卡接口")
            return
            
        self.is_running = True
        self._stop_sniffing.clear()
        self.time = time.time()
        print(f"开始在接口 {self.nif} 上抓包...")
        if self.filter:
            print(f"使用过滤器: {self.filter}")
        
        # 使用线程来运行sniff
        self.sniffer = threading.Thread(
            target=self._sniff_packets
        )
        self.sniffer.start()

    def _sniff_packets(self):
        try:
            sniff(
                iface=self.nif,
                prn=self.handle_packet,
                filter=self.filter,
                stop_filter=lambda _: self._stop_sniffing.is_set()
            )
        except Exception as e:
            print(f"抓包出错: {e}")
            self.is_running = False

    def stop(self):
        if self.is_running:
            self._stop_sniffing.set()
            if self.sniffer and self.sniffer.is_alive():
                self.sniffer.join(timeout=2)  # 等待线程结束
            self.is_running = False
            print(f"\n共抓取 {self.number} 个数据包")

    def handle_packet(self, pkt):
        try:
            self.number += 1
            packet_info = self._parse_packet(pkt)
            self.packets.append(packet_info)
            self._print_packet_info(packet_info)
        except Exception as e:
            print(f"处理数据包时出错: {e}")

    def _parse_packet(self, pkt):
        # 解析数据包信息
        raw_data = pkt.show(dump=True)
        hex_info = hexdump(pkt, dump=True)
        current_time = str(time.time() - self.time)[0:9]
        
        src, dst = self._get_addresses(pkt)
        protocol = self._get_protocol(pkt)
        length = len(pkt)
        info = self._get_info(pkt, protocol)
        
        packet_info = PacketInfo()
        try:
            payload = str(bytes(pkt.payload.payload.payload))
        except:
            payload = ''
            
        packet_info.from_args(self.number, current_time, src, dst, 
                            protocol, length, info, raw_data, hex_info, payload)
        return packet_info

    def _print_packet_info(self, packet_info):
        if self.quiet_mode:
            # 安静模式只显示最基本信息
            print(f"{packet_info.number:4d}  {packet_info.protocol:10s}  "
                  f"{packet_info.src:15s} -> {packet_info.dst:15s}")
        else:
            # 正常模式显示完整信息
            print(f"{packet_info.number:4d}  {packet_info.time:9s}  "
                  f"{packet_info.protocol:10s}  {packet_info.src:15s} -> "
                  f"{packet_info.dst:15s}  {packet_info.length:5d}  {packet_info.info}")
            
            # 详细模式显示数据包详情
            if self.verbose_mode:
                print("\n详细信息:")
                for layer, info in packet_info.detail_info.items():
                    print(f"  {layer}:")
                    for key, value in info.items():
                        print(f"    {key}: {value}")
                print()

    def save_packets(self, filename):
        try:
            with open(filename, 'w') as f:
                for packet in self.packets:
                    f.write(str(packet.to_dict()) + '\n')
            print(f"数据包已保存到 {filename}")
        except Exception as e:
            print(f"保存文件时出错: {e}")

    def _get_addresses(self, pkt):
        try:
            if IP in pkt:
                return pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                return pkt[IPv6].src, pkt[IPv6].dst
            elif ARP in pkt:
                return pkt[ARP].psrc, pkt[ARP].pdst
            else:
                return pkt.src, pkt.dst
        except:
            return "unknown", "unknown"

    def _get_protocol(self, pkt):
        try:
            if ARP in pkt:
                return 'ARP'
            elif IP in pkt:
                if TCP in pkt:
                    return 'TCP'
                elif UDP in pkt:
                    return 'UDP'
                elif ICMP in pkt:
                    return 'ICMP'
                else:
                    return 'IP'
            elif IPv6 in pkt:
                if TCP in pkt:
                    return 'IPv6/TCP'
                elif UDP in pkt:
                    return 'IPv6/UDP'
                else:
                    return 'IPv6'
            else:
                return 'OTHER'
        except:
            return 'UNKNOWN'

    def _get_info(self, pkt, protocol):
        try:
            if protocol == 'ARP':
                if pkt[ARP].op == 1:  # who-has
                    return f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"
                else:  # is-at
                    return f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
            elif TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                return f"{sport} -> {dport} [Flags: {flags}]"
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                return f"{sport} -> {dport}"
            elif ICMP in pkt:
                return f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
            else:
                return pkt.summary()
        except:
            return "Unknown packet info"

    def set_quiet_mode(self, quiet):
        self.quiet_mode = quiet

    def set_verbose_mode(self, verbose):
        self.verbose_mode = verbose

    def set_packet_count(self, count):
        self.max_packets = count

    def set_promiscuous_mode(self, interface):
        """启用网卡的混杂模式"""
        try:
            # 首先尝试使用ip命令
            subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'])
            print(f"已启用 {interface} 的混杂模式")
        except Exception as e1:
            try:
                # 如果ip命令失败，尝试使用ifconfig
                subprocess.run(['ifconfig', interface, 'promisc'])
                print(f"已启用 {interface} 的混杂模式")
            except Exception as e2:
                print(f"启用混杂模式失败: {e1}, {e2}")

    def set_monitor_mode(self, interface):
        """启用无线网卡的监控模式"""
        try:
            # 首先尝试使用airmon-ng
            subprocess.run(['airmon-ng', 'start', interface])
            print(f"已启用 {interface} 的监控模式")
        except Exception as e1:
            try:
                # 如果airmon-ng失败，尝试使用iwconfig
                subprocess.run(['iwconfig', interface, 'mode', 'monitor'])
                print(f"已启用 {interface} 的监控模式")
            except Exception as e2:
                print(f"启用监控模式失败: {e1}, {e2}")

    def get_interface_info(self, interface):
        """获取网卡详细信息"""
        info = {}
        try:
            # 使用 conf.iface 获取接口信息
            if interface in conf.ifaces:
                iface = conf.ifaces[interface]
                info['mac'] = iface.mac
                info['ip'] = iface.ip
            else:
                # 备选方案：使用系统命令
                try:
                    # 获取MAC地址
                    mac_output = subprocess.check_output(['ip', 'link', 'show', interface]).decode()
                    mac_match = re.search(r'link/ether ([0-9a-f:]+)', mac_output)
                    if mac_match:
                        info['mac'] = mac_match.group(1)
                    
                    # 获取IP地址
                    ip_output = subprocess.check_output(['ip', 'addr', 'show', interface]).decode()
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ip_output)
                    if ip_match:
                        info['ip'] = ip_match.group(1)
                except:
                    info['mac'] = 'unknown'
                    info['ip'] = 'unknown'
            
            # 获取网卡速率
            try:
                with open(f'/sys/class/net/{interface}/speed', 'r') as f:
                    info['speed'] = f.read().strip()
            except:
                info['speed'] = 'unknown'
                
            # 获取MTU
            try:
                with open(f'/sys/class/net/{interface}/mtu', 'r') as f:
                    info['mtu'] = f.read().strip()
            except:
                info['mtu'] = 'unknown'
                
        except Exception as e:
            print(f"获取网卡信息失败: {e}")
        return info

    def collect_socket_stats(self):
        """收集套接字统计信息"""
        try:
            with open('/proc/net/sockstat', 'r') as f:
                stats = f.read()
            self.socket_stats = self._parse_sockstat(stats)
        except Exception as e:
            print(f"获取套接字统计信息失败: {e}")

    def collect_connection_stats(self):
        """收集网络连接统计信息"""
        try:
            connections = psutil.net_connections()
            stats = {'TCP': {}, 'UDP': {}}
            for conn in connections:
                proto = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                status = conn.status if conn.status else 'NONE'
                stats[proto][status] = stats[proto].get(status, 0) + 1
            self.connection_stats = stats
        except Exception as e:
            print(f"获取连接统计信息失败: {e}")

    def set_pid_filter(self, pid):
        """设置进程ID过滤器"""
        try:
            proc = psutil.Process(pid)
            connections = proc.connections()
            ports = set()
            for conn in connections:
                if conn.laddr:
                    ports.add(str(conn.laddr.port))
            if ports:
                self.filter += f" and port ({' or '.join(ports)})"
        except Exception as e:
            print(f"设置PID过滤器失败: {e}")

    def set_uid_filter(self, uid):
        """设置用户ID过滤器"""
        try:
            # 获取指定UID的所有进程
            processes = [p for p in psutil.process_iter(['uids', 'connections']) 
                        if p.info['uids'].real == uid]
            
            # 收集所有端口
            ports = set()
            for proc in processes:
                try:
                    for conn in proc.connections(kind='inet'):
                        if conn.laddr:  # 本地地址
                            ports.add(str(conn.laddr.port))
                        if conn.raddr:  # 远程地址
                            ports.add(str(conn.raddr.port))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # 如果找到端口，添加到过滤器
            if ports:
                port_filter = " or ".join(f"port {port}" for port in ports)
                if self.filter:
                    self.filter += f" and ({port_filter})"
                else:
                    self.filter = port_filter
                print(f"已添加UID {uid}的端口过滤: {port_filter}")
            else:
                print(f"未找到UID {uid}的活动网络连接")

        except Exception as e:
            print(f"设置UID过滤器失败: {e}")

    def _parse_sockstat(self, stats):
        """解析/proc/net/sockstat的输出"""
        result = {}
        for line in stats.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                result[key.strip()] = {
                    k: int(v) for k, v in re.findall(r'(\w+)\s+(\d+)', value)
                }
        return result
