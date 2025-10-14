from patterns import *
import re
import json


class PacketInfo:

    def __init__(self):

        self.number = None
        self.time = None
        self.protocol = None
        self.src = None
        self.dst = None
        self.length = None
        self.info = None
        self.detail_info = {}
        self.raw_data = None
        self.hex_info = None
        self.payload = None

    def from_args(self, number, time, src, dst, protocol, length, info, raw_data, hex_info, payload=''):
        self.number = number
        self.time = time
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.length = length
        self.info = info
        self.detail_info = {}
        self.raw_data = raw_data
        self.hex_info = hex_info
        self.payload = payload
        self.get_detail()

    def from_dict(self, packet_dict: dict):
        for key, value in packet_dict.items():
            self.__dict__[key] = value

    def get_detail(self):
        try:
            pattern = r'###\[ (\w+) \]###'
            layers = re.findall(pattern, self.raw_data)
            self.detail_info = self.detail_info.fromkeys(layers)

            for layer in layers:
                if layer == 'Ethernet':
                    self._parse_ethernet()
                elif layer == 'IP':
                    self._parse_ip()
                elif layer == 'IPv6':
                    self._parse_ipv6()
                elif layer == 'TCP':
                    self._parse_tcp()
                elif layer == 'UDP':
                    self._parse_udp()
                elif layer == 'ARP':
                    self._parse_arp()
                elif layer == 'ICMP':
                    self._parse_icmp()
                elif layer == 'Raw':
                    self._parse_raw()
                elif layer == 'Padding':
                    self._parse_padding()
        except Exception as e:
            print(f"解析数据包详情时出错: {e}")

    def _parse_ethernet(self):
        try:
            if match := re.search(ethernet_pattern, self.raw_data):
                self.detail_info['Ethernet'] = {
                    'dst(目的地址)': match.group(1),
                    'src(源地址)': match.group(2),
                    'type(类型)': match.group(3)
                }
        except:
            self.detail_info['Ethernet'] = {}

    def _parse_ip(self):
        try:
            if match := re.search(ip_pattern, self.raw_data):
                attributes = ['version(版本)', 'ihl(报头长度)', 'tos(服务类型)', 'len(总长��)', 
                            'id(标识)', 'flags(分段标志)', 'frag(段偏移)', 'ttl(生存期)', 
                            'proto(协议)', 'chksum(校验和)', 'src(源地址)', 'dst(目的地址)']
                self.detail_info['IP'] = {
                    attr: match.group(i + 1) for i, attr in enumerate(attributes)
                }
        except:
            self.detail_info['IP'] = {}

    def _parse_ipv6(self):
        try:
            if match := re.search(ipv6_pattern, self.raw_data):
                attributes = ['vsersion(版本)', 'tc(流量分类)', 'fl(流标签)', 'plen(有效载荷长度)',
                            'nh(下一个头类型)', 'hlim(最大跳数)', 'src(源地址)', 'dst(目的地址)']
                self.detail_info['IPv6'] = {
                    attr: match.group(i + 1) for i, attr in enumerate(attributes)
                }
        except:
            self.detail_info['IPv6'] = {}

    def _parse_tcp(self):
        try:
            if match := re.search(tcp_pattern, self.raw_data):
                attributes = ['sport(源端口)', 'dport(目的端口)', 'seq(序号)', 'ack(确认号)', 
                            'dataofs(数据偏移)', 'reserved(保留位)', 'flags(标志位)', 
                            'window(窗口大小)', 'chksum(校验和)', 'urgptr(紧急指针)', 'options(选项)']
                self.detail_info['TCP'] = {
                    attr: match.group(i + 1) for i, attr in enumerate(attributes)
                }
        except:
            self.detail_info['TCP'] = {}

    def _parse_udp(self):
        try:
            if match := re.search(udp_pattern, self.raw_data):
                attributes = ['sport(源端口)', 'dport(目的端口)', 'len(长度)', 'chksum(校验和)']
                self.detail_info['UDP'] = {
                    attr: match.group(i + 1) for i, attr in enumerate(attributes)
                }
        except:
            self.detail_info['UDP'] = {}

    def _parse_arp(self):
        try:
            if match := re.search(arp_pattern, self.raw_data):
                attributes = ['hwtype(硬件类型)', 'ptype(协议类型)', 'hwlen(硬件地址长度)', 
                            'plen(协议长度)', 'op(操作类型)', 'hwsrc(源MAC地址)', 
                            'psrc(源IP地址)', 'hwdst(目的MAC地址)', 'pdst(目的IP地址)']
                self.detail_info['ARP'] = {
                    attr: match.group(i + 1) for i, attr in enumerate(attributes)
                }
        except:
            self.detail_info['ARP'] = {}

    def _parse_icmp(self):
        try:
            if match := re.search(icmp_pattern, self.raw_data):
                attributes = ['type(类型)', 'code(代码)', 'chksum(校验和)', 
                            'id(标识)', 'seq(序号)', 'unused(未使用)']
                self.detail_info['ICMP'] = {
                    attr: match.group(i + 1) for i, attr in enumerate(attributes)
                }
        except:
            self.detail_info['ICMP'] = {}

    def _parse_raw(self):
        try:
            if match := re.search(raw_pattern, self.raw_data):
                self.detail_info['Raw'] = {'load': match.group(1)}
            else:
                self.detail_info['Raw'] = {'load': ''}
        except:
            self.detail_info['Raw'] = {'load': ''}

    def _parse_padding(self):
        try:
            if match := re.search(padding_pattern, self.raw_data):
                self.detail_info['Padding'] = {'load': match.group(1)}
            else:
                self.detail_info['Padding'] = {'load': ''}
        except:
            self.detail_info['Padding'] = {'load': ''}

    def to_dict(self):
        return {
            'number': self.number,
            'time': self.time,
            'src': self.src,
            'dst': self.dst,
            'protocol': self.protocol,
            'length': self.length,
            'info': self.info,
            'detail_info': self.detail_info,
            'hex_info': self.hex_info,
            'payload': self.payload
        }
