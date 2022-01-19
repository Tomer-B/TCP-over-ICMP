from scapy.all import *
import struct
from socket import socket, SOL_SOCKET
import sys; sys.path.append('/home/tomer/.local/lib/python3.8/site-packages') #TODO FIX PATH
from awaits.awaitable import awaitable
from ctypes import create_string_buffer, addressof


def generate_filter_with_tcpdump(filter : str):
    import subprocess
    result = []
    tcpdump_output = subprocess.check_output(["sudo", "tcpdump", "-ddd", filter]).strip()
    opcode_packer = struct.Struct("HBBI")
    for line in tcpdump_output.splitlines()[1:]: # first line is length
        code, k, jt, jf = (int(x) for x in line.strip().split(b' '))
        result.append(opcode_packer.pack(code, k, jt, jf))
    return result


def set_bpf(sock : socket, filter: str):
    filters_list = generate_filter_with_tcpdump(filter)
    filters = b''.join(filters_list)  
    b = create_string_buffer(filters)  
    mem_addr_of_filters = addressof(b)  
    fprog = struct.pack('HL', len(filters_list), mem_addr_of_filters)  
    sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, fprog)


@awaitable
def async_sendto(sock: socket, packet : bytes):
    dst_ip = IP(packet)[IP].dst
    dst_port = IP(packet)[TCP].dport
    final_data = IP(packet)
    final_data[IP].chksum = None
    final_data[TCP].chksum = None
    sock.sendto(final_data.build(), (dst_ip, dst_port))