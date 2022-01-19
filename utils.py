from scapy.all import *
import struct
from socket import socket, SOL_SOCKET
import sys; sys.path.append('/home/tomer/.local/lib/python3.8/site-packages') #TODO FIX PATH
from awaits.awaitable import awaitable
from ctypes import create_string_buffer, addressof


def _generate_filter_with_tcpdump(filter : str) -> list:
    """
    Uses tcpdump as a helper binary to generate the bpf opcodes
    Private function, and should not be used on it's own.

    Parameters
    ----------
    filter : str
        filter string, like "arp" or "udp and src host 1.1.1.1"

    Returns
    -------
    list
        A list of the bpf opcodes

    """
    import subprocess
    result = []
    tcpdump_output = subprocess.check_output(["tcpdump", "-ddd", filter]).strip()
    opcode_packer = struct.Struct("HBBI")
    for line in tcpdump_output.splitlines()[1:]: # first line is length
        code, k, jt, jf = (int(x) for x in line.strip().split(b' '))
        result.append(opcode_packer.pack(code, k, jt, jf))
    return result


def set_bpf(sock : socket, filter: str) -> None:
    """
    Sets a socket's bpf using setsockopt

    Parameters
    ----------
    filter : str
        filter string, like "arp" or "udp and src host 1.1.1.1"
    sock : socket
        a socket.socket object
    """
    filters_list = _generate_filter_with_tcpdump(filter)
    filters = b''.join(filters_list)  
    b = create_string_buffer(filters)  
    mem_addr_of_filters = addressof(b)  
    fprog = struct.pack('HL', len(filters_list), mem_addr_of_filters)  
    sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, fprog)


@awaitable
def async_sendto(sock: socket, packet : bytes) -> None:
    """
    asyncio has a built in `socket.send` function, but no `socket.sendto`, needed by the Tunneler.
    This is an awaitable (Async) function that wraps socket.sendto
    The function Uses the packet bytes to get  the Destination IP & Port needed by the sendto function,
    and also Nullifies the checksum to make sure It is re-calculated

    Parameters
    ----------
    sock : socket
        a socket.socket object
    packet : bytes
        the bytes to send
    """
    dst_ip = IP(packet)[IP].dst
    dst_port = IP(packet)[TCP].dport
    final_data = IP(packet)
    final_data[IP].chksum = None
    final_data[TCP].chksum = None
    sock.sendto(final_data.build(), (dst_ip, dst_port))
