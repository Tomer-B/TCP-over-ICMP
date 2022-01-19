# This is the code for the unlimited reosurces remote client.

import asyncio
import socket
from scapy.all import *

from consts import MAX_PACKET_SIZE, ETH_P_IP, LOCAL_ICMP_IP, REMOTE_ICMP_IP, TYPE_ECHO_REPLY, REMOTE_BPF_FILTER
from utils import async_sendto, set_bpf, serialize_data, deserialize_data


class RemoteServer:
    def __init__(self):
        self.create_icmp_socket() # De-serialize ICMP
        self.create_output_tcp_socket() # Send TCP connection to service
        self.create_input_tcp_socket() # Sniff reply, and back to ICMP.
        self._loop = asyncio.get_running_loop()
    
    def create_icmp_socket(self):
        self.icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmp_socket.bind((REMOTE_ICMP_IP, 0))
        self.icmp_socket.connect((LOCAL_ICMP_IP, 0))
        self.icmp_socket.setblocking(False)

    def create_output_tcp_socket(self):
        self.output_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.output_tcp.setblocking(False)

    def create_input_tcp_socket(self):
        self.input_tcp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        self.input_tcp.bind(('rl2r', 0))
        self.input_tcp.setblocking(False)
        set_bpf(self.input_tcp, REMOTE_BPF_FILTER)

    def serialize_data_over_icmp(self, data : bytes) -> bytes:
        return bytes(ICMP(seq=1, id=1, type=TYPE_ECHO_REPLY)) + bytes(Ether(data)[IP])

    def deserialize_data_over_icmp(self, data : bytes) -> bytes:
        return bytes(IP(data)[Raw])

    async def run(self):
        await asyncio.wait([asyncio.create_task(self.tunnel_icmp_to_tcp()), asyncio.create_task(self.tunnel_tcp_to_icmp())])

    async def tunnel_icmp_to_tcp(self):
        while True:
            data = await self._loop.sock_recv(self.icmp_socket, MAX_PACKET_SIZE)
            packet = deserialize_data(data)
            await async_sendto(self.output_tcp, packet)

    async def tunnel_tcp_to_icmp(self):
        while True:
            data = await self._loop.sock_recv(self.input_tcp, MAX_PACKET_SIZE)
            packet = serialize_data(data, TYPE_ECHO_REPLY)
            await self._loop.sock_sendall(self.icmp_socket, packet)
        

async def main():
    server = RemoteServer()
    await server.run()

if __name__ == '__main__':
    asyncio.run(main())
