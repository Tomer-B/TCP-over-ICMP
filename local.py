# This is the code for the limited reosurces local server.

import asyncio
import socket
from scapy.all import *

from consts import MAX_PACKET_SIZE, ETH_P_IP, TYPE_ECHO_REQUEST, LOCAL_ICMP_IP, REMOTE_ICMP_IP, LOCAL_BPF_FILTER
from utils import async_sendto, set_bpf, serialize_data, deserialize_data


class LocalClient:
    def __init__(self):
        self.create_input_tcp_socket() # Input TCP connection from local service user
        self.create_icmp_socket() # Serialize to ICMP and send to Server, Receive reply from Server, De-serialize
        self.create_output_tcp_socket() # Receive tunneled TCP connection from Server
        self._loop = asyncio.get_running_loop()

    def create_input_tcp_socket(self):
        self.input_tcp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        self.input_tcp.bind(('lr2l', 0))
        self.input_tcp.setblocking(False)
        set_bpf(self.input_tcp, LOCAL_BPF_FILTER)

    def create_icmp_socket(self):
        self.icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmp_socket.bind((LOCAL_ICMP_IP, 0))
        self.icmp_socket.connect((REMOTE_ICMP_IP, 0))
        self.icmp_socket.setblocking(False)

    def create_output_tcp_socket(self):
        self.output_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.output_tcp.setblocking(False)

    async def run(self):
        await asyncio.wait([asyncio.create_task(self.tunnel_tcp_to_icmp()), asyncio.create_task(self.tunnel_icmp_to_tcp())])

    async def tunnel_tcp_to_icmp(self):
        while True:
            data = await self._loop.sock_recv(self.input_tcp, MAX_PACKET_SIZE)
            packet = serialize_data(data, TYPE_ECHO_REQUEST)
            await self._loop.sock_sendall(self.icmp_socket, packet)

    async def tunnel_icmp_to_tcp(self):
        while True:
            data = await self._loop.sock_recv(self.icmp_socket, MAX_PACKET_SIZE)
            packet = deserialize_data(data)
            await async_sendto(self.output_tcp, packet)

async def main():
    client = LocalClient()
    await client.run()

if __name__ == '__main__':
    asyncio.run(main())
