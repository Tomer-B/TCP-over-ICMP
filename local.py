# This is the code for the limited reosurces local server.

import asyncio
import socket
# from socket import socket, htons, gethostbyname, gethostname, AF_INET, SOCK_RAW, IPPROTO_ICMP, AF_PACKET, IPPROTO_TCP, IPPROTO_RAW, SOCK_STREAM, IPPROTO_IP, IP_HDRINCL
from scapy.all import *

from consts import MAX_PACKET_SIZE, ETH_P_IP, TYPE_ECHO_REQUEST, LOCAL_ICMP_IP, REMOTE_ICMP_IP, LOCAL_SRC_IP
from utils import async_sendto, set_bpf


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
        set_bpf(self.input_tcp, "tcp and src host {}".format(LOCAL_SRC_IP))

    def create_icmp_socket(self):
        self.icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmp_socket.bind((LOCAL_ICMP_IP, 0))
        self.icmp_socket.connect((REMOTE_ICMP_IP, 0))
        self.icmp_socket.setblocking(False)

    def create_output_tcp_socket(self):
        self.output_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.output_tcp.setblocking(False)

    def serialize_data_over_icmp(self, data : bytes) -> bytes:
        # print('LOCAL (TCP->ICMP): Payload should be: {}'.format(bytes(Ether(data)[IP])))
        # dummy_bytes = bytes(1) * 8 #TODO: fix? Scapy uses first 8 bytes of payload as ICMP.unused
        # return dummy_bytes + bytes(Ether(data)[IP])
        return bytes(Ether(data)[IP])

    def deserialize_data_over_icmp(self, data : bytes) -> bytes:
        # import pdb; pdb.set_trace()
        return bytes(IP(data)[ICMP])

    async def run(self):
        await asyncio.wait([asyncio.create_task(self.tunnel_tcp_to_icmp()), asyncio.create_task(self.tunnel_icmp_to_tcp())])

    async def tunnel_tcp_to_icmp(self):
        while True:
            print('LOCAL (TCP->ICMP):')
            data = await self._loop.sock_recv(self.input_tcp, MAX_PACKET_SIZE)
            print('LOCAL (TCP->ICMP): Got Data: {}'.format(data))
            # import pdb; pdb.set_trace()
            packet = self.serialize_data_over_icmp(data)
            print('LOCAL (TCP->ICMP): Serialized: {}'.format(packet))
            await self._loop.sock_sendall(self.icmp_socket, packet)
            print('LOCAL (TCP->ICMP): Sent')

    async def tunnel_icmp_to_tcp(self):
        while True:
            print('LOCAL (ICMP->TCP):')
            data = await self._loop.sock_recv(self.icmp_socket, MAX_PACKET_SIZE)
            print('LOCAL (ICMP->TCP): Got Data: {}'.format(data))            
            # import pdb; pdb.set_trace()
            packet = self.deserialize_data_over_icmp(data)
            print('LOCAL (TCP->ICMP): De-Serialized: {}'.format(packet))
            await async_sendto(self.output_tcp, packet)
            print('LOCAL (TCP->ICMP): Sent')

async def main():
    client = LocalClient()
    await client.run()

if __name__ == '__main__':
    asyncio.run(main())
