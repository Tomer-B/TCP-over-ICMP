# This is the code for the unlimited reosurces remote client.

import asyncio
# from socket import socket, htons, gethostbyname, gethostname, AF_INET, SOCK_RAW, IPPROTO_ICMP, AF_PACKET, IPPROTO_TCP, IPPROTO_RAW, SOCK_STREAM, IPPROTO_IP, IP_HDRINCL
import socket
from scapy.all import *

from consts import MAX_PACKET_SIZE, ETH_P_IP, LOCAL_ICMP_IP, REMOTE_ICMP_IP, TYPE_ECHO_REPLY, REMOTE_IP, LOCAL_SRC_IP
from utils import async_sendto, set_bpf


# This is the code for the limited reosurces local server.
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
        # self.output_tcp.bind(('3.3.3.1', 0))
        self.output_tcp.setblocking(False)
        # self.output_tcp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def create_input_tcp_socket(self):
        self.input_tcp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        self.input_tcp.bind(('rl2r', 0))
        self.input_tcp.setblocking(False)
        set_bpf(self.input_tcp, "tcp") # and dst host {}".format(LOCAL_SRC_IP))

    def serialize_data_over_icmp(self, data : bytes) -> bytes:
        # final_data = bytes(IP(data))
        # pkt = Ether() / IP(src=REMOTE_ICMP_IP, dst=LOCAL_ICMP_IP) / ICMP(type=TYPE_ECHO_REPLY) / final_data
        # return pkt.build()
        # dummy_bytes = bytes(1) * 8 #TODO: fix? Scapy uses first 8 bytes of payload as ICMP.unused
        # return dummy_bytes + bytes(IP(data))
        return bytes(Ether(data)[IP])

    def deserialize_data_over_icmp(self, data : bytes) -> bytes:
        # final_data = IP(data)[Raw]
        # pkt = Ether() / IP(final_data) # contains all layers including tcp
        # pkt[IP].src = REMOTE_IP
        # self.nat(pkt)
        # return pkt.build()
        return bytes(IP(data)[ICMP])

    async def run(self):
        await asyncio.wait([asyncio.create_task(self.tunnel_icmp_to_tcp()), asyncio.create_task(self.tunnel_tcp_to_icmp())])

    async def tunnel_icmp_to_tcp(self):
        while True:
            print('REMOTE (ICMP->TCP):')
            data = await self._loop.sock_recv(self.icmp_socket, MAX_PACKET_SIZE)
            print('REMOTE (ICMP->TCP): Got Data: {}'.format(data)) # Data is IP layer and beyond        
            packet = self.deserialize_data_over_icmp(data)
            print('REMOTE (ICMP->TCP): De-Serialized: {}'.format(packet))
            # import pdb; pdb.set_trace()
            await async_sendto(self.output_tcp, packet)
            print('REMOTE (ICMP->TCP): Sent')

    async def tunnel_tcp_to_icmp(self):
        while True:
            print('REMOTE (TCP->ICMP):')
            data = await self._loop.sock_recv(self.input_tcp, MAX_PACKET_SIZE)
            print('REMOTE (TCP->ICMP): Got Data: {}'.format(data))
            # import pdb; pdb.set_trace()
            packet = self.serialize_data_over_icmp(data)
            print('REMOTE (TCP->ICMP): Serialized: {}'.format(packet))
            await self._loop.sock_sendall(self.icmp_socket, packet)
            print('REMOTE (TCP->ICMP): Sent')

async def main():
    server = RemoteServer()
    await server.run()

if __name__ == '__main__':
    asyncio.run(main())
