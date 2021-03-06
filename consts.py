ETH_P_IP = 0x800
TYPE_ECHO_REPLY = 0
TYPE_ECHO_REQUEST = 8
MAX_PACKET_SIZE = 65535

# From asm/socket.h  
SO_ATTACH_FILTER = 26

LOCAL_SRC_IP = '1.1.1.1'
LOCAL_BPF_FILTER = "tcp and src host {}".format(LOCAL_SRC_IP)
REMOTE_BPF_FILTER = "tcp and dst host {}".format(LOCAL_SRC_IP)
LOCAL_ICMP_IP = '2.2.2.1'
REMOTE_ICMP_IP = '2.2.2.2'
