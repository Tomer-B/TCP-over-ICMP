#!/bin/bash

# Clean previous Network namespaces (Also deletes interfaces and settings)
ip -all netns delete

# Kill previous running Local & Remote
killall -9 "python3"

# Create four Network namespaces for Local, Remote, and both "pipes" Local->Remote, Remote->Local
ip netns add local
ip netns add local_remote
ip netns add remote_local
ip netns add remote

# Create Three coupled interfaces to emulate the "Connection" between any two Network namespaces.
# Unfortunately, too long of a name is not possible - hence the shortcuts.
    # l2lr - Local to Local-Remote
    # lr2l - Local-Remote to Local
    # lr2rl - Local-Remote to Remote-Local
    # rl2lr - Remote-Local to Local-Remote
    # rl2r - Remote-Local to Remote
    # r2rl - Remote to Remote-Local

ip link add l2lr netns local type veth peer name lr2l netns local_remote
ip link add lr2rl netns local_remote type veth peer name rl2lr netns remote_local
ip link add rl2r netns remote_local type veth peer name r2rl netns remote
 
# Lower MTU to account for extra headers (42 bytes max + spare)
ip netns exec local ifconfig l2lr mtu 1450
ip netns exec remote ifconfig r2rl mtu 1450

# Turn all interfaces on
ip netns exec local ip link set l2lr up
ip netns exec local_remote ip link set lr2l up 
ip netns exec local_remote ip link set lr2rl up
ip netns exec remote_local ip link set rl2lr up
ip netns exec remote_local ip link set rl2r up
ip netns exec remote ip link set r2rl up

# Configure All interfaces IP addresses - A pair for each Network namespace "Connection"
ip netns exec local ip address add dev l2lr 1.1.1.1/28
ip netns exec local_remote ip address add dev lr2l 1.1.1.2/28
ip netns exec local_remote ip address add dev lr2rl 2.2.2.1/28
ip netns exec remote_local ip address add dev rl2lr 2.2.2.2/28
ip netns exec remote_local ip address add dev rl2r 3.3.3.1/28
ip netns exec remote ip address add dev r2rl 3.3.3.2/28

# Configure The Connection Interfaces as Default gateways to any non-Connection Interfaces
ip netns exec local ip route add default via 1.1.1.2
ip netns exec remote ip route add default via 3.3.3.1

# Add iptables rules to drop any unnecessary tcp packets on both ends
ip netns exec local_remote iptables -I INPUT -p tcp -j DROP
ip netns exec remote_local iptables -I INPUT -p tcp -j DROP

# Run the Local & Remote
setsid ip netns exec local_remote python3 -m local &
setsid ip netns exec remote_local python3 -m remote &
