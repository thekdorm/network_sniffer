#!/usr/bin/python3

# Experimental script for inspecting IP traffic on a network interface
#
# Only really works on Linux, as Windows strips off the Ethernet II header by default
# and I haven't really found a way around that yet
#
# Author: Kyle Dormody

import sys
import socket
from tools import sniffer_tools

# TODO: Possibly add in automatic interface detection -> list, allow user to choose at runtime
linux_interface = 'enp0s8'  # From Ubuntu VM


def main():
    # Determine first how we're running; Windows doesn't work so this really should only be Linux
    if sys.platform == 'win32':
        print("WARNING: This module not intended for use on Windows systems!!! Use at your own discretion.")
        listener = sniffer_tools.make_listener(socket.AF_INET, socket.SOCK_RAW,
                                               socket.IPPROTO_IP, 'localhost', 0)
    elif sys.platform == 'linux':
        listener = sniffer_tools.make_listener(socket.PF_PACKET, socket.SOCK_RAW,
                                               socket.htons(0x0800), linux_interface, 0)

    # Main loop here, grab a packet to play with
    # Prints a pretty version of the packet similar to what Wireshark would output
    # Parses some other cool info from the packet
    while True:
        packet = listener.recvfrom(2048)[0]  # Normally returns a tuple of (packet, interface, ???)

        print("#############################################################################")
        print(sniffer_tools.wiresharkify(packet))

        # Only perform packet analysis if we are on Linux
        if sys.platform == 'linux':
            packet_details = sniffer_tools.analyze_packet(packet, beautify=True)
            print(
                f'Source MAC:       {packet_details["src_mac"]}\n'
                f'Source IP:        {packet_details["src_ip"]}\n'
                f'Destination IP:   {packet_details["dst_ip"]}\n'
                f'Destination MAC:  {packet_details["dst_mac"]}\n'
                f'Ethernet Type:    0x{packet_details["eth_type"]}\n'
                f'Protocol Type:    {packet_details["protocol"]}\n'
            )

            if packet_details['data']:
                print(f'Packet Payload:\n{packet_details["data"]}')
            print("#############################################################################")

        # input()  # Allows us to look at one packet at a time; comment out for lightspeed
        break


if __name__ == '__main__':
    main()
