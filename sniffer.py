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


# TODO: Look into getting away from single interfaces in lists
def main():
    # Make a socket object to listen for packets
    listener = create_and_verify_listener()
    
    # Main loop here, grab a packet to play with
    # Prints a pretty version of the packet similar to what Wireshark would output
    # Parses some other cool info from the packet
    while True:
        packet = listener.recvfrom(2048)[0]  # Normally returns a tuple of (packet, interface, ???)

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
                print("Packet Payload:")
                for i in range(len(packet_details["data"])):
                    if i % 100 == 0:
                        print(packet_details["data"][i])  # add a newline
                    else:
                        print(packet_details["data"][i], end='')  # no newline
                print("\n")
            print("#############################################################################")

        input()  # Allows us to look at one packet at a time; comment out for lightspeed
    return 0


def create_and_verify_listener() -> socket.socket:
    """Creates a socket object for use in main()

    Returns:
        socket.socket: socket object for packet inspection
    """
    # Check if script was called with an interface to listen on
    try:
        unverified_interface = sys.argv[1]
    except IndexError:
        unverified_interface = False

    if sys.platform == 'win32':
        print("WARNING: This module not intended for use on Windows systems!!! Use at your own discretion.")
        listener = sniffer_tools.make_listener(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_IP,
            'localhost',
            0,
        )

    # For Linux, if script wasn't called with an interface let's try to detect some first
    # Once we have an unverified_interface, run it through verify_interface()
    elif sys.platform == 'linux':
        if unverified_interface is False:  # If we don't have an interface yet, detect some
            network_interfaces = sniffer_tools.detect_interfaces()
        else:
            network_interfaces = [unverified_interface]  # Put in array since our methods expect that

        # Catch anything that went wrong here
        if not network_interfaces:
            print("No interface could be detected or verified. Aborting...")
            exit(0)
        else:
            # Start a while loop here until we can validate a chosen interface
            while True:
                # If we have multiple interfaces, print them out for user to choose from
                if len(network_interfaces) > 1:
                    for interface in network_interfaces:
                        print(f'{network_interfaces.index(interface)}: {interface}')

                    # Set linux_interface to -1 here, then make a while loop to keep prompting until valid choice
                    # This will remain in loop until user selects a valid choice
                    linux_interface = -1
                    while linux_interface < 0 or linux_interface >= len(network_interfaces):
                        print(f'Valid inputs are integers from 0 to {len(network_interfaces) -1 }.')
                        linux_interface = int(input("Input the number of the interface you'd like to listen on: "))

                # Set to 0 here since our input interface was verified and is the only item in network_interfaces list
                elif len(network_interfaces) == 1:
                    linux_interface = 0
                
                elif len(network_interfaces) == 0:
                    print("There are no more interfaces available. Aborting.")
                    exit(0)
                
                # Run the verification, if it returns True then it's valid and we're good
                if sniffer_tools.verify_interface(network_interfaces[linux_interface]):
                    print(f'Interface {network_interfaces[linux_interface]} has been verified!')
                    break
                else:
                    print(f'Interface {network_interfaces[linux_interface]} could not be verified.')
                    if len(network_interfaces) == 1:
                        exit(0)
                    else:
                        network_interfaces.pop(linux_interface)  # Remove the bad interface from list
            
            listener = sniffer_tools.make_listener(
                socket.PF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0800),
                network_interfaces[linux_interface],
                0,
            )
    else:
        print("Unsupported operating system, exiting.")
        exit(0)
    return listener


if __name__ == '__main__':
    main()
