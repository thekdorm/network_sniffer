#!/usr/bin/python3

# Experimental module for inspecting IP traffic on a network interface
#
# Only really works on Linux, as Windows strips off the Ethernet II header by default
# and I haven't really found a way around that yet
#
# Author: Kyle Dormody

import subprocess
import socket
import binascii
import json
import sys
import os
from typing import Dict, List


def detect_interfaces() -> List[str]:
    """Function to attempt to detect network interfaces for binding
    If none are found the user has the option to manually input an interface

    Returns:
        List[str]: A list of found network interfaces
    """
    if sys.platform == 'linux':
        try:
            output = subprocess.check_output(r"grep -Eo '\w*:' /proc/net/dev", shell=True)
            interfaces = output.decode().rstrip(':\n').split(':\n')
        except subprocess.CalledProcessError as e:
            print(f'EXCEPTION: {type(e).__name__} raised with exit status {e.args[0]}')
            if e.args[0] != 0:  # if the exit code of the grep command is not 0, it failed so ask for interface manually
                interfaces = [input("Automatic interface detection failed, input an interface now: ").lower().rstrip()]
    else:
        interfaces = [input("Automatic interface detection failed, input an interface now: ").lower().rstrip()]
    interfaces.sort()
    return interfaces


def verify_interface(interface: str) -> bool:
    """Attempts to verify the chosen network interface

    Args:
        interface (str): The interface to verify

    Returns:
        bool: True if verified, False if not
    """
    # TODO: Make this section nicer, probably a better way to check ifconfig or ip commands than
    # try/except clauses to see which one works
    if sys.platform == 'linux':
        try:
            subprocess.check_output("ip addr", shell=True)
            command = "ip link show"
        except subprocess.CalledProcessError:
            print("This os doesn't support the ip tool, trying ifconfig...")
            try:
                subprocess.check_output("ifconfig", shell=True)
                command = "ifconfig"
            except subprocess.CalledProcessError:
                print("This os doesn't support the ifconfig tool, aborting!")
                return False
        
        # If we've got this far then we know which tool to check the interface with
        try:
            subprocess.check_output(f'{command} {interface}', shell=True)
            return True
        except subprocess.CalledProcessError:
            return False


def make_listener(interface: int, socket_type: int, packet_type: int, host: str,
                  port: int, promiscuous=True) -> socket.socket:
    """Create and bind a socket object for packet inspection

    Args:
        interface (int): Interface type
        socket_type (int): Socket type
        packet_type (int): Packet type
        host (str): Host to bind to
        port (int): Port to bind to
        promiscuous (bool, optional): Snoop on all packets? Defaults to True.

    Returns:
        socket.socket: socket object for packet listening
    """
    s = socket.socket(interface, socket_type, packet_type)
    s.bind((host, port))

    # This junk doesn't do a whole lot besides from setting a Windows interface to 'promiscuous'
    # Windows strips the Ethernet II header from packets which kinda makes all this pointless
    # You can still snoop on packets though, just won't be able to get much info from them
    if sys.platform == 'win32':
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if promiscuous is True:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return s


# TODO: Work on the while loop logic. It works but could be nicer.
def wiresharkify(packet: bytes) -> str:
    """Takes a raw packet and formats a string to look like a Wireshark packet

    Args:
        packet (bytes): Raw packet to format

    Returns:
        str: Formatted string, wiresharkified!
    """
    try:
        decoded_packet = binascii.hexlify(packet).decode()
    except (TypeError, AttributeError) as e:
        print(f'EXCEPTION: {type(e).__name__}: {e}')
        decoded_packet = packet
    
    # Make a string to append the hex characters to and define some starting variables
    formatted = '\nWiresharkified Packet:\n\n'
    start = 0
    if len(decoded_packet) < 32:
        end = len(decoded_packet)
    else:
        end = 32
    
    while True:
        current_set = decoded_packet[start:end]  # Need to iterate over the entire packet
        for i in range(len(current_set)):
            formatted += current_set[i]  # Append the current character to the formatted string
            if i != 0:
                if i % 31 == 0:  # After byte 15 from index 0, add a \n
                    formatted += '\n'
                elif i % 15 == 0 and i % 30 != 0:  # After byte 7 from index 0, add a \t\t because just \t doesn't show
                    formatted += '\t\t'
                elif i == 1 or i % 2 == 1:  # If none of the others hold true, after byte 1 from index 0, add a ' '
                    formatted += ' '
        
        # Move on to the next set of 16 bytes. Don't go past the length of the packet
        # Exit the loop when the "start" is greater than the length of the packet
        start += 32
        end += 32
        if end > len(decoded_packet):
            end = len(decoded_packet)
        if start > len(decoded_packet):
            break
    formatted += "\n"
    return formatted


def analyze_packet(packet: bytes,  beautify: bool = False) -> Dict[str, str]:
    """Pull out some interesting information from the packet

    Args:
        packet (bytes): Raw packet
        beautify (bool, optional): Make it pretty! Defaults to False.

    Returns:
        Dict[str, str]: Dictionary of info we could parse
    """
    # This logic is assuming it's an IPv4 packet, something like an ARP will probably break it
    packet_info = {
        'dst_mac':  packet[0:6],
        'dst_ip':   packet[30:34],
        'src_mac':  packet[6:12],
        'src_ip':   packet[26:30],
        'eth_type': packet[12:14],
        'protocol': packet[23],  # byte 23 is protocol type for IPv4 packets
        'data':     None,
    }

    # If it's an IPv4 packet, find the associated protocol
    if packet_info['eth_type'] == b'\x08\x00':
        with open(f'{os.getcwd()}/tools/ip_protocols.json') as f:
            protocols = json.load(f)
        packet_info['protocol'] = protocols[packet_info['protocol']]['Keyword']  # convert byte to protocol type

        # Attempt to decode the UDP data
        if packet_info['protocol'] == 'UDP':
            packet_info['data'] = packet[42:].decode('ISO-8859-1')
    else:
        pass
    return _beautify_packet(packet_info, beautify)


def _beautify_packet(packet: Dict[str, bytes], beautify: bool = False) -> Dict[str, str or bytes]:
    """Gets called whenever analyze_packet is called; this will either just return whatever
    analyze_packet returns if beautify = False, or convert to ASCII if beautify = True

    Args:
        packet (Dict[str, bytes]): Packet info
        beautify (bool, optional): Make it pretty!. Defaults to False.

    Returns:
        Dict[str, str or bytes]: Values will be str or bytes depending on if beautify=True
    """
    if beautify is True:
        packet['dst_mac']= ':'.join(format(s, '02X') for s in bytes.fromhex(binascii.hexlify(packet['dst_mac']).decode()))
        packet['dst_ip'] = '.'.join(format(s, '02d') for s in bytes.fromhex(binascii.hexlify(packet['dst_ip']).decode()))
        packet['src_mac'] = ':'.join(format(s, '02X') for s in bytes.fromhex(binascii.hexlify(packet['src_mac']).decode()))
        packet['src_ip'] = '.'.join(format(s, '02d') for s in bytes.fromhex(binascii.hexlify(packet['src_ip']).decode()))
        packet['eth_type'] = binascii.hexlify(packet['eth_type']).decode()
    return packet
