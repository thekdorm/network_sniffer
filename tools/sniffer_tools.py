#!/usr/bin/python3

# Experimental module for inspecting IP traffic on a network interface
#
# Only really works on Linux, as Windows strips off the Ethernet II header by default
# and I haven't really found a way around that yet
#
# Author: Kyle Dormody

import socket
import binascii
import json
import os
from typing import Dict


def make_listener(interface: int, socket_type: int, packet_type: int, host: str,
                  port: int, promiscuous=True) -> socket.socket:
    """
    This isn't necessarily useful in any way, it's more just here as a future reference.

    Open a socket of specified type, listening for specific packets. Refer to documentation for more on socket module.
    When passing arguments, need to pass them as socket.ATTRIBUTE, i.e. socket.AF_UNIX, socket.SOCK_STREAM etc.

    Parameters
    ----------
    interface       AF_UNIX, AF_INET, AF_INET6
    socket_type     SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_CLOEXEC, SOCK_NONBLOCK
    packet_type     Type of packets you want to look at; use socket.htons(0x0800) or socket.IPPROTO_IP
    host            Host name the listener will be on
    port            Port the listener binds to
    promiscuous     If set to True, will listen to all packets that the NIC sees (Windows mostly)

    Returns         Returns a socket object
    -------

    """
    s = socket.socket(interface, socket_type, packet_type)
    s.bind((host, port))

    # This junk doesn't do a whole lot besides from setting a Windows interface to 'promiscuous'
    # Windows strips the Ethernet II header from packets which kinda makes all this pointless
    # You can still snoop on packets though, just won't be able to get much info from them
    #
    # if sys.platform == 'win32':
    #     s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #     if promiscuous is True:
    #         s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return s


# TODO: Work on the while loop logic. It works but could be nicer.
def wiresharkify(packet: bytes) -> str:
    """Basically will just take a raw packet and format it to look similar to what you'd see in Wireshark.

    Parameters
    ----------
    packet      Packet we want to wiresharkify

    Returns     The returned packet that can be parsed easier
    -------

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


def analyze_packet(packet: bytes,  beautify: bool = False) -> [Dict[str, bytes], bool]:
    """Pull out some cool information from the packet

    Parameters
    ----------
    packet      The packet we want to analyze
    beautify    If True, converts raw hex to ASCII

    Returns     [Dictionary of info, bool]
    -------

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
    """
    Gets called whenever analyze_packet is called; this will either just return whatever
    analyze_packet returns if beautify = False, or convert to ASCII if beautify = True

    Parameters
    ----------
    packet      The packet we want to analyze
    beautify    If True, converts raw hex to ASCII

    Returns     [Dictionary of info, bool]
    -------

    """
    if beautify is True:
        packet['dst_mac']= ':'.join(format(s, '02X') for s in bytes.fromhex(binascii.hexlify(packet['dst_mac']).decode()))
        packet['dst_ip'] = '.'.join(format(s, '02d') for s in bytes.fromhex(binascii.hexlify(packet['dst_ip']).decode()))
        packet['src_mac'] = ':'.join(format(s, '02X') for s in bytes.fromhex(binascii.hexlify(packet['src_mac']).decode()))
        packet['src_ip'] = '.'.join(format(s, '02d') for s in bytes.fromhex(binascii.hexlify(packet['src_ip']).decode()))
        packet['eth_type'] = binascii.hexlify(packet['eth_type']).decode()
    return packet
