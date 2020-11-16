# network_sniffer
Simple IPv4 packet sniffer for viewing packets on a network interface.  
Linux only currently, it sorta works in Windows but not really. Will most likely remove Windows functionality.

# Examples
Running the `sniffer.py` script as it is currently will provide the following output:  
(Actual script output is in nice columns but not sure how to make this happen with markdown)  
>#############################################################  
>
>Wiresharkified Packet:
>
>08 00 27 23 1b 1e 04 d4&nbsp; &nbsp; &nbsp; c4 4a ea 20 08 00 45 00  
>00 8c 68 24 40 00 80 06&nbsp; &nbsp; &nbsp; 7e 3c 0a 00 00 02 0a 00  
>00 0a ea 92 00 16 e8 54&nbsp; &nbsp; &nbsp; 6b f6 42 2e ca 3d 50 18  
>20 12 5a ce 00 00 dd 30&nbsp; &nbsp; &nbsp; c2 a7 34 7e 10 b1 2c 74  
>9e c0 0d 45 c1 ed e0 9e&nbsp; &nbsp; &nbsp; 70 2c 4c 00 a8 82 b3 cc  
>ee fb b1 62 c3 79 c3 73&nbsp; &nbsp; &nbsp; ed be 0f 7f 5c a5 41 29  
>2b 10 93 59 3b fd 05 d8&nbsp; &nbsp; &nbsp; 4a 85 eb eb 4e 9d 68 d7  
>76 b7 a4 aa b2 c1 85 43&nbsp; &nbsp; &nbsp; a5 da f2 a4 20 96 40 a1  
>c7 f8 76 eb 41 91 08 1c&nbsp; &nbsp; &nbsp; 40 fa 7f 0c 46 8b 92 7a  
>1c 6b 9d d8 e0 58 69 80&nbsp; &nbsp; &nbsp; 39 3b  
>
>Source MAC:&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;&nbsp;00:AB:CD:12:33:99  
>Source IP:&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 10.00.00.02  
>Destination IP:&nbsp; &nbsp; &nbsp; &nbsp;10.00.00.10  
>Destination MAC:&nbsp; &nbsp;91:01:72:26:GC:1E  
>Ethernet Type:&nbsp; &nbsp; &nbsp; &nbsp; 0x0800  
>Protocol Type:&nbsp; &nbsp; &nbsp; &nbsp; TCP  
>
>#############################################################  
  
For UDP packets the script will also output an attempted translation of the data payload.
