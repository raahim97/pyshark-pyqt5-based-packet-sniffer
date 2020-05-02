This project mainly focuses on implementing features of Wireshark using Pyshark and pyqt5 to analyze WLAN packets. The capturing can be done either Live Capture or File Capture.

LIVE CAPTURE

     The Live Capture is performed with Live Network. Please connect the device to the Wireless Local Area Network to capture the packets.The sniffing of packets can be limited by either packet count or timeout. The pyqt5 is a GUI which is used to get user input data.The pyshark takes this user input data and process accordingly. The output file is stored with pcap(packet capture) extension which can displayed using Wireshark.  


FILE CAPTURE

    The File Capture is useful only when we want to analyse a pre-existing pcap file. The pcap file uses tshark(Terminal shark) to analyse and display
 the output. Here the packets can be viewed by selecting the desired protocol. For a detailed and non-detailed description of data in the packets only_summaries option would be useful.
