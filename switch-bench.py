from scapy.all import Ether, sendp, sniff
import sys

def send_layer2_packet(dst_mac, src_mac, payload):
    # Create an Ethernet frame with the specified MAC addresses
    ether = Ether(dst=dst_mac, src=src_mac)

    # Attach the payload to the Ethernet frame
    packet = ether / payload

    # Send the packet on the network
    sendp(packet)


def analyze_packet(packet):
    if Ether in packet:
        print("Source MAC: ", packet[Ether].src)
        print("Destination MAC: ", packet[Ether].dst)
        print("Ethernet Type: ", packet[Ether].type)
        print("Payload: ", packet[Ether].payload)

def capture_packets():
    sniff(filter="ether", prn=analyze_packet)

def validate_mac_address(mac_address):
    if len(mac_address) != 17:
        raise Exception("Invalid MAC address. MAC address must be 17 characters long.")

    if mac_address[2] != ":" or mac_address[5] != ":" or mac_address[8] != ":" or mac_address[11] != ":" or mac_address[14] != ":":
        raise Exception("Invalid MAC address. MAC address must be in the format 'XX:XX:XX:XX:XX:XX'.")

    for i in range(0, 17):
        if i % 3 == 0:
            if not mac_address[i].isalnum():
                raise Exception("Invalid MAC address. MAC address must be in the format 'XX:XX:XX:XX:XX:XX'.")

    return True

if __name__ == "__main__":
    print("Number of arguments: ", len(sys.argv))
    print("Arguments: ", str(sys.argv))
    if len(sys.argv) < 4:
        print("Usage: python switch-bench.py [send|capture|combined] <src_mac> <dst_mac> [<dst_mac_1> <dst_mac_2> <dst_mac_3 ...>]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode not in ["send", "capture", "combined"]:
        raise Exception("Invalid mode. Please choose 'send', 'capture', or 'combined'.")

    src_mac = sys.argv[2]
    if not validate_mac_address(src_mac):
        raise Exception("Invalid source MAC address. Expected format: 'XX:XX:XX:XX:XX:XX'.")
    
    for i in range(3, len(sys.argv)):
        dst_mac = sys.argv[i]
        if not validate_mac_address(dst_mac):
            raise Exception("Invalid destination MAC address:" + dst_mac + ". Expected format: 'XX:XX:XX:XX:XX:XX'.")

    if mode == "send":
        while True:
            for i in range(3, len(sys.argv)):
                send_layer2_packet(sys.argv[i], src_mac, "Hello, World!")
    elif mode == "capture":
        capture_packets()
    elif mode == "combined":
        raise Exception("Combined mode not implemented yet.")

    #send_layer2_packet(dst_mac, src_mac, "Hello, World!")
    #send_layer2_packet("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "Hello, World!")
    #capture_packets()