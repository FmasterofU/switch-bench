from scapy.all import Ether, sendp, sniff, raw, conf
import zlib
import sys, os, random

conf.verb = 0

def append_fcs(packet):
    #fill with zeros so that the packet has a minimum lenght of 46 bytes
    if len(packet) < 46:
        packet += b'\x00' * (46 - len(packet))
    # Calculate CRC32 over the bytes of the packet
    crc = zlib.crc32(raw(packet)) & 0xffffffff
    # Convert the CRC into bytes, little-endian order
    fcs = crc.to_bytes(4, byteorder='little')
    # Append the FCS to the original packet
    return raw(packet) + fcs

def check_fcs(packet):
    # Extract the FCS from the packet
    fcs = packet[-4:]
    # Extract the rest of the packet
    rest = packet[:-4]
    # Calculate the CRC32 over the rest of the packet
    crc = zlib.crc32(rest) & 0xffffffff
    # Convert the CRC into bytes, little-endian order
    expected_fcs = crc.to_bytes(4, byteorder='little')
    # Compare the FCS from the packet with the expected FCS
    return fcs == expected_fcs

def send_layer2_packet(dst_mac, src_mac, payload):
    # Create an Ethernet frame with the specified MAC addresses
    ether = Ether(dst=dst_mac, src=src_mac, type=0x1234)

    payload = append_fcs(payload)

    # Attach the payload to the Ethernet frame
    packet = ether / payload

    # Send the packet on the network
    sendp(packet)

def send_random_size_layer2_packet(dst_mac, src_mac):
    # create random payload of size between 46 and 1496 bytes
    payload = os.urandom(random.randint(46, 1496))
    send_layer2_packet(dst_mac, src_mac, payload)

def analyze_packet(packet):
    if not check_fcs(bytes(packet[Ether].payload)):
        raise Exception("FCS check failed.")

def capture_packets(remote_hosts = None):
    if not remote_hosts:
        sniff(filter="ether proto 0x1234", prn=analyze_packet)
    else:
        filter = "ether proto 0x1234 and (ether src " + remote_hosts[0]
        for i in range(1, len(remote_hosts)):
            filter += " or ether src " + remote_hosts[i]
        filter += " or ether dst ff:ff:ff:ff:ff:ff)"
        sniff(filter=filter, prn=analyze_packet)

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
        print("Usage: python switch-bench.py [send|capture|combined] <localhost_mac> <remote_host_mac> [<remote_host_mac_1> ...]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode not in ["send", "capture", "combined"]:
        raise Exception("Invalid mode. Please choose 'send', 'capture', or 'combined'.")

    localhost_mac = sys.argv[2]
    if not validate_mac_address(localhost_mac):
        raise Exception("Invalid source MAC address. Expected format: 'XX:XX:XX:XX:XX:XX'.")
    
    for i in range(3, len(sys.argv)):
        remote_host_mac = sys.argv[i]
        if not validate_mac_address(remote_host_mac):
            raise Exception("Invalid destination MAC address:" + remote_host_mac + ". Expected format: 'XX:XX:XX:XX:XX:XX'.")

    if mode == "send":
        while True:
            for i in range(3, len(sys.argv)):
                send_random_size_layer2_packet(sys.argv[i], localhost_mac)
    elif mode == "capture":
        capture_packets(sys.argv[3:])
    elif mode == "combined":
        raise Exception("Combined mode not implemented yet.")

    #send_layer2_packet(dst_mac, src_mac, "Hello, World!")
    #send_layer2_packet("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "Hello, World!")
    #capture_packets()