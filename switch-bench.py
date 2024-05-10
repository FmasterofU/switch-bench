from scapy.all import Ether, sendp, sniff, raw, conf, sendpfast
import zlib
import sys, os, random, time
from multiprocessing import Process, active_children
import signal

conf.verb = 0

counter = 0

ENABLE_FCS = False

FCS_SIZE = 4

ETHERNET_ENCAPSULATED_PROTOCOL = 0x1234
ETHERNET_MINIMUM_FRAME_SIZE = 46

ENABLE_PACKET_DUPLICATION = True
PACKET_DUPLICATION_RATE = 1000

OPTIMAL_NUMBER_OF_PROCESSES = 16
ENABLE_MULTI_PROCESSING = False

if not ENABLE_FCS:
    FCS_SIZE = 0

MTU=1500

default_payload = os.urandom(MTU - FCS_SIZE)

def append_fcs(packet):
    #fill with zeros so that the packet has a minimum lenght of 46 bytes
    if len(packet) < ETHERNET_MINIMUM_FRAME_SIZE:
        packet += b'\x00' * (ETHERNET_MINIMUM_FRAME_SIZE - len(packet))
    # Calculate CRC32 over the bytes of the packet
    crc = zlib.crc32(raw(packet)) & 0xffffffff
    # Convert the CRC into bytes, little-endian order
    fcs = crc.to_bytes(FCS_SIZE, byteorder='little')
    # Append the FCS to the original packet
    return raw(packet) + fcs

def check_fcs(packet):
    # Extract the FCS from the packet
    fcs = packet[-FCS_SIZE:]
    # Extract the rest of the packet
    rest = packet[:-4]
    # Calculate the CRC32 over the rest of the packet
    crc = zlib.crc32(rest) & 0xffffffff
    # Convert the CRC into bytes, little-endian order
    expected_fcs = crc.to_bytes(FCS_SIZE, byteorder='little')
    # Compare the FCS from the packet with the expected FCS
    return fcs == expected_fcs

def send_layer2_packet(dst_mac, src_mac, payload):
    # Create an Ethernet frame with the specified MAC addresses
    ether = Ether(dst=dst_mac, src=src_mac, type=ETHERNET_ENCAPSULATED_PROTOCOL)

    if ENABLE_FCS:
        payload = append_fcs(payload)
    
    # Attach the payload to the Ethernet frame
    packet = ether / payload

    # Send the packet on the network
    if not ENABLE_PACKET_DUPLICATION:
        sendp(packet)
    else:
        sendp(packet, count=PACKET_DUPLICATION_RATE)

def send_random_size_layer2_packet(dst_mac, src_mac):
    # create random payload of size between 46 and 1496 bytes
    payload = os.urandom(random.randint(ETHERNET_MINIMUM_FRAME_SIZE, MTU - FCS_SIZE))
    send_layer2_packet(dst_mac, src_mac, payload)

def send_default_layer2_packet(dst_mac, src_mac):
    send_layer2_packet(dst_mac, src_mac, default_payload)

def analyze_packet(packet):
    if ENABLE_FCS and not check_fcs(bytes(packet[Ether].payload)):
        raise Exception("FCS check failed.")
    global counter
    counter += 1

def capture_packets(remote_hosts = None):
    filter = ""
    if not remote_hosts:
        filter="ether proto " + hex(ETHERNET_ENCAPSULATED_PROTOCOL)
    else:
        filter = "ether proto " + hex(ETHERNET_ENCAPSULATED_PROTOCOL) + " and (ether src " + remote_hosts[0]
        for i in range(1, len(remote_hosts)):
            filter += " or ether src " + remote_hosts[i]
        filter += " or ether dst ff:ff:ff:ff:ff:ff)"
    while True:
        sniff(filter=filter, prn=analyze_packet, timeout=10)

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


def send_process(localhost_mac):
    while True:
        for i in range(3, len(sys.argv)):
            send_default_layer2_packet(sys.argv[i], localhost_mac)

def printer(sig, frame):
    global counter
    print("Number of packets received: ", counter)
    exit(0)

signal.signal(signal.SIGINT, printer)

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
        if ENABLE_MULTI_PROCESSING:
            max_processes = len(sys.argv) - 3 if len(sys.argv) - 3 > OPTIMAL_NUMBER_OF_PROCESSES else OPTIMAL_NUMBER_OF_PROCESSES
            procs = []
            for _ in range(max_processes):
                proc = Process(target=send_process, args=(localhost_mac,))
                proc.start()
            for _ in procs:
                proc.pop(0).join()
        else:
            send_process(localhost_mac)
    elif mode == "capture":
        capture_packets(sys.argv[3:])
    elif mode == "combined":
        raise Exception("Combined mode not implemented yet.")
