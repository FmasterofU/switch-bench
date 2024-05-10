#include <iostream>
#include "stdlib.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "PayloadLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "MacAddress.h"
#include <vector>
#include <random>
#include <ctime>
#include <thread>

// interface
pcpp::PcapLiveDevice *dev = nullptr;

// vector of packets
std::vector<pcpp::RawPacket> packetVec;

void printDevice(pcpp::PcapLiveDevice *dev)
{
    // Get device info
    // ~~~~~~~~~~~~~~~

    // before capturing packets let's print some info about this interface
    std::cout
        << "Interface info:" << std::endl
        << "   Interface name:        " << dev->getName() << std::endl           // get interface name
        << "   Interface description: " << dev->getDesc() << std::endl           // get interface description
        << "   MAC address:           " << dev->getMacAddress() << std::endl     // get interface MAC address
        << "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
        << "   Interface MTU:         " << dev->getMtu() << std::endl;           // get interface MTU
}

void sender()
{
    for (int i = 0; i < 30; i++)
    {
        int packetsSent = dev->sendPackets(packetVec.data(), packetVec.size());

        if (packetVec.size() != packetsSent)
        {
            std::cerr << "Couldn't send all packets." << std::endl;
            exit(1);
        }
        else
        {
            std::cout << packetsSent << " packets sent" << std::endl;
        }
    }
}

struct PacketStats
{
    int ethPacketCount;

    /**
     * Clear all stats
     */
    void clear()
    {
        ethPacketCount = 0;
    }

    /**
     * C'tor
     */
    PacketStats() { clear(); }

    /**
     * Collect stats from a packet
     */
    void consumePacket(pcpp::Packet &packet)
    {
        if (packet.isPacketOfType(pcpp::Ethernet))
        {
            ethPacketCount++;
        }
    }

    /**
     * Print stats to console
     */
    void printToConsole()
    {
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl;
    }
};

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::TCP:
        return "TCP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}

int main(int argc, char *argv[])
{
    // commandline arguments are ['path', 'mode', 'host_mac_address','remote_mac_address']
    enum
    {
        ARG_PATH = 0,
        ARG_MODE = 1,
        ARG_HOST_MAC = 2,
        ARG_REMOTE_MAC = 3,
    };

    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[ARG_PATH] << " [send|capture|combined] <host_mac_address> <remote_mac_address>" << std::endl;
        return 1;
    }
    // Check if mode is correct
    if (strcmp(argv[ARG_MODE], "send") != 0 && strcmp(argv[ARG_MODE], "capture") != 0 && strcmp(argv[ARG_MODE], "combined") != 0)
    {
        std::cerr << "Invalid mode. Mode must be either 'send', 'capture' or 'combined'." << std::endl;
        return 1;
    }

    // MAC address of the interface we want to sniff (host === interface)
    std::string interfaceMacAddr = argv[ARG_HOST_MAC];
    // Convert the MAC address string to a MacAddress object
    pcpp::MacAddress interface_macAddress(interfaceMacAddr);
    std::string remoteMacAddr = argv[ARG_REMOTE_MAC];
    // Convert the MAC address string to a MacAddress object
    pcpp::MacAddress remote_macAddress(remoteMacAddr);

    // Validate host MAC address format
    if (!interface_macAddress.isValid())
    {
        std::cerr << "Invalid host MAC address. MAC address must be in the format 'XX:XX:XX:XX:XX:XX'." << std::endl;
        return 1;
    }
    // else, validate remote MAC address format
    if (!remote_macAddress.isValid())
    {
        std::cerr << "Invalid remote MAC address. MAC address must be in the format 'XX:XX:XX:XX:XX:XX'." << std::endl;
        return 1;
    }

    std::srand(std::time(0)); // use current time as seed for random generator

    // Get the list of all devices
    pcpp::PcapLiveDeviceList &deviceList = pcpp::PcapLiveDeviceList::getInstance();

    // Retrieve the list of all available live devices
    const std::vector<pcpp::PcapLiveDevice *> &devices = deviceList.getPcapLiveDevicesList();

    // Iterate over all devices
    for (pcpp::PcapLiveDevice *device : devices)
    {
        // Get the MAC address of the current device
        pcpp::MacAddress currMacAddress = device->getMacAddress();

        // Check if the MAC address of the current device matches the one we're looking for
        if (currMacAddress == interface_macAddress)
        {
            // We found the device
            dev = device;
            // Use the device...
            break;
        }
    }

    printDevice(dev);

    // open the device before start capturing/sending packets
    if (!dev->open())
    {
        std::cerr << "Cannot open device" << std::endl;
        return 1;
    }

    // pcpp::Packet newPacket = createPacket();
    //  Packet Creation
    //  ~~~~~~~~~~~~~~~

    // if send mode, create a packet and send it
    if (strcmp(argv[ARG_MODE], "send") == 0)
    {
        // create a new Ethernet layer
        pcpp::EthLayer newEthernetLayer(interface_macAddress, remote_macAddress, 0x1234);

        // Create a payload
        int num_chars = 1500; // number of random characters to generate

        std::vector<uint8_t> random_chars(num_chars);

        for (int i = 0; i < num_chars; ++i)
        {
            random_chars[i] = 'a' + std::rand() % 26; // Generate a random character between 'a' and 'z'
        }

        // Now random_chars contains num_chars random characters
        pcpp::PayloadLayer payloadLayer(random_chars.data(), random_chars.size(), false);

        // create a packet (will grow automatically if needed)
        pcpp::Packet newPacket;

        // add all the layers we created
        newPacket.addLayer(&newEthernetLayer);
        newPacket.addLayer(&payloadLayer);

        // compute all calculated fields
        newPacket.computeCalculateFields();

        // send single packet. If fails exit the application
        if (!dev->sendPacket(&newPacket))
        {
            std::cout.flush();
            std::cerr << "Couldn't send packet." << std::endl;
            return 1;
        }
        else
        {
            std::cout << "Single packet sent" << std::endl;
        }

        // pcpp::RawPacketVector packetVec;

        for (int i = 0; i < 10000; i++)
            packetVec.push_back(*(newPacket.getRawPacket()));

        // Sending batch of packets
        // ~~~~~~~~~~~~~~~~~~~~~~~~

        std::cout << "Sending " << packetVec.size() << " packets..." << std::endl;
        sender();
    }
    else if // capture mode
        (strcmp(argv[ARG_MODE], "capture") == 0)
    {
        // create the stats object
        PacketStats stats;

        std::cout << std::endl
                  << "Starting async capture..." << std::endl;

        // create an empty packet vector object
        pcpp::RawPacketVector capturePacketVec;

        // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
        dev->startCapture(capturePacketVec);

        // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
        pcpp::multiPlatformSleep(10);

        // stop capturing packets
        dev->stopCapture();

        // go over the packet vector and feed all packets to the stats object
        for (pcpp::RawPacketVector::ConstVectorIterator iter = capturePacketVec.begin(); iter != capturePacketVec.end(); iter++)
        {
            // parse raw packet
            pcpp::Packet parsedPacket(*iter);

            // get ethernet layer for filtering
            pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
            if (ethernetLayer == NULL)
            {
                std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
                // return;
                continue;
            }
            // std::cout
            //     << "Layer type: " << "Ethernet" << "; "                                    // get layer type
            //     << "Total data: " << ethernetLayer->getDataLen() << " [bytes]; "           // get total length of the layer
            //     << "Layer data: " << ethernetLayer->getHeaderLen() << " [bytes]; "         // get the header length of the layer
            //     << "Layer payload: " << ethernetLayer->getLayerPayloadSize() << " [bytes]" // get the payload length of the layer (equals total length minus header length)
            //     << std::endl;

            // print the source and dest MAC addresses and the Ether type
            // std::cout << std::endl
            //           << "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
            //           << "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
            //           << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

            // collect stats from packet if it matches filter (source MAC address, destination mac address, ether type)
            if (ethernetLayer->getSourceMac() == remoteMacAddr && ethernetLayer->getDestMac() == interfaceMacAddr && pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) == 0x1234)
                stats.consumePacket(parsedPacket);
        }

        // print results
        std::cout << "Results:" << std::endl;
        stats.printToConsole();
    }
    else // error
    {
        std::cerr << "Invalid mode. Mode must be either 'send', 'capture' or 'combined'." << std::endl;
        return 1;
    }
}