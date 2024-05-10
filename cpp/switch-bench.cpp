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

int main(int argc, char *argv[])
{
    // commandline arguments are ['path','host_mac_address','remote_mac_address']
    enum
    {
        ARG_PATH = 0,
        ARG_HOST_MAC = 1,
        ARG_REMOTE_MAC = 2,
    };

    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[ARG_PATH] << " <host_mac_address> <remote_mac_address>" << std::endl;
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

    // Sending packets
    // ~~~~~~~~~~~~~~~~~~~~~~

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

    for (int i = 0; i < 1; i++)
        packetVec.push_back(*(newPacket.getRawPacket()));

    // Sending batch of packets
    // ~~~~~~~~~~~~~~~~~~~~~~~~

    std::cout << "Sending " << packetVec.size() << " packets..." << std::endl;
    // std::thread t1(sender);
    // std::thread t2(sender);

    // t1.join();
    // t2.join();
    sender();
}