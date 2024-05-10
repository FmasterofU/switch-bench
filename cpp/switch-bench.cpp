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
#include <map>

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

void sender(int packages = 1)
{
    for (int i = 0; i < packages; i++)
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
    // map of pairs of source MAC address (as string) and the number of packets sent by that MAC address
    std::map<std::string, int> srcMacCount;

    /**
     * Clear all stats
     */
    void clear()
    {
        ethPacketCount = 0;
        srcMacCount.clear();
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
            // extract source MAC address
            pcpp::MacAddress srcMac = packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac();
            // convert srcMac to string and then increase counter in map
            srcMacCount[srcMac.toString()]++;
        }
    }

    /**
     * Print stats to console
     */
    void printToConsole()
    {
        std::cout
            << "Ethernet packet count: " << ethPacketCount << std::endl;
        // Get an iterator pointing to the first element in the
        // map
        std::map<std::string, int>::iterator it = srcMacCount.begin();

        // iterate over all source MAC addresses and print the count
        while (it != srcMacCount.end())
        {
            std::cout
                << "   Source MAC address: " << it->first << " - " << it->second << " packets" << std::endl;
            it++;
        }
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

/**
 * A callback function for the async capture which is called each time a packet is captured
 */
static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
    // extract the stats object form the cookie
    PacketStats *stats = (PacketStats *)cookie;

    // parsed the raw packet
    pcpp::Packet parsedPacket(packet);

    // collect stats from packet
    stats->consumePacket(parsedPacket);
}

// function to check if string is an unsigned integer
bool isInteger(const std::string &s)
{
    return !s.empty() && std::find_if(s.begin(),
                                      s.end(), [](char c)
                                      { return !std::isdigit(c); }) == s.end();
}

int main(int argc, char *argv[])
{
    int ARG_NUM_PACKAGES = -1;
    int ARG_PATH = 0;
    int ARG_MODE = 1;
    int ARG_HOST_MAC = 2;
    int ARG_REMOTE_MAC = 3;
    int ARG_REMOTE_MAC_VEC = 4;
    bool customSendMode = false;

    // commandline arguments are ['path', 'mode', [number_of_packages_to_send], 'host_mac_address','remote_mac_address', [<remote_mac_address_1>, ...]]
    if (argc < 4)
    {
        std::cerr << "Usage: " << argv[ARG_PATH] << " [send|capture|combined] [number_of_packages_to_send] <host_mac_address> <remote_mac_address>, [<remote_mac_address_1>, ...]" << std::endl;
        return 1;
    }

    if (!strcmp(argv[ARG_MODE], "send") && isInteger(argv[2]))
        customSendMode = true;
    // if in send mode and second argument is a number, then send packets
    if (customSendMode)
    {
        ARG_NUM_PACKAGES = 2;
        ARG_HOST_MAC = 3;
        ARG_REMOTE_MAC = 4;
        ARG_REMOTE_MAC_VEC = 5;
    }

    if (!strcmp(argv[ARG_MODE], "send") && argc < 5)
    {
        std::cerr << "Usage: " << argv[ARG_PATH] << " [send|capture|combined] [number_of_packages_to_send] <host_mac_address> <remote_mac_address>, [<remote_mac_address_1>, ...]" << std::endl;
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

    // if more than 1 remote MAC address is provided do validation for each
    if (argc > ARG_REMOTE_MAC_VEC)
    {
        for (size_t i = 0; i < argc - ARG_REMOTE_MAC_VEC; i++)
        {
            // Convert the MAC address string to a MacAddress object
            pcpp::MacAddress macAddress(argv[ARG_REMOTE_MAC_VEC + i]);
            // Validate remote MAC address format
            if (!macAddress.isValid())
            {
                std::cerr << "Invalid remote MAC address at index [" << i + 1 << "]. MAC address must be in the format 'XX:XX:XX:XX:XX:XX'." << std::endl;
                return 1;
            }
        }
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
        // temporary: notify user that send only sends to first remote MAC address
        if (argc > ARG_REMOTE_MAC_VEC)
        {
            std::cout << "Note: Send mode currently only supports sending to the first remote MAC address." << std::endl;
        }
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

        // Sending batches of packets
        // ~~~~~~~~~~~~~~~~~~~~~~~~
        if (customSendMode)
        {
            std::cout << "Sending " << argv[ARG_NUM_PACKAGES] << " packages of " << packetVec.size() << " packets..." << std::endl;
            sender(std::stoi(argv[ARG_NUM_PACKAGES]));
        }
        else
        {
            std::cout << "Sending " << packetVec.size() << " packets..." << std::endl;
            sender();
        }
    }
    else if // capture mode
        (strcmp(argv[ARG_MODE], "capture") == 0)
    {
        // create filter for device using BPF standard
        std::string filter = "";
        if (argc > 4)
        {
            filter = "ether proto 0x1234";
            filter += " and (";
            for (size_t i = 0; i < argc - ARG_REMOTE_MAC; i++)
            {
                filter += "ether src " + pcpp::MacAddress(argv[ARG_REMOTE_MAC + i]).toString();
                if (i < argc - ARG_REMOTE_MAC - 1)
                {
                    filter += " or ";
                }
            }
            filter += " or ether dst ff:ff:ff:ff:ff:ff";
            filter += ")";
        }
        else
        {
            filter = "ether proto 0x1234";
            filter += " and (";
            filter += "ether src " + remote_macAddress.toString();
            filter += " or ether dst ff:ff:ff:ff:ff:ff";
            filter += ")";
        }

        std::cout << "Filter has been set: " << filter << std::endl;

        // Set the filter
        if (!dev->setFilter(filter))
        {
            std::cerr << "Failed to set filter\n";
            return 1;
        }

        // create the stats object
        PacketStats stats;

        std::cout << std::endl
                  << "Starting async capture..." << std::endl;

        // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
        dev->startCapture(onPacketArrives, &stats);

        // sleep for 10 seconds in main thread, in the meantime packets are captured in the async thread
        // pcpp::multiPlatformSleep(10);
        std::cout << "Press any key to stop capture..." << std::endl;
        std::getchar();

        // stop capturing packets
        dev->stopCapture();

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