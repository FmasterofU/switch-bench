#include <iostream>
#include "stdlib.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"

int main(int argc, char* argv[])
{
	// Packet Creation
	// ~~~~~~~~~~~~~~~

	// create a new Ethernet layer
	pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));


	// create a packet with initial capacity of 100 bytes (will grow automatically if needed)
	pcpp::Packet newPacket(100);

	// add all the layers we created
	newPacket.addLayer(&newEthernetLayer);

	// compute all calculated fields
	newPacket.computeCalculateFields();





    // IPv4 address of the interface we want to sniff
	std::string interfaceIPAddr = "10.100.0.145";

	// find the interface by IP address
    pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
	if (dev == nullptr)
	{
		std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
		return 1;
	}


    // Get device info
	// ~~~~~~~~~~~~~~~

	// before capturing packets let's print some info about this interface
	std::cout
		<< "Interface info:" << std::endl
		<< "   Interface name:        " << dev->getName() << std::endl // get interface name
		<< "   Interface description: " << dev->getDesc() << std::endl // get interface description
		<< "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
		<< "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
		<< "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU



    // open the device before start capturing/sending packets
	if (!dev->open())
	{
		std::cerr << "Cannot open device" << std::endl;
		return 1;
	}

    // Sending single packets
	// ~~~~~~~~~~~~~~~~~~~~~~

    pcpp::RawPacketVector packetVec;
    packetVec.pushBack(newPacket.getRawPacket());

	std::cout << std::endl << "Sending " << packetVec.size() << " packets one by one..." << std::endl;

	// go over the vector of packets and send them one by one
	for (pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++)
	{
		// send the packet. If fails exit the application
		if (!dev->sendPacket(**iter))
		{
			std::cerr << "Couldn't send packet" << std::endl;
			return 1;
		}
	}
	std::cout << packetVec.size() << " packets sent" << std::endl;
/*

	// Sending batch of packets
	// ~~~~~~~~~~~~~~~~~~~~~~~~

	std::cout << std::endl << "Sending " << packetVec.size() << " packets..." << std::endl;

	// send all packets in the vector. The returned number shows how many packets were actually sent (expected to be equal to vector size)
	int packetsSent = dev->sendPackets(packetVec);

	std::cout << packetsSent << " packets sent" << std::endl;
*/
}