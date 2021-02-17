#include <stdio.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <iostream>
#include <thread>
#include <pcap.h>
#include <ctime>
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"

std::string g_strPacketPath;
std::string g_strEvilPacketPath;
std::string g_strDebug;
bool stopThread;
bool savePrompt;
bool savePrompt2;
unsigned int g_duration;
unsigned int g_totalPackets;
unsigned int g_ethPacketCount;
unsigned int g_ipv4PacketCount;
unsigned int g_ipv6PacketCount;
unsigned int g_icmpPacketCount;
unsigned int g_tcpPacketCount;
unsigned int g_udpPacketCount;
unsigned int g_dnsPacketCount;
unsigned int g_httpPacketCount;
unsigned int g_sslPacketCount;
unsigned int g_evilPacketCount;
std::vector<unsigned int> g_evilPacketList;

struct PacketStats {
	unsigned int initTime;
	
    PacketStats() { 
	}
	
    void printFirstOutput() {
		initTime = (unsigned int)std::time(0);
        printf("Statistics: \n\n");
        printf("\tTotal packet count:    %i\n", g_totalPackets);
        printf("\tEthernet packet count: %i\n", g_ethPacketCount);
        printf("\tIPv4 packet count:     %i\n", g_ipv4PacketCount);
        printf("\tIPv6 packet count:     %i\n", g_ipv6PacketCount);
        printf("\tICMP packet count:     %i\n", g_icmpPacketCount);
        printf("\tTCP packet count:      %i\n", g_tcpPacketCount);
        printf("\tUDP packet count:      %i\n", g_udpPacketCount);
        printf("\tDNS packet count:      %i\n", g_dnsPacketCount);
        printf("\tHTTP packet count:     %i\n", g_httpPacketCount);
        printf("\tSSL packet count:      %i\n", g_sslPacketCount);
        printf("\tEvil packet count:     %i\n", g_evilPacketCount);
		printf("\t(%i seconds elapsed)\n\n", (unsigned int)std::time(0)-initTime);
		printf("Analyzing packets...\n");
		fflush(stdout);
    }
	
    void printToConsole() {
		g_duration = (unsigned int)std::time(0)-initTime;
        printf("\x1b[14A\tTotal packet count:    %i\n", g_totalPackets);
		printf("\tEthernet packet count: %i\n", g_ethPacketCount);
        printf("\tIPv4 packet count:     %i\n", g_ipv4PacketCount);
        printf("\tIPv6 packet count:     %i\n", g_ipv6PacketCount);
        printf("\tICMP packet count:     %i\n", g_icmpPacketCount);
        printf("\tTCP packet count:      %i\n", g_tcpPacketCount);
        printf("\tUDP packet count:      %i\n", g_udpPacketCount);
        printf("\tDNS packet count:      %i\n", g_dnsPacketCount);
        printf("\tHTTP packet count:     %i\n", g_httpPacketCount);
        printf("\tSSL packet count:      %i\n", g_sslPacketCount);
        printf("\tEvil packet count:     %i\n", g_evilPacketCount);
		printf("\t(%i seconds elapsed)\n\n", g_duration);
		printf("Analyzing packets...\n");
		fflush(stdout);
    }
};

PacketStats stats;

void printThread() {
	stats.printFirstOutput();
	while(!stopThread) {
		stats.printToConsole();
		usleep(100000);
	}
}

int main(int argc, char** argv) {
	g_totalPackets = 0;
	g_duration = 0;
	stopThread = false;
	if(argc < 2) {
		printf("No interface defined.\nAborting.\n");
		return 0;
	}
	std::string strInterface = std::string(*(argv+1));
	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(strInterface);
	
	std::string strTime = std::to_string((unsigned int)std::time(0));
	g_strPacketPath = strTime;
	g_strPacketPath += "_packets.pcap";
	g_strEvilPacketPath = strTime;
	g_strEvilPacketPath += "_evil.pcap";
	
	std::string statpath = strTime;
	statpath += "_statistic.txt";
	
	if (dev == NULL) {
		printf("Failed! Network interface called '%s' could not be found!\n", strInterface.c_str());
		return false;
	}
	if (!dev->open()) {
		printf("Error! Couldn't open network interface '%s'. Did you run as superuser and is the interface up?\n", strInterface.c_str());
		return false;
	}
	
	std::string prompt;
	printf("\033[1m# Save all packets to a pcap file?\033[0m [y/n] ");
	std::getline(std::cin,prompt);
	if(prompt == "y") {
		savePrompt = true;
		printf("Saving enabled.\n");
	} else { 
		savePrompt = false;
		printf("Saving disabled.\n");
	}
	std::string prompt2;
	printf("\033[1m# Save packets containing the evil bit in another seperate file?\033[0m [y/n] ");
	std::getline(std::cin,prompt);
	if(prompt == "y") {
		savePrompt2 = true;
		printf("Saving evil packets to another file aswell.\n");
	} else { 
		savePrompt2 = false;
		printf("Not using an additional file for evil packets.\n");
	}
	
	printf("\nInterface info:\n\n");
	printf("\tInterface name:        %s\n", dev->getName());
	printf("\tInterface description: %s\n", dev->getDesc());
	printf("\tIPv4 address:          %s\n", dev->getIPv4Address().toString().c_str());
	printf("\tMAC address:           %s\n", dev->getMacAddress().toString().c_str());
	printf("\tDefault gateway:       %s\n", dev->getDefaultGateway().toString().c_str());
	printf("\tInterface MTU:         %d\n", dev->getMtu());
	if(dev->getDnsServers().size() > 0)
		printf("\tDNS server:            %s\n", dev->getDnsServers().at(0).toString().c_str());
	
	if(savePrompt) {
		pcpp::PcapFileWriterDevice packetwriter(g_strPacketPath.c_str(), pcpp::LINKTYPE_ETHERNET);
		if(!packetwriter.open()) {
			printf("Error! Couldn't create output pcap file.\n");
			return 0;
		}
		packetwriter.close();
	}
	if(savePrompt2) {
		pcpp::PcapFileWriterDevice packetwriter2(g_strEvilPacketPath.c_str(), pcpp::LINKTYPE_ETHERNET);
		if(!packetwriter2.open()) {
			printf("Error! Couldn't create evil output pcap file.\n");
			return 0;
		}
		packetwriter2.close();
	}
	printf("\nCapturing packets... \033[1;33m(hit [RETURN] to stop capturing and start analyzing)\033[0m\n");
	fflush(stdout);
	pcpp::RawPacketVector packetVec;
	dev->startCapture(packetVec);
	
	std::string dummystr;
    	std::getline(std::cin,dummystr);
	dev->stopCapture();
	std::thread t(printThread);
	
	for(pcpp::RawPacketVector::ConstVectorIterator iter = packetVec.begin(); iter != packetVec.end(); iter++) {
		bool isEvil = false;
		pcpp::Packet parsedPacket(*iter);
		g_totalPackets++;
		if(parsedPacket.isPacketOfType(pcpp::Ethernet)) g_ethPacketCount++;
		if(parsedPacket.isPacketOfType(pcpp::IPv4)) {
			g_ipv4PacketCount++;
			pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if(ipLayer == NULL) {
				//failed to open layer
			} else {
				unsigned short fragmentoff = ipLayer->getIPv4Header()->fragmentOffset;
				if(((fragmentoff << 8) >> 15) == 1) {
					isEvil = true;
					g_evilPacketCount++;
					g_evilPacketList.push_back(g_totalPackets);
				}
			}
		}
		if(parsedPacket.isPacketOfType(pcpp::IPv6)) g_ipv6PacketCount++;
		if(parsedPacket.isPacketOfType(pcpp::ICMP)) g_icmpPacketCount++;
		if(parsedPacket.isPacketOfType(pcpp::TCP)) g_tcpPacketCount++;
		if(parsedPacket.isPacketOfType(pcpp::UDP)) g_udpPacketCount++;
		if(parsedPacket.isPacketOfType(pcpp::HTTP)) g_httpPacketCount++;
		if(parsedPacket.isPacketOfType(pcpp::SSL)) g_sslPacketCount++;

		if(savePrompt) {
			pcpp::PcapFileWriterDevice write(g_strPacketPath.c_str(), pcpp::LINKTYPE_ETHERNET);
			if(!write.open(true)) {
				printf("Error! Couldn't open output pcap file.\n");
				exit(0);
			}
			write.writePacket(**iter);
			write.close();
		}
		if(savePrompt2 && isEvil) {
			pcpp::PcapFileWriterDevice write2(g_strEvilPacketPath.c_str(), pcpp::LINKTYPE_ETHERNET);
			if(!write2.open(true)) {
				printf("Error! Couldn't open output pcap file.\n");
				exit(0);
			}
			write2.writePacket(**iter);
			write2.close();
		}
		isEvil = false;
	}
	std::ofstream statfile;
	stopThread = true;
	t.join();


	statfile.open(statpath);
	statfile << "Total packet count:    " << g_totalPackets << ")\n";
	statfile << "Duration: " << g_duration << " seconds\n\n";
	statfile << "Ethernet packet count: " << g_ethPacketCount << "\n";
	statfile << "IPv4 packet count:     " << g_ipv4PacketCount << "\n";
	statfile << "IPv6 packet count:     " << g_ipv6PacketCount << "\n";
	statfile << "ICMP packet count:     " << g_icmpPacketCount << "\n";
	statfile << "TCP packet count:      " << g_tcpPacketCount << "\n";
	statfile << "UDP packet count:      " << g_udpPacketCount << "\n";
	statfile << "DNS packet count:      " << g_dnsPacketCount << "\n";
	statfile << "HTTP packet count:     " << g_httpPacketCount << "\n";
	statfile << "SSL packet count:      " << g_sslPacketCount << "\n\n";
	statfile << "Evil packet count:     " << g_evilPacketCount << "\n";
	statfile << "List of evil packets:\n";
	for(auto i = std::begin(g_evilPacketList); i != std::end(g_evilPacketList)-1; i++) {
		statfile << "\tFrame " << *i << "\n";
	}
	
	statfile.close();	
	if(savePrompt) printf("Saved %i packets to '%s'.\n", packetVec.size(), g_strPacketPath.c_str());
	if(savePrompt2) printf("Saved %i evil packets to '%s'.\n", g_evilPacketCount, g_strEvilPacketPath.c_str());
	
	printf("Saved statistics to '%s'.\n", statpath.c_str());
	printf("Done.\n");
	return 0;
}
