#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <random>
#include <sstream>
#include <string>
#include <iostream>
#include <fstream>
#include <thread>
#include <cstdlib>
#include <pcap.h>
#include <ctime>
#include <signal.h>
#include "oLib/Utils.h"
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"

#define MAX_COMMAND_SIZE 120

//Author: Oliver Keil

Utils g_utils;

int g_u32iDstIpAt;
int g_u32iInterfaceAt;
int g_u32iSrcIpAt;
int g_u32iLegAt;
int g_u32iDelayAt;
int g_u32iDstMacAt;
int g_u32iLegPcapAt;
int g_u32iMalPcapAt;
int g_u32iUseDistAt;
int g_u32iLoadConfigAt;
int g_u32iUseTimestampsAt;
int g_u32iLoopAt;
int g_u32iLegMbpsAt;
int g_u32iMalMbpsAt;
int g_s32iLegMbps;
int g_s32iMalMbps;
int g_s32iLoop;
std::string g_strLegPcap;
std::string g_strMalPcap;
std::string g_strSrcIP;
std::string g_strDstIP;
std::string g_strDstMAC;
bool g_bUseDist;
bool g_bUseTimestamps;
bool g_bLoadConf;
char** g_newargv;
unsigned int g_u32iNewargc;
timespec g_initTimestamp;

int g_u32iDelayAmount;
char g_cDelayType;
std::string g_strComStrMal;
std::string g_strComStrLeg;
std::string g_strInterface;
std::string g_strConfigPath;

// in-program params
bool g_bRewriteLegTrafficIP;
bool g_bRewriteMalTrafficIP;
bool g_bSetEvilBit;
bool g_bBernoulliPrompt;
unsigned int g_u32iBernoulliPerc;
std::string g_strBernoulliSeed;

//distribution for mal source addresses
bool g_bStandardPrompt;
std::string g_strStandardCIDR;
std::string g_strStandardLow;
std::string g_strStandardHigh;
unsigned int g_u32iStandardMean;
std::string g_strStandardMeanIP;
unsigned int g_u32iStandardDev;
std::string g_strStandardSeed;

//distribution for leg source addresses
bool g_bStandardLegSrcPrompt;
std::string g_strStandardLegSrcCIDR;
std::string g_strStandardLegSrcLow;
std::string g_strStandardLegSrcHigh;
unsigned int g_u32iStandardLegSrcMean;
std::string g_strStandardLegSrcMeanIP;
unsigned int g_u32iStandardLegSrcDev;
std::string g_strStandardLegSrcSeed;

//distribution for mal dst addresses
bool g_bStandardMalDstPrompt;
std::string g_strStandardMalDstCIDR;
std::string g_strStandardMalDstLow;
std::string g_strStandardMalDstHigh;
unsigned int g_u32iStandardMalDstMean;
std::string g_strStandardMalDstMeanIP;
unsigned int g_u32iStandardMalDstDev;
std::string g_strStandardMalDstSeed;

//distribution for leg dst addresses
bool g_bStandardLegDstPrompt;
std::string g_strStandardLegDstCIDR;
std::string g_strStandardLegDstLow;
std::string g_strStandardLegDstHigh;
unsigned int g_u32iStandardLegDstMean;
std::string g_strStandardLegDstMeanIP;
unsigned int g_u32iStandardLegDstDev;
std::string g_strStandardLegDstSeed;

std::string g_stdstrType;

std::thread legT;
std::vector<pcpp::RawPacket> sendVector;

void legitTraffic() {
    if(g_u32iLegPcapAt != -1) {
        system(g_strComStrLeg.c_str());
    }
}

void countdown(unsigned int p_seconds) {
    for(; p_seconds > 0; p_seconds--) {
        std::cout << p_seconds << std::flush; usleep(333333); std::cout << "." << std::flush; usleep(333333); std::cout << ". " << std::flush; usleep(333333);
    }
}

unsigned int ipstringtointeger(std::string p_ipstring) {
    struct in_addr addr;
    int res = inet_pton(AF_INET, p_ipstring.c_str(), &(addr));
    return *((uint32_t*)&(addr));
}

uint32_t changeEndianness32(uint32_t val) {
    return (val << 24) | ((val <<  8) & 0x00ff0000) | ((val >>  8) & 0x0000ff00) | ((val >> 24) & 0x000000ff);
}

char createCombinedPcap(std::string p_strLeg, std::string p_strMal, unsigned int p_u32iRatio, std::string p_strSeed, char** p_argv) {
	printf("Preparing combined traffic (stopping after one file ends)...\n");
	//turn ratio into decimal between 0 and 1
	double ratio = p_u32iRatio/100.d;
	
	//do bernoulli stuff and write mal packet if true, leg packet if false
    std::default_random_engine generator;
	std::seed_seq bernoulliseed(p_strSeed.begin(),p_strSeed.end());
    generator.seed(bernoulliseed);
    std::bernoulli_distribution distribution(ratio);
	
	pcpp::IFileReaderDevice* legreader = pcpp::IFileReaderDevice::getReader("pcap/send_leg.pcap");
	pcpp::IFileReaderDevice* malreader = pcpp::IFileReaderDevice::getReader("pcap/send_mal.pcap");
	pcpp::PcapFileWriterDevice writer("pcap/send_combined.pcap", pcpp::LINKTYPE_ETHERNET);

	if(legreader == NULL) {
		printf("\033[1;31mCannot determine reader for good traffic\033\0m\n");
		return 0x01;
	}
	if(malreader == NULL) {
		printf("\033[1;31mCannot determine reader for malicious traffic\033\0m\n");
		return 0x02;
	}
	if(!legreader->open()) {
		printf("\033[1;31mCannot open good pcap file for reading\033\0m\n");
		return 0x03;
	}
	if(!malreader->open()) {
		printf("\033[1;31mCannot open malicious pcap file for reading\033\0m\n");
		return 0x04;
	}
	if(!writer.open()) {
		printf("\033[1;31mCannot create/open output pcap file for writing\033\0m\n");
		return 0x05;
	}
	unsigned int packetcounter = 1;
	unsigned int count = 0;
	unsigned int anticount = 0;
	pcpp::RawPacket rawPacket;
	
	bool done = false;
	while(!done) {
        if(distribution(generator)) { //true -> malicious
			if(malreader->getNextPacket(rawPacket)) {
				writer.writePacket(rawPacket);
            	count++;
			} else {
				done = true;
			}
        } else { //false -> legit
			if(legreader->getNextPacket(rawPacket)) {
				writer.writePacket(rawPacket);
            	anticount++;
			} else {
				done = true;
			}
        }
	}
	writer.close();
	legreader->close();
	malreader->close();

	//done
	printf("\033[0;32mSuccessfully created the combined pcap file based on the given bernoulli distribution:\n");
	printf("\tPercentage: %f\n\tSeed: %s\n\tGood packets written:  %i\n\tEvil packets written:  %i\n\tTotal packets written: %i\033[0m\n\n", ratio, p_strSeed.c_str(), anticount, count, anticount+count);
	return 0x00;
}

char createLegPcap(char** p_argv) {
	std::string rewriteprompt;
	if(g_u32iLegPcapAt != -1) {
		if(!g_bLoadConf) {
			std::cout << "\033[1m# Rewrite good traffic with given parameters? \n(The file you provided will be untouched. A new modified file would be created.)\033[0m [y/n] ";
			std::getline(std::cin, rewriteprompt);
		}
		if(rewriteprompt == "y" || g_bRewriteLegTrafficIP) {
			printf("Preparing good traffic...\n");
			g_bRewriteLegTrafficIP = true;
			pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(g_strLegPcap.c_str());
			pcpp::PcapFileWriterDevice writer("pcap/send_leg.pcap", pcpp::LINKTYPE_ETHERNET);

			if(reader == NULL) {
				printf("\033[1;31mCannot determine reader for good traffic pcap file\033\0m\n");
				return 0;
			}
			if(!reader->open()) {
				printf("\033[1;31mCannot open input pcap file for reading\033\0m\n");
				return 0;
			}
			if(!writer.open()) {
				printf("\033[1;31mCannot create/open output pcap file for writing\033\0m\n");
				return 0;
			}
			unsigned int failcounter = 0;
			unsigned int packetcounter = 1;
			bool failed = false;
			pcpp::RawPacket rawPacket;
			
			//NORMAL DIST
			unsigned int lowipsrc;
			unsigned int highipsrc;
			unsigned int meanipsrc;
			unsigned int iprangesrc;
			unsigned int lowipdst;
			unsigned int highipdst;
			unsigned int meanipdst;
			unsigned int iprangedst;
			if(g_bUseDist && g_bStandardLegSrcPrompt) {
				lowipsrc = changeEndianness32(ipstringtointeger(g_strStandardLegSrcLow));
				highipsrc = changeEndianness32(ipstringtointeger(g_strStandardLegSrcHigh));
				meanipsrc = changeEndianness32(ipstringtointeger(g_strStandardLegSrcMeanIP));
				iprangesrc = highipsrc-lowipsrc;
			}
			std::default_random_engine stangeneratorsrc;
			std::normal_distribution<double> standistributionsrc((double)meanipsrc,(double)g_u32iStandardLegSrcDev);
			std::seed_seq actualstandardseedsrc(g_strStandardLegSrcSeed.begin(),g_strStandardLegSrcSeed.end());
			stangeneratorsrc.seed(actualstandardseedsrc);
			
			if(g_bUseDist && g_bStandardLegDstPrompt) {
				lowipdst = changeEndianness32(ipstringtointeger(g_strStandardLegDstLow));
				highipdst = changeEndianness32(ipstringtointeger(g_strStandardLegDstHigh));
				meanipdst = changeEndianness32(ipstringtointeger(g_strStandardLegDstMeanIP));
				iprangedst = highipdst-lowipdst;
			}
			std::default_random_engine stangeneratordst;
			std::normal_distribution<double> standistributiondst((double)meanipdst,(double)g_u32iStandardLegDstDev);
			std::seed_seq actualstandardseeddst(g_strStandardLegDstSeed.begin(),g_strStandardLegDstSeed.end());
			stangeneratordst.seed(actualstandardseeddst);

			while(reader->getNextPacket(rawPacket)) {
				failed = false;
				pcpp::Packet parsedPacket(&rawPacket);
				pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
				if(ipLayer == NULL) {
					failcounter++;
					failed = true;
					//printf("ERROR (Packet %i): IPv4 Layer could not be found.\n",packetcounter);
					//return 0;
				} else {
					ipLayer->getIPv4Header()->ipDst = ipstringtointeger(g_strDstIP);
					if(g_u32iSrcIpAt != -1) {
						ipLayer->getIPv4Header()->ipSrc = ipstringtointeger(g_strSrcIP);
					}
					if(g_bUseDist && g_bStandardLegSrcPrompt) {
						//NORMAL DISTRIBUTION
						unsigned int newipsrc = (unsigned int)standistributionsrc(stangeneratorsrc);
						while(newipsrc < lowipsrc || newipsrc > highipsrc) newipsrc = (unsigned int)standistributionsrc(stangeneratorsrc);
						ipLayer->getIPv4Header()->ipSrc = changeEndianness32(newipsrc);
					}
					if(g_bUseDist && g_bStandardLegDstPrompt) {
						//NORMAL DISTRIBUTION
						unsigned int newipdst = (unsigned int)standistributiondst(stangeneratordst);
						while(newipdst < lowipdst || newipdst > highipdst) newipdst = (unsigned int)standistributiondst(stangeneratordst);
						ipLayer->getIPv4Header()->ipDst = changeEndianness32(newipdst);
					}
				}
				pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
				if(ethernetLayer == NULL) {
					//printf("ERROR (Packet %i): Ethernet Layer could not be found.\n",packetcounter);
					if(!failed) {
						failcounter++;
						failed = true;
					}
				} else {
					ethernetLayer->setDestMac(pcpp::MacAddress(g_strDstMAC.c_str()));
				}
				if(!failed) writer.writePacket(rawPacket);
				packetcounter++;
			}
			if(failcounter > 0) {
				printf("\033[1;31m\tExperienced an error at %i of %i packets.\n\t\033[1;33mYou can still continue, \n\tbut the file to be sent consists of %i packets instead of %i now.\033[0m\n", failcounter, packetcounter-1, packetcounter-failcounter-1, packetcounter-1);
			}
			writer.close();
			reader->close();

			//done
			printf("\033[0;32mGood Traffic Rewritten (%i packets).\033[0m\n\n", packetcounter-1-failcounter);
		} else {
			g_bRewriteLegTrafficIP = false;
			std::string legcopystring = "cp ";
			legcopystring += g_strLegPcap;
			legcopystring += " pcap/send_leg.pcap";
			system(legcopystring.c_str());
			printf("Provided legitimate PCAP file was not edited.\n");
		}
	} else { //leg pcap was not defined, wont send any leg traffic

	}
	return 0x00;
}

char createMalPcap(char** p_argv) {
	std::string rewriteprompt;
	if(!g_bLoadConf) {
		std::cout << "\033[1m# Rewrite evil traffic with given parameters? \n(The input file itself will not change. A new modified file would be created.)\033[0m [y/n] ";
		std::getline(std::cin, rewriteprompt);
	}
	if(rewriteprompt == "y" || g_bRewriteMalTrafficIP) {
		printf("Preparing malicious traffic...\n");
		g_bRewriteMalTrafficIP = true;
		std::string rewriteprompt2;

		if(!g_bLoadConf) {
			std::cout << "\033[1m# Also set the evil bit to mark the evil traffic?\033[0m [y/n] ";
			std::getline(std::cin, rewriteprompt2);
		}
		pcpp::IFileReaderDevice* mreader = pcpp::IFileReaderDevice::getReader(g_strMalPcap.c_str());
		pcpp::PcapFileWriterDevice mwriter("pcap/send_mal.pcap", pcpp::LINKTYPE_ETHERNET);
		if(rewriteprompt2 == "y") g_bSetEvilBit = true;

		if(mreader == NULL) {
			printf("\033[1;31mCannot determine reader for malicious traffic pcap file\033\0m\n");
			return 0;
		}
		if(!mreader->open()) {
			printf("\033[1;31mCannot open input pcap file for reading\033\0m\n");
			return 0;
		}
		if(!mwriter.open()) {
			printf("\033[1;31mCannot create/open output pcap file for writing\033\0m\n");
			return 0;
		}
		unsigned int failcounter = 0;
		unsigned int packetcounter = 1;
		bool failed = false;
		pcpp::RawPacket rawPacket;

		//NORMAL DIST
		unsigned int lowipsrc;
		unsigned int highipsrc;
		unsigned int meanipsrc;
		unsigned int iprangesrc;
		unsigned int lowipdst;
		unsigned int highipdst;
		unsigned int meanipdst;
		unsigned int iprangedst;
		if(g_bUseDist && g_bStandardPrompt) {
			lowipsrc = changeEndianness32(ipstringtointeger(g_strStandardLow));
			highipsrc = changeEndianness32(ipstringtointeger(g_strStandardHigh));
			meanipsrc = changeEndianness32(ipstringtointeger(g_strStandardMeanIP));
			iprangesrc = highipsrc-lowipsrc;
		}
		std::default_random_engine stangeneratorsrc;
		std::normal_distribution<double> standistributionsrc((double)meanipsrc,(double)g_u32iStandardDev);
		std::seed_seq actualstandardseedsrc(g_strStandardSeed.begin(),g_strStandardSeed.end());
		stangeneratorsrc.seed(actualstandardseedsrc);

		if(g_bUseDist && g_bStandardMalDstPrompt) {
			lowipdst = changeEndianness32(ipstringtointeger(g_strStandardMalDstLow));
			highipdst = changeEndianness32(ipstringtointeger(g_strStandardMalDstHigh));
			meanipdst = changeEndianness32(ipstringtointeger(g_strStandardMalDstMeanIP));
			iprangedst = highipdst-lowipdst;
		}
		std::default_random_engine stangeneratordst;
		std::normal_distribution<double> standistributiondst((double)meanipdst,(double)g_u32iStandardMalDstDev);
		std::seed_seq actualstandardseeddst(g_strStandardMalDstSeed.begin(),g_strStandardMalDstSeed.end());
		stangeneratordst.seed(actualstandardseeddst);

		while(mreader->getNextPacket(rawPacket)) {
			failed = false;
			pcpp::Packet parsedPacket(&rawPacket);
			pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if(ipLayer == NULL) {
				failcounter++;
				failed = true;
			} else {
				if(g_bSetEvilBit) ipLayer->getIPv4Header()->fragmentOffset |= 128;
				ipLayer->getIPv4Header()->ipDst = ipstringtointeger(g_strDstIP);
				if(g_u32iSrcIpAt != -1) {
					ipLayer->getIPv4Header()->ipSrc = ipstringtointeger(g_strSrcIP);
				}
				if(g_bUseDist && g_bStandardPrompt) {
					//NORMAL DISTRIBUTION
					unsigned int newipsrc = (unsigned int)standistributionsrc(stangeneratorsrc);
					while(newipsrc < lowipsrc || newipsrc > highipsrc) newipsrc = (unsigned int)standistributionsrc(stangeneratorsrc);
					ipLayer->getIPv4Header()->ipSrc = changeEndianness32(newipsrc);
				}
				if(g_bUseDist && g_bStandardMalDstPrompt) {
					//NORMAL DISTRIBUTION
					unsigned int newipdst = (unsigned int)standistributiondst(stangeneratordst);
					while(newipdst < lowipdst || newipdst > highipdst) newipdst = (unsigned int)standistributiondst(stangeneratordst);
					ipLayer->getIPv4Header()->ipDst = changeEndianness32(newipdst);
				}
			}
			pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
			if(ethernetLayer == NULL) {
				//printf("ERROR (Packet %i): Ethernet Layer could not be found.\n",packetcounter);
				if(!failed) {
					failcounter++;
					failed = true;
					//printf("ERROR (Packet %i): Ethernet Layer could not be found.\n",packetcounter);
				} else {
					failcounter++;
					//printf("ERROR (Packet %i): Both IPv4 and Ethernet Layers could not be found.\n",packetcounter);
				}
			} else {
				ethernetLayer->setDestMac(pcpp::MacAddress(g_strDstMAC.c_str()));
				if(failed) {
					//printf("ERROR (Packet %i): IPv4 Layer could not be found.\n",packetcounter);
				}
			}
			if(!failed) mwriter.writePacket(rawPacket);
			packetcounter++;
		}
		if(failcounter > 0) {
			printf("\033[1;31m\tExperienced an error at %i of %i packets.\n\t\033[1;33mYou can still continue, \n\tbut the file to be sent consists of %i packets instead of %i now.\033[0m\n", failcounter, packetcounter-1, packetcounter-failcounter-1, packetcounter-1);
		}
		mwriter.close();
		mreader->close();

		//done
		printf("\033[0;32mMalicious Traffic Rewritten (%i packets).\033[0m\n\n", packetcounter-1-failcounter);
	} else { //rewriteprompt == n
		g_bRewriteMalTrafficIP = false;
		std::string malcopystring = "cp ";
		malcopystring += g_strMalPcap;
		malcopystring += " pcap/send_mal.pcap";
		system(malcopystring.c_str());
		printf("Using the file without applying any changes.\n");
	}
	return 0x00;
}

bool sendTraffic(char** p_argv) {
	std::string sendstring = "tcpreplay ";
	if(g_u32iLoopAt != -1) {
		sendstring += "--loop=";
		if(g_bLoadConf) sendstring += std::string(*(g_newargv+g_u32iLoopAt+1));
		else sendstring += std::string(*(p_argv+g_u32iLoopAt+1));
	} else sendstring += "--loop=0";
	sendstring += " --preload-pcap ";
	if(g_u32iMalMbpsAt != -1) {
		sendstring += "--mbps=";
		if(g_bLoadConf) sendstring += std::string(*(g_newargv+g_u32iMalMbpsAt+1));
		else sendstring += std::string(*(p_argv+g_u32iMalMbpsAt+1));
		sendstring += " ";
	}
	if(!g_bUseTimestamps && g_u32iMalMbpsAt == -1) sendstring += "--topspeed ";
	sendstring += "-i ";
	if(g_bLoadConf) sendstring += std::string(*(g_newargv+g_u32iInterfaceAt+1));
	else sendstring += std::string(*(p_argv+g_u32iInterfaceAt+1));
	if(g_u32iLegPcapAt != -1 && g_bBernoulliPrompt) { //send send_combined.pcap
		sendstring += " pcap/send_combined.pcap";
	} else if(g_u32iLegPcapAt != -1) { //send defined leg and default mal traffic at top speed
		g_strComStrLeg = "tcpreplay --loop=0 --preload-pcap ";
		if(g_u32iLegMbpsAt != -1) {
			sendstring += "--mbps=";
			if(g_bLoadConf) sendstring += std::string(*(g_newargv+g_u32iLegMbpsAt+1));
			else sendstring += std::string(*(p_argv+g_u32iLegMbpsAt+1));
			sendstring += " ";
		}
		if(!g_bUseTimestamps && g_u32iLegMbpsAt == -1) g_strComStrLeg += "--topspeed ";
		g_strComStrLeg += "-i ";
		if(g_bLoadConf) g_strComStrLeg += std::string(*(g_newargv+g_u32iInterfaceAt+1));
		else sendstring += std::string(*(p_argv+g_u32iMalMbpsAt+1));
		g_strComStrLeg += " pcap/send_leg.pcap";
		sendstring += " pcap/send_mal.pcap";
		legT = std::thread(legitTraffic);
	} else { //just send the mal traffic at top speed
		sendstring += " pcap/send_mal.pcap";
	}
	
	if(g_u32iDelayAt != -1 && g_u32iLegPcapAt != -1 && g_bUseDist) {
		printf("Waiting for %i seconds...\n", g_u32iDelayAt);
		sleep(g_u32iDelayAmount);
		printf("Done. Sending evil traffic, too.\n");
	}
	system(sendstring.c_str());
	return true;
}

std::string getConfigValue(std::vector<std::string> p_config, std::string p_for) {
	for(unsigned int i = 0; i < p_config.size(); i++) {
		if(p_config[i].find(p_for) != std::string::npos) {
			char* tempstr = (char*)p_config[i].c_str();
			tempstr += p_for.length() + 3;
			return std::string(tempstr);
		}
	}
	printf("\033[1;31mCould'nt find '%s'. Aborting.\033\0m\n", p_for.c_str());
	exit(0);
}

bool loadconfig(std::string p_strPath) {
	std::ifstream configFile(p_strPath);
	std::vector<std::string> parsedConfig;
	std::string curline;
	//printf("Iteration 1:\n");
	while(std::getline(configFile,curline)) {
		//printf("%s\n", curline.c_str());
		parsedConfig.push_back(curline);
	}
	std::string arguments = getConfigValue(parsedConfig, "Arguments");
	//printf("args: %s", arguments.c_str());
	g_bRewriteLegTrafficIP = (getConfigValue(parsedConfig, "RewriteGoodDstIP") == "y")?true:false;
	g_bRewriteMalTrafficIP = (getConfigValue(parsedConfig, "RewriteEvilDstIP") == "y")?true:false;
	g_bSetEvilBit = (getConfigValue(parsedConfig, "SetEvilBit") == "y")?true:false;
	g_bBernoulliPrompt = (getConfigValue(parsedConfig, "UseBernoulli") == "y")?true:false;
	if(g_bBernoulliPrompt) {
		g_u32iBernoulliPerc = stoi(getConfigValue(parsedConfig, "BernoulliPerc"));
		g_strBernoulliSeed = getConfigValue(parsedConfig, "BernoulliSeed");
	}
	g_bStandardPrompt = (getConfigValue(parsedConfig, "UseStandardMalSrc") == "y")?true:false;
	if(g_bStandardPrompt) {
		g_strStandardLow = getConfigValue(parsedConfig, "StanLowIPMalSrc");
		g_strStandardHigh = getConfigValue(parsedConfig, "StanHighIPMalSrc");
		g_strStandardMeanIP = getConfigValue(parsedConfig, "StanMeanIPMalSrc");
		g_u32iStandardDev = stoi(getConfigValue(parsedConfig, "StanDevMalSrc"));
		g_strStandardSeed = getConfigValue(parsedConfig, "StanSeedMalSrc");
	}
	g_bStandardMalDstPrompt = (getConfigValue(parsedConfig, "UseStandardMalDst") == "y")?true:false;
	if(g_bStandardMalDstPrompt) {
		g_strStandardMalDstLow = getConfigValue(parsedConfig, "StanLowIPMalDst");
		g_strStandardMalDstHigh = getConfigValue(parsedConfig, "StanHighIPMalDst");
		g_strStandardMalDstMeanIP = getConfigValue(parsedConfig, "StanMeanIPMalDst");
		g_u32iStandardMalDstDev = stoi(getConfigValue(parsedConfig, "StanDevMalDst"));
		g_strStandardMalDstSeed = getConfigValue(parsedConfig, "StanSeedMalDst");
	}
	g_bStandardLegSrcPrompt = (getConfigValue(parsedConfig, "UseStandardLegSrc") == "y")?true:false;
	if(g_bStandardLegSrcPrompt) {
		g_strStandardLegSrcLow = getConfigValue(parsedConfig, "StanLowIPLegSrc");
		g_strStandardLegSrcHigh = getConfigValue(parsedConfig, "StanHighIPLegSrc");
		g_strStandardLegSrcMeanIP = getConfigValue(parsedConfig, "StanMeanIPLegSrc");
		g_u32iStandardLegSrcDev = stoi(getConfigValue(parsedConfig, "StanDevLegSrc"));
		g_strStandardLegSrcSeed = getConfigValue(parsedConfig, "StanSeedLegSrc");
	}
	g_bStandardLegDstPrompt = (getConfigValue(parsedConfig, "UseStandardLegDst") == "y")?true:false;
	if(g_bStandardLegDstPrompt) {
		g_strStandardLegDstLow = getConfigValue(parsedConfig, "StanLowIPLegDst");
		g_strStandardLegDstHigh = getConfigValue(parsedConfig, "StanHighIPLegDst");
		g_strStandardLegDstMeanIP = getConfigValue(parsedConfig, "StanMeanIPLegDst");
		g_u32iStandardLegDstDev = stoi(getConfigValue(parsedConfig, "StanDevLegDst"));
		g_strStandardLegDstSeed = getConfigValue(parsedConfig, "StanSeedLegDst");
	}
	g_newargv = (char**)malloc(arguments.size()+1);
	
	//split string
	std::vector<std::string> newargvect;
	std::stringstream argstream(arguments);
    std::string word;
    while(std::getline(argstream, word, ' ')) {
        newargvect.push_back(word);
    }
	
	g_u32iNewargc = newargvect.size();
	for(unsigned int i = 0; i < newargvect.size(); i++) {
		*(g_newargv+i) = (char*)malloc(newargvect[i].size()+1);
		*(*(g_newargv+i)+newargvect[i].size()) = '\0';
		memcpy(*(g_newargv+i), newargvect[i].c_str(), newargvect[i].size());
	}
	
	return true;
}

//args
bool parseArgs(int p_argc, char** p_argv) {
    printf("Validating the arguments for syntax...\n");
    if(g_u32iLoadConfigAt != -1) {
		if(!g_utils.file_exists(*(p_argv+g_u32iLoadConfigAt+1))) {
			std::cout << "\033[1;31mFile " << *(p_argv+g_u32iLoadConfigAt+1) << " could not be found. Aborting.\033[0m" << std::endl;
			return false;
		} else {
			std::cout << "Loading configuration from " << *(p_argv+g_u32iLoadConfigAt+1) << "..." << std::endl;
			bool configresult = loadconfig(std::string(*(p_argv+g_u32iLoadConfigAt+1)));
			if(configresult) {
				printf("\033[0;32mConfiguration loaded successfully.\033[0m\n");
				g_u32iInterfaceAt = g_utils.findstr("-interface", g_newargv, g_u32iNewargc);
				g_u32iDstIpAt = g_utils.findstr("-dstip", g_newargv, g_u32iNewargc);
				g_u32iLegAt = g_utils.findstr("-leg", g_newargv, g_u32iNewargc);
				g_u32iSrcIpAt = g_utils.findstr("-srcip", g_newargv, g_u32iNewargc);
				g_u32iDelayAt = g_utils.findstr("-startupdelay", g_newargv, g_u32iNewargc);
				g_u32iLegPcapAt = g_utils.findstr("-legpcap", g_newargv, g_u32iNewargc);
				g_u32iMalPcapAt = g_utils.findstr("-malpcap", g_newargv, g_u32iNewargc);
				g_u32iDstMacAt = g_utils.findstr("-dstmac", g_newargv, g_u32iNewargc);
				g_u32iUseDistAt = g_utils.findstr("-usedistribution", g_newargv, g_u32iNewargc);
				g_u32iUseTimestampsAt = g_utils.findstr("-usetimestamps", g_newargv, g_u32iNewargc);
				g_u32iLegMbpsAt = g_utils.findstr("-legmbps", g_newargv, g_u32iNewargc);
				g_u32iMalMbpsAt = g_utils.findstr("-malmbps", g_newargv, g_u32iNewargc);
				g_u32iLoopAt = g_utils.findstr("-loop", g_newargv, g_u32iNewargc);
				p_argv = g_newargv;
				p_argc = g_u32iNewargc;
			} else {
				printf("\033[1;31mFailed to load configuration. Aborting.\033\0m\n");
				return 0;
			}
		}
	}
	//legpcap file
	if(g_u32iLegPcapAt != -1) {
		if(!g_utils.file_exists(*(p_argv+g_u32iLegPcapAt+1))) {
			std::cout << "\033[1;31mFile " << *(p_argv+g_u32iLegPcapAt+1) << " could not be found. Aborting.\033[0m" << std::endl;
			return false;
		} else {
			std::cout << "\033[0;32mFile for good traffic: " << *(p_argv+g_u32iLegPcapAt+1) << "\033[0m" << std::endl;
			g_strLegPcap = std::string(*(p_argv+g_u32iLegPcapAt+1));
		}
	}

	//malpcap file
	if(g_u32iMalPcapAt != -1) {
		if(!g_utils.file_exists(*(p_argv+g_u32iMalPcapAt+1))) {
			std::cout << "\033[1;31mFile " << *(p_argv+g_u32iMalPcapAt+1) << " could not be found. Aborting.\033[0m" << std::endl;
			return false;
		} else {
			std::cout << "\033[0;32mFile for malicious traffic: " << *(p_argv+g_u32iMalPcapAt+1) << "\033[0m" << std::endl;
			g_strMalPcap = std::string(*(p_argv+g_u32iMalPcapAt+1));
		}
	} else {
		if(!g_utils.file_exists("./pcap/SYN.pcap")) {
			std::cout << "\033[1;31mDefault malicious pcap file (./pcap/SYN.pcap) could not be found. \nThis usually ships with the program. Did you delete it?\nYou could also use a custom pcap file with the '-malpcap' option.\nAborting.\033[0m" << std::endl;
			return false;
		} else {
			std::cout << "\033[0;32mNo file for malicious traffic provided. Using default: ./pcap/SYN.pcap\033[0m" << std::endl;
			g_strMalPcap = "./pcap/SYN.pcap";
		}
	}

	//parse Dst IP
	struct sockaddr_in address;
	int validdstip = inet_pton(AF_INET, *(p_argv+g_u32iDstIpAt+1), &(address.sin_addr));
	if(validdstip != 1) {
		std::cout << "DSTIP invalid." << std::endl;
		return false;
	}
	g_strDstIP = std::string(*(p_argv+g_u32iDstIpAt+1));
	std::cout << "\033[0;32mDestination IP Address: " << *(p_argv+g_u32iDstIpAt+1) << "\033[0m" << std::endl;

	//parse dstmac
	if(g_u32iDstMacAt != -1) {
		g_strDstMAC = std::string(*(p_argv+g_u32iDstMacAt+1));
		std::cout << "\033[0;32mDestination MAC Address: " << g_strDstMAC << "\033[0m" << std::endl;
	}

	//parse srcip
	if(g_u32iSrcIpAt != -1) {
		int validsrcip = inet_pton(AF_INET, *(p_argv+g_u32iSrcIpAt+1), &(address.sin_addr));
		if(validsrcip != 1) {
			std::cout << "SRCIP invalid." << std::endl;
			return false;
		}
		g_strSrcIP = std::string(*(p_argv+g_u32iSrcIpAt+1));
		std::cout << "\033[0;32mSource IP Address: " << *(p_argv+g_u32iSrcIpAt+1) << "\033[0m" << std::endl;
	}

	//parse delay
	if(g_u32iDelayAt != -1) {
		g_u32iDelayAmount = atoi(*(p_argv+g_u32iDelayAt+1));
		std::cout << "\033[0;32mDelay after " << g_u32iDelayAmount << " seconds.\033[0\n" << std::endl;
	}

	//parse interface
	if(g_u32iInterfaceAt != -1) {
		g_strInterface = std::string(*(p_argv+g_u32iInterfaceAt+1));
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(g_strInterface);
		if (dev == NULL) {
			printf("Network interface called '%s' could not be found!\n", g_strInterface.c_str());
			return false;
		}
		if (!dev->open()) {
			printf("Error opening network interface '%s'. Did you run as superuser and is the interface up?\n", g_strInterface.c_str());
			return false;
		}
		std::cout << "\033[0;32mNetwork interface: " << g_strInterface << "\033[0m" << std::endl;
	}

	//parse usedist
	if(g_u32iUseDistAt != -1) {
		if(std::string(*(p_argv+g_u32iUseDistAt+1)) == "true") {
			g_bUseDist = true;
			std::cout << "\033[0;32mMaking use of probability distributions.\033[0m" << std::endl;
		}
	}

	//parse usetimestamp
	if(g_u32iUseTimestampsAt != -1) {
		if(std::string(*(p_argv+g_u32iUseTimestampsAt+1)) == "true") {
			g_bUseTimestamps = true;
			std::cout << "\033[0;32mUsing timestamps given in the pcap files.\033[0m" << std::endl;
		}
	}

	//parse legmbps
	if(g_u32iLegMbpsAt != -1) {
		if(g_bUseTimestamps) {
			printf("You cannot define the mbps and use the timestamps at the same time.\nAborting.");
			return false;
		}
		g_s32iLegMbps = atoi(*(p_argv+g_u32iLegMbpsAt+1));
		std::cout << "\033[0;32mMbps for good traffic: " << g_s32iLegMbps << "\033[0m" << std::endl;
	}

	//parse malmbps
	if(g_u32iMalMbpsAt != -1) {
		if(g_bUseTimestamps) {
			printf("You cannot define the mbps and use the timestamps at the same time.\nAborting.");
			return false;
		}
		g_s32iMalMbps = atoi(*(p_argv+g_u32iMalMbpsAt+1));
		std::cout << "\033[0;32mMbps for evil traffic: " << g_s32iMalMbps << "\033[0m" << std::endl;
	}

	//parse loop
	if(g_u32iLoopAt != -1) {
		g_s32iLoop = atoi(*(p_argv+g_u32iLoopAt+1));
		std::cout << "\033[0;32mIterations: " << g_s32iLoop << ((g_s32iLoop == 0)?" (infinite)":"") << "\033[0m" << std::endl;
	}

    return true;
}

int main(int argc, char** argv) {
	printf("\033[1;33m# CAUTION - BE CAREFUL WITH THE TARGET ADDRESSES AND NETWORK INTERFACES #\n# TRAFFIC MUST NEVER LEAVE YOUR TEST ENVIRONMENT #\033[0m\n\n");
    g_strComStrMal = "";
    g_strComStrLeg = "";
	g_bBernoulliPrompt = false;
	g_bUseDist = false;
	g_bLoadConf = false;

    //args
    g_u32iInterfaceAt = g_utils.findstr("-interface", argv, argc);
    g_u32iDstIpAt = g_utils.findstr("-dstip", argv, argc);
    g_u32iLegAt = g_utils.findstr("-leg", argv, argc);
    g_u32iSrcIpAt = g_utils.findstr("-srcip", argv, argc);
    g_u32iDelayAt = g_utils.findstr("-startupdelay", argv, argc);
    g_u32iLegPcapAt = g_utils.findstr("-legpcap", argv, argc);
    g_u32iMalPcapAt = g_utils.findstr("-malpcap", argv, argc);
    g_u32iDstMacAt = g_utils.findstr("-dstmac", argv, argc);
    g_u32iUseDistAt = g_utils.findstr("-usedistribution", argv, argc);
    g_u32iLoadConfigAt = g_utils.findstr("-loadconfig", argv, argc);
    g_u32iUseTimestampsAt = g_utils.findstr("-usetimestamps", argv, argc);
    g_u32iLegMbpsAt = g_utils.findstr("-legmbps", argv, argc);
    g_u32iMalMbpsAt = g_utils.findstr("-malmbps", argv, argc);
    g_u32iLoopAt = g_utils.findstr("-loop", argv, argc);
	
	if(g_u32iLoadConfigAt != -1 && g_u32iLoadConfigAt%2 == 1 && argc < 4) {
		g_bLoadConf = true;
		printf("Loading configuration from file: %s\n", *(argv+g_u32iLoadConfigAt+1));
	} else if (argc < 7 || g_u32iInterfaceAt == -1 || g_u32iDstIpAt == -1 || g_u32iDstMacAt == -1 || g_u32iDstIpAt%2 != 1 || g_u32iDstMacAt%2 != 1 || g_u32iInterfaceAt%2 != 1 ||
       (g_u32iSrcIpAt != -1 && g_u32iSrcIpAt%2 != 1) ||
       (g_u32iLegAt != -1 && g_u32iLegAt%2 != 1) || (g_u32iMalPcapAt != -1 && g_u32iMalPcapAt%2 != 1) ||
       (g_u32iDelayAt != -1 && g_u32iDelayAt%2 != 1) || (g_u32iLegPcapAt != -1 && g_u32iLegPcapAt%2 != 1) ||
	   (g_u32iUseDistAt != -1 && g_u32iUseDistAt%2 != 1)) {
        printf("Usage: \tsudo %s [ARGUMENTS]\n\n", *argv);
        printf("Mandatory arguments (if not using '-loadconfig'): \n\n");
        printf("\t-dstip\n\t-dstmac\n\t-interface\n\n");
		
        printf("Argument overview:\n\n");
		
        printf("\t-interface [value]\n");
        printf("\t\tSet the network interface through which traffic should be sent.\n");
		
        printf("\t-srcip [value]\n");
        printf("\t\tSet source IP address.\n");
        printf("\t\tdefault: unmodified when using pre-generated pcap-traffic,\n");
        printf("\t\t         random when generating new traffic\n");
		
        printf("\t-dstip [value]\n");
        printf("\t\tSet the destination IP address.\n");
		
        printf("\t-dstmac [value]\n");
        printf("\t\tSet destination mac address.\n");
		
        printf("\t-startupdelay [value]\n");
        printf("\t\tDefines the amount of seconds that the legitimate traffic\n");
        printf("\t\tshould run before the malicious traffic starts.\n");
        printf("\t\tHas to be a number followed by s (seconds) or p (packets).\n");
        printf("\t\tSeconds are disabled when using distributions.\n");
        printf("\t\tExamples:\n");
        printf("\t\t\t-startupdelay 30s\n");
        printf("\t\t\t-startupdelay 30p\n");
		
        printf("\t-legpcap [value]\n");
        printf("\t\tDefines a custom pcap-file containing legitimate traffic  to be replayed.\n");
        printf("\t\tValue must be a path to the file.\n");
        printf("\t\tExample:\n");
        printf("\t\t\t-legpcap /home/username/Documents/traffic.pcap\n");
		
        printf("\t-malpcap [value]\n");
        printf("\t\tDefines a custom pcap-file containing malicious traffic to be replayed.\n");
        printf("\t\tValue must be a path to the file.\n");
        printf("\t\tDefault Pcap-File is SYN.pcap in pcap-subfolder.\n");
        printf("\t\tExample:\n");
        printf("\t\t\t-malpcap /home/username/Documents/traffic.pcap\n");
		
        printf("\t-usedistribution [true/false]\n");
        printf("\t\tDefines whether the traffic pattern should follow a probability distribution.\n");
        printf("\t\tIf set to true, you will be asked to provide a ratio and a seed throughout the program.\n");
        printf("\t\tThe distribution will end as soon as one of the input files reaches their end.\n");
        printf("\t\tThis argument requires '-legpcap' to be defined.\n");
        printf("\t\tValue must be true or false.\n");
        printf("\t\tDefault is false.\n");
		
        printf("\t-usetimestamps [true/false]\n");
        printf("\t\tDefines whether the packets should be sent with the intervals they were captured with.\n");
        printf("\t\tCannot be used together with 'legmbps', 'malmbps' and 'usedistribution'.\n\n");
        printf("\t\tValue must be true or false.\n");
        printf("\t\tDefault is false.\n");
		
        printf("\t-loadconfig [path to file]\n");
        printf("\t\tLoad the configuration of a previous run.\n");
        printf("\t\tValue must lead to a configuration file generated by this program.\n");
        printf("\t\tNo other arguments will be required nor accepted.\n");
		
        printf("\t-legmbps|malmbps [value]\n");
        printf("\t\tSet the replay-speed of the specified pcap-file in megabits per second.\n");
        printf("\t\tSum of both values must not exceed the overall link bandwidth.\n");
        printf("\t\tCannot be used together with 'usetimestamps'.\n");
        printf("\t\tWill only use 'malmbps' when combining traffic with the bernoulli distribution.\n\n");
		
        printf("\t-loop [value]\n");
        printf("\t\tSend the traffic for the specified amount of rounds.\n");
        printf("\t\tExamples: \n");
        printf("\t\t\t0 = loop forever\n");
        printf("\t\t\t1 = send just once\n");
        printf("\t\t\t2 = send twice.\n");
        printf("\t\tDefault: 0\n\n");
        printf("\nExamples: \n\n");
        printf("\tSend a default attack (SYN Flood) to the target described with dstmac and dstip through eth0:\n");
        printf("\tsudo %s -dstmac 08:00:27:e1:9c:bf -dstip 192.168.5.5 -interface eth0\n\n", *argv);
        printf("\tSend self-defined pcap files while 80% of the packets sent should be malicious to the target described with dstmac \n\tand dstip through vboxnet0 and rewrite the source addresses to 0.0.0.0:\n");
        printf("\tsudo ./generator.run -dstmac 08:00:27:38:d5:2e -dstip 192.168.56.101 -srcip 0.0.0.0 -interface vboxnet0 -legpcap /home/user/my_good_traffic.pcap -malpcap /home/user/my_malicious_traffic.pcap\n\n", *argv);
        /**/
		return 0;
    }

    if(!parseArgs(argc,argv)) {
        std::cout << "\033[1;31mWrong arguments!\033[0m\n" << std::endl;
        return 0;
    } else {
        std::cout << "\033[1;32mNo argument-related issues detected.\033[0m\n" << std::endl;
    }
	
	bool usebern = false;
	int bernperc = -1;
	std::string bernseed = "";
	bool usestan = false;
	bool usemaldststan = false;
	bool uselegsrcstan = false;
	bool uselegdststan = false;
	std::string strusemalsrcstan = "";
	std::string strusemaldststan = "";
	std::string struselegsrcstan = "";
	std::string struselegdststan = "";
	std::string stancidr = "";
	std::string stanlow = "";
	std::string stanhigh = "";
	std::string stanmean = "";
	std::string stansdev = "";
	std::string stanseed = "";
	
	if(!g_bLoadConf) {
		if(g_u32iLegPcapAt != -1 && g_u32iMalPcapAt != -1 && g_bUseDist) {
			std::string bernoulliprompt;
			if(g_bUseTimestamps) {
				std::cout << "\n\033[1m(You are using the timestamps. Bernoulli distribution disabled.)\033[0m";
				g_bBernoulliPrompt = false;
			} else {
				std::cout << "\n\033[1m# Use the bernoulli distribution to distribute good and evil traffic?\033[0m [y/n] ";
				std::getline(std::cin,bernoulliprompt);
				if(bernoulliprompt == "y") {
					g_bBernoulliPrompt = true;
					usebern = true;
					std::string strpercent;
					std::cout << "\033[1m# How much percent should the evil traffic take overall\033[0m (0-100): ";
					std::getline(std::cin,strpercent);

					bernperc = std::stoi(strpercent);
					g_u32iBernoulliPerc = bernperc;
					if(bernperc < 0 || bernperc > 100) {
						std::cout << "WRONG VALUE - ABORTING\n";
						return false;
					}
					std::cout << "\033[1m# Please enter a seed\033[0m (string): ";
					std::getline(std::cin,bernseed);
					g_strBernoulliSeed = bernseed;
				} else {
					g_bBernoulliPrompt = false;
				}
			}

			//// DISTRIBUTION: MALICIOUS SOURCE
			
			std::cout << "\n\033[1m# Use the standard distribution to distribute malicious source ip addresses?\033[0m [y/n] ";
			std::getline(std::cin,strusemalsrcstan);

			if(strusemalsrcstan == "y") {
				g_bStandardPrompt = true;
				struct sockaddr_in address;
				usestan = true;
				std::cout << "\033[1m# Please enter the lowest address of the address space:\033[0m ";
				std::getline(std::cin,stanlow);
				g_strStandardLow = stanlow;
				int validlowip = inet_pton(AF_INET, stanlow.c_str(), &(address.sin_addr));
				if(validlowip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter the highest address of the address space:\033[0m ";
				std::getline(std::cin,stanhigh);
				g_strStandardHigh = stanhigh;
				int validhighip = inet_pton(AF_INET, stanhigh.c_str(), &(address.sin_addr));
				if(validhighip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter an IP address as the mean value:\033[0m ";
				std::getline(std::cin,stanmean);
				g_strStandardMeanIP = stanmean;
				int validmeanip = inet_pton(AF_INET, stanmean.c_str(), &(address.sin_addr));
				if(validmeanip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter a standard deviation:\033[0m ";
				std::getline(std::cin,stansdev);
				g_u32iStandardDev = stoi(stansdev);

				std::cout << "\033[1m# Please enter a seed\033[0m (string): ";
				std::getline(std::cin,stanseed);
				g_strStandardSeed = stanseed;
			} else {
				g_bStandardPrompt = false;
			}

			//// DISTRIBUTION: MALICIOUS DESTINATION

			std::cout << "\n\033[1m# Use the standard distribution to distribute malicious destination ip addresses?\033[0m [y/n] ";
			std::getline(std::cin,strusemaldststan);

			if(strusemaldststan == "y") {
				g_bStandardMalDstPrompt = true;
				struct sockaddr_in address;
				usemaldststan = true;
				std::cout << "\033[1m# Please enter the lowest address of the address space:\033[0m ";
				std::getline(std::cin,stanlow);
				g_strStandardMalDstLow = stanlow;
				int validlowip = inet_pton(AF_INET, stanlow.c_str(), &(address.sin_addr));
				if(validlowip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter the highest address of the address space:\033[0m ";
				std::getline(std::cin,stanhigh);
				g_strStandardMalDstHigh = stanhigh;
				int validhighip = inet_pton(AF_INET, stanhigh.c_str(), &(address.sin_addr));
				if(validhighip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter an IP address as the mean value:\033[0m ";
				std::getline(std::cin,stanmean);
				g_strStandardMalDstMeanIP = stanmean;
				int validmeanip = inet_pton(AF_INET, stanmean.c_str(), &(address.sin_addr));
				if(validmeanip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter a standard deviation:\033[0m ";
				std::getline(std::cin,stansdev);
				g_u32iStandardMalDstDev = stoi(stansdev);

				std::cout << "\033[1m# Please enter a seed\033[0m (string): ";
				std::getline(std::cin,stanseed);
				g_strStandardMalDstSeed = stanseed;
			} else {
				g_bStandardMalDstPrompt = false;
			}

			//// DISTRIBUTION: LEGIT SOURCE

			std::cout << "\n\033[1m# Use the standard distribution to distribute good source ip addresses?\033[0m [y/n] ";
			std::getline(std::cin,struselegsrcstan);

			if(struselegsrcstan == "y") {
				g_bStandardLegSrcPrompt = true;
				struct sockaddr_in address;
				uselegsrcstan = true;
				std::cout << "\033[1m# Please enter the lowest address of the address space:\033[0m ";
				std::getline(std::cin,stanlow);
				g_strStandardLegSrcLow = stanlow;
				int validlowip = inet_pton(AF_INET, stanlow.c_str(), &(address.sin_addr));
				if(validlowip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter the highest address of the address space:\033[0m ";
				std::getline(std::cin,stanhigh);
				g_strStandardLegSrcHigh = stanhigh;
				int validhighip = inet_pton(AF_INET, stanhigh.c_str(), &(address.sin_addr));
				if(validhighip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter an IP address as the mean value:\033[0m ";
				std::getline(std::cin,stanmean);
				g_strStandardLegSrcMeanIP = stanmean;
				int validmeanip = inet_pton(AF_INET, stanmean.c_str(), &(address.sin_addr));
				if(validmeanip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter a standard deviation:\033[0m ";
				std::getline(std::cin,stansdev);
				g_u32iStandardLegSrcDev = stoi(stansdev);

				std::cout << "\033[1m# Please enter a seed\033[0m (string): ";
				std::getline(std::cin,stanseed);
				g_strStandardLegSrcSeed = stanseed;
			} else {
				g_bStandardLegSrcPrompt = false;
			}

			//// DISTRIBUTION: LEGIT DESTINATION

			std::cout << "\n\033[1m# Use the standard distribution to distribute good destination ip addresses?\033[0m [y/n] ";
			std::getline(std::cin,struselegdststan);

			if(struselegdststan == "y") {
				g_bStandardLegDstPrompt = true;
				struct sockaddr_in address;
				uselegdststan = true;
				std::cout << "\033[1m# Please enter the lowest address of the address space:\033[0m ";
				std::getline(std::cin,stanlow);
				g_strStandardLegDstLow = stanlow;
				int validlowip = inet_pton(AF_INET, stanlow.c_str(), &(address.sin_addr));
				if(validlowip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter the highest address of the address space:\033[0m ";
				std::getline(std::cin,stanhigh);
				g_strStandardLegDstHigh = stanhigh;
				int validhighip = inet_pton(AF_INET, stanhigh.c_str(), &(address.sin_addr));
				if(validhighip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter an IP address as the mean value:\033[0m ";
				std::getline(std::cin,stanmean);
				g_strStandardLegDstMeanIP = stanmean;
				int validmeanip = inet_pton(AF_INET, stanmean.c_str(), &(address.sin_addr));
				if(validmeanip != 1) {
					std::cout << "IP invalid. Aborting." << std::endl;
					return false;
				}

				std::cout << "\033[1m# Please enter a standard deviation:\033[0m ";
				std::getline(std::cin,stansdev);
				g_u32iStandardLegDstDev = stoi(stansdev);

				std::cout << "\033[1m# Please enter a seed\033[0m (string): ";
				std::getline(std::cin,stanseed);
				g_strStandardLegDstSeed = stanseed;
			} else {
				g_bStandardLegDstPrompt = false;
			}
		}
	}
	
	//modify PCAP files
	createLegPcap(argv);
	createMalPcap(argv);

	//combine them if using bernoulli distribution
	if(g_u32iLegPcapAt != -1 && g_u32iMalPcapAt != -1 && g_bBernoulliPrompt) {
		char combres;
		if(g_bLoadConf) combres = createCombinedPcap(std::string(*(g_newargv+g_u32iLegPcapAt+1)), std::string(*(g_newargv+g_u32iMalPcapAt+1)), g_u32iBernoulliPerc, g_strBernoulliSeed, g_newargv);
		else combres = createCombinedPcap(std::string(*(argv+g_u32iLegPcapAt+1)), std::string(*(argv+g_u32iMalPcapAt+1)), g_u32iBernoulliPerc, g_strBernoulliSeed, argv);
	}
	
	if(!g_bLoadConf) {
		std::string promptsave = "";
		std::cout << "\033[1m# Do you want to save this configuration for later use?\033[0m [y/n] ";
		std::getline(std::cin,promptsave);
		if(promptsave == "y") {
			std::cout << "Saving... ";
			std::string savepath = "./config/";
			savepath += std::to_string((unsigned int)std::time(0));
			savepath += ".ddoscfg";
			std::ofstream savefile;
			savefile.open(savepath);
			savefile << "Arguments = ";
			for(unsigned int i = 1; i < argc; i++)
				savefile << *(argv+i) << " ";
			savefile << "\n";
			savefile << "RewriteGoodDstIP = " << (g_bRewriteLegTrafficIP?"y":"n");
			savefile << "\n";
			savefile << "RewriteEvilDstIP = " << (g_bRewriteMalTrafficIP?"y":"n");
			savefile << "\n";
			savefile << "SetEvilBit = " << (g_bSetEvilBit?"y":"n");
			savefile << "\n";
			savefile << "UseBernoulli = " << (g_bBernoulliPrompt?"y":"n");
			savefile << "\n";
			savefile << "BernoulliPerc = " << g_u32iBernoulliPerc;
			savefile << "\n";
			savefile << "BernoulliSeed = " << g_strBernoulliSeed;
			savefile << "\n";
			//malsrc
			savefile << "UseStandardMalSrc = " << (g_bStandardPrompt?"y":"n");
			savefile << "\n";
			savefile << "StanLowIPMalSrc = " << g_strStandardLow;
			savefile << "\n";
			savefile << "StanHighIPMalSrc = " << g_strStandardHigh;
			savefile << "\n";
			savefile << "StanMeanIPMalSrc = " << g_strStandardMeanIP;
			savefile << "\n";
			savefile << "StanDevMalSrc = " << g_u32iStandardDev;
			savefile << "\n";
			savefile << "StanSeedMalSrc = " << g_strStandardSeed;
			savefile << "\n";
			//maldst
			savefile << "UseStandardMalDst = " << (g_bStandardMalDstPrompt?"y":"n");
			savefile << "\n";
			savefile << "StanLowIPMalDst = " << g_strStandardMalDstLow;
			savefile << "\n";
			savefile << "StanHighIPMalDst = " << g_strStandardMalDstHigh;
			savefile << "\n";
			savefile << "StanMeanIPMalDst = " << g_strStandardMalDstMeanIP;
			savefile << "\n";
			savefile << "StanDevMalDst = " << g_u32iStandardMalDstDev;
			savefile << "\n";
			savefile << "StanSeedMalDst = " << g_strStandardMalDstSeed;
			savefile << "\n";
			//legsrc
			savefile << "UseStandardLegSrc = " << (g_bStandardLegSrcPrompt?"y":"n");
			savefile << "\n";
			savefile << "StanLowIPLegSrc = " << g_strStandardLegSrcLow;
			savefile << "\n";
			savefile << "StanHighIPLegSrc = " << g_strStandardLegSrcHigh;
			savefile << "\n";
			savefile << "StanMeanIPLegSrc = " << g_strStandardLegSrcMeanIP;
			savefile << "\n";
			savefile << "StanDevLegSrc = " << g_u32iStandardLegSrcDev;
			savefile << "\n";
			savefile << "StanSeedLegSrc = " << g_strStandardLegSrcSeed;
			savefile << "\n";
			//legdst
			savefile << "UseStandardLegDst = " << (g_bStandardLegDstPrompt?"y":"n");
			savefile << "\n";
			savefile << "StanLowIPLegDst = " << g_strStandardLegDstLow;
			savefile << "\n";
			savefile << "StanHighIPLegDst = " << g_strStandardLegDstHigh;
			savefile << "\n";
			savefile << "StanMeanIPLegDst = " << g_strStandardLegDstMeanIP;
			savefile << "\n";
			savefile << "StanDevLegDst = " << g_u32iStandardLegDstDev;
			savefile << "\n";
			savefile << "StanSeedLegDst = " << g_strStandardLegDstSeed;
			savefile << "\n";
			savefile.close();
			std::cout << "Saved to " << savepath << "\nYou can rename it if you like, but you should not change the content." << std::endl;
		}
	}
	
    printf("\n\033[1;33mSummarizing attack parameters:\033[0m\n");
    if(g_u32iLegPcapAt != -1) printf("Legitimate PCAP File = %s\n", g_strLegPcap.c_str());
	else printf("No file for good traffic provided. Only malicious traffic will be sent.\n");
    if(g_u32iMalPcapAt != -1) printf("Malicious PCAP File = %s\n", g_strMalPcap.c_str());
	else printf("No malicious pcap file provided. Using default: ./pcap/SYN.pcap\n");
	
    if(g_u32iDstIpAt != -1) printf("Destination IP address = %s\n", g_strDstIP.c_str());
    if(g_u32iDstMacAt != -1) printf("Destination Ethernet MAC Address = %s\n", g_strDstMAC.c_str());
    if(g_u32iInterfaceAt != -1) printf("Interface = %s\n", g_strInterface.c_str());
    if(g_u32iSrcIpAt != -1) printf("Source IP address = %s\n", (g_u32iSrcIpAt != -1)?g_strSrcIP.c_str():("---"));
    if(g_u32iDelayAt != -1) printf("Delay = %s\n", (g_u32iDelayAt != -1)?*(argv+g_u32iDelayAt+1):("---"));
    if(g_u32iUseDistAt != -1) {
		printf("Using probability distributions with following configuration:\n\n");
		printf("\tBernoulli packet-distribution: %s", (g_bBernoulliPrompt?"yes\n":"no\n"));
		printf("\t\tPercentage of evil traffic: %i%s", g_u32iBernoulliPerc, "%\n");
		printf("\t\tSeed: %s\n\n", g_strBernoulliSeed.c_str());
		printf("\tStandard IP-distribution (malicious source): %s", (g_bStandardPrompt?"yes\n":"no\n"));
		printf("\t\tLowest IP: %s\n", g_strStandardLow.c_str());
		printf("\t\tHighest IP: %s\n", g_strStandardHigh.c_str());
		printf("\t\tMean IP: %s\n", g_strStandardMeanIP.c_str());
		printf("\t\tStandard Deviation: %i\n", g_u32iStandardDev);
		printf("\t\tSeed: %s\n\n", g_strStandardSeed.c_str());/**/
		printf("\tStandard IP-distribution (malicious destination): %s", (g_bStandardMalDstPrompt?"yes\n":"no\n"));
		printf("\t\tLowest IP: %s\n", g_strStandardMalDstLow.c_str());
		printf("\t\tHighest IP: %s\n", g_strStandardMalDstHigh.c_str());
		printf("\t\tMean IP: %s\n", g_strStandardMalDstMeanIP.c_str());
		printf("\t\tStandard Deviation: %i\n", g_u32iStandardMalDstDev);
		printf("\t\tSeed: %s\n\n", g_strStandardMalDstSeed.c_str());/**/
		printf("\tStandard IP-distribution (good source): %s", (g_bStandardLegSrcPrompt?"yes\n":"no\n"));
		printf("\t\tLowest IP: %s\n", g_strStandardLegSrcLow.c_str());
		printf("\t\tHighest IP: %s\n", g_strStandardLegSrcHigh.c_str());
		printf("\t\tMean IP: %s\n", g_strStandardLegSrcMeanIP.c_str());
		printf("\t\tStandard Deviation: %i\n", g_u32iStandardLegSrcDev);
		printf("\t\tSeed: %s\n\n", g_strStandardLegSrcSeed.c_str());/**/
		printf("\tStandard IP-distribution (good destination): %s", (g_bStandardLegDstPrompt?"yes\n":"no\n"));
		printf("\t\tLowest IP: %s\n", g_strStandardLegDstLow.c_str());
		printf("\t\tHighest IP: %s\n", g_strStandardLegDstHigh.c_str());
		printf("\t\tMean IP: %s\n", g_strStandardLegDstMeanIP.c_str());
		printf("\t\tStandard Deviation: %i\n", g_u32iStandardLegDstDev);
		printf("\t\tSeed: %s\n", g_strStandardLegDstSeed.c_str());/**/
	}

    printf("\n\033[1;33mPlease review the configuration.\nHit [RETURN] if the traffic should be sent (this will start a countdown of 3 seconds)... \033[0m");
    std::string dummystr;
    std::getline(std::cin,dummystr);
    countdown(3);
    printf("Sending...\n");
	
	bool result = sendTraffic(argv);

	std::cout << "Done.\n";
    return 0;
}
