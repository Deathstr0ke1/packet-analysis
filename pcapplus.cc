#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "pcapplus.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>


#define EXIT_WITH_ERROR(reason) do { \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)


#define PRINT_STAT_LINE(description, counter, measurement) \
		std::cout \
			<< std::left << std::setw(46) << (std::string(description) + ":") \
			<< std::right << std::setw(15) << std::fixed << std::showpoint << std::setprecision(3) << counter \
			<< " [" << measurement << "]" << std::endl;

#define DEFAULT_CALC_RATES_PERIOD_SEC 2


struct SSLPacketArrivedData
{
	SSLStatsCollector* statsCollector;
	pcpp::PcapFileWriterDevice* pcapWriter;
};


void printStatsHeadline(std::string description)
{
	std::string underline;
	for (size_t i = 0; i < description.length(); i++)
	{
		underline += "-";
	}

	std::cout << std::endl << description << std::endl << underline << std::endl << std::endl;
}


/**
 * packet capture callback - called whenever a packet arrives
 */
void sslPacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	pcpp::Packet parsedPacket(packet);

	SSLPacketArrivedData* data  = (SSLPacketArrivedData*)cookie;

	// give the packet to the collector
	data->statsCollector->collectStats(&parsedPacket);

	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != NULL)
	{
		data->pcapWriter->writePacket(*packet);
	}
}


/**
 * An auxiliary method for sorting the string count map. Used in printServerNames() and in printCipherSuites()
 */
bool stringCountComparer(std::pair<std::string, int> first, std::pair<std::string, int> second)
{
	if (first.second == second.second)
	{
		return first.first > second.first;
	}
	return first.second > second.second;
}


/**
 * An auxiliary method for sorting the uint16_t count map. Used in printPorts()
 */
bool uint16CountComparer(std::pair<uint16_t, int> first, std::pair<uint16_t, int> second)
{
	if (first.second == second.second)
	{
		return first.first > second.first;
	}
	return first.second > second.second;
}


/**
 * Print the server-name count map to a table sorted by popularity (most popular names will be first)
 */
void printServerNames(ClientHelloStats& clientHelloStatsCollector)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("Hostname");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(40);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the server-name count map so the most popular names will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int> > map2vec(clientHelloStatsCollector.serverNameCount.begin(), clientHelloStatsCollector.serverNameCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &stringCountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<std::string, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		std::stringstream values;
		values << iter->first << "|" << iter->second;
		printer.printRow(values.str(), '|');
	}
}


/**
 * Print SSL record version map
 */
void printVersions(std::map<uint16_t, int>& versionMap, std::string headline)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back(headline);
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(28);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the version map so the most popular version will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<uint16_t, int> > map2vec(versionMap.begin(), versionMap.end());
	std::sort(map2vec.begin(),map2vec.end(), &uint16CountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<uint16_t, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		std::stringstream values;
		values << pcpp::SSLVersion(iter->first).toString() << "|" << iter->second;
		printer.printRow(values.str(), '|');
	}
}


/**
 * Print used cipher-suite map to a table sorted by popularity (most popular cipher-suite will be first)
 */
void printCipherSuites(ServerHelloStats& serverHelloStats)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("Cipher-suite");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(50);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the cipher-suite count map so the most popular names will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<std::string, int> > map2vec(serverHelloStats.cipherSuiteCount.begin(), serverHelloStats.cipherSuiteCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &stringCountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<std::string, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		std::stringstream values;
		values << iter->first << "|" << iter->second;
		printer.printRow(values.str(), '|');
	}
}


void printPorts(SSLGeneralStats& stats)
{
	// create the table
	std::vector<std::string> columnNames;
	columnNames.push_back("SSL/TLS ports");
	columnNames.push_back("Count");
	std::vector<int> columnsWidths;
	columnsWidths.push_back(13);
	columnsWidths.push_back(5);
	pcpp::TablePrinter printer(columnNames, columnsWidths);

	// sort the port count map so the most popular names will be first
	// since it's not possible to sort a std::map you must copy it to a std::vector and sort it then
	std::vector<std::pair<uint16_t, int> > map2vec(stats.sslPortCount.begin(), stats.sslPortCount.end());
	std::sort(map2vec.begin(),map2vec.end(), &uint16CountComparer);

	// go over all items (names + count) in the sorted vector and print them
	for(std::vector<std::pair<uint16_t, int> >::iterator iter = map2vec.begin();
			iter != map2vec.end();
			iter++)
	{
		std::stringstream values;
		values << iter->first << "|" << iter->second;
		printer.printRow(values.str(), '|');
	}
}


/**
 * Print a summary of all statistics collected by the SSLStatsCollector. Should be called when traffic capture was finished
 */
void printStatsSummary(SSLStatsCollector& collector)
{
	printStatsHeadline("General stats");
	PRINT_STAT_LINE("Sample time", collector.getGeneralStats().sampleTime, "Seconds");
	PRINT_STAT_LINE("Number of SSL packets", collector.getGeneralStats().numOfSSLPackets, "Packets");
	PRINT_STAT_LINE("Rate of SSL packets", collector.getGeneralStats().sslPacketRate.totalRate, "Packets/sec");
	PRINT_STAT_LINE("Number of SSL flows", collector.getGeneralStats().numOfSSLFlows, "Flows");
	PRINT_STAT_LINE("Rate of SSL flows", collector.getGeneralStats().sslFlowRate.totalRate, "Flows/sec");
	PRINT_STAT_LINE("Total SSL data", collector.getGeneralStats().amountOfSSLTraffic, "Bytes");
	PRINT_STAT_LINE("Rate of SSL data", collector.getGeneralStats().sslTrafficRate.totalRate, "Bytes/sec");
	PRINT_STAT_LINE("Average packets per flow", collector.getGeneralStats().averageNumOfPacketsPerFlow, "Packets");
	PRINT_STAT_LINE("Average data per flow", collector.getGeneralStats().averageAmountOfDataPerFlow, "Bytes");
	PRINT_STAT_LINE("Client-hello message", collector.getClientHelloStats().numOfMessages, "Messages");
	PRINT_STAT_LINE("Server-hello message", collector.getServerHelloStats().numOfMessages, "Messages");
	PRINT_STAT_LINE("Number of SSL flows with successful handshake", collector.getGeneralStats().numOfHandshakeCompleteFlows, "Flows");
	PRINT_STAT_LINE("Number of SSL flows ended with alert", collector.getGeneralStats().numOfFlowsWithAlerts, "Flows");

	printStatsHeadline("SSL/TLS ports count");
	printPorts(collector.getGeneralStats());

	printStatsHeadline("SSL/TLS versions count");
	printVersions(collector.getGeneralStats().sslVersionCount, std::string("SSL/TLS version"));

	printStatsHeadline("Cipher-suite count");
	printCipherSuites(collector.getServerHelloStats());

	printStatsHeadline("Server-name count");
	printServerNames(collector.getClientHelloStats());

}


/**
 * Print the current rates. Should be called periodically during traffic capture
 */
void printCurrentRates(SSLStatsCollector& collector)
{
	printStatsHeadline("Current SSL rates");
	PRINT_STAT_LINE("Rate of SSL packets", collector.getGeneralStats().sslPacketRate.currentRate, "Packets/sec");
	PRINT_STAT_LINE("Rate of SSL flows", collector.getGeneralStats().sslFlowRate.currentRate, "Flows/sec");
	PRINT_STAT_LINE("Rate of SSL data", collector.getGeneralStats().sslTrafficRate.currentRate, "Bytes/sec");
	PRINT_STAT_LINE("Rate of SSL requests", collector.getClientHelloStats().messageRate.currentRate, "Requests/sec");
	PRINT_STAT_LINE("Rate of SSL responses", collector.getServerHelloStats().messageRate.currentRate, "Responses/sec");
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * activate SSL/TLS analysis from pcap file
 */
void analyzeSSLFromPcapFile(std::string pcapFileName, std::set<std::string> &ip_addrs_str_set)
{
	// open input file (pcap or pcapng file)
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFileName);

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	// read the input file packet by packet and give it to the SSLStatsCollector for collecting stats
	SSLStatsCollector collector;
	pcpp::RawPacket rawPacket;
	while(reader->getNextPacket(rawPacket))
	{
		pcpp::Packet parsedPacket(&rawPacket);


        if (parsedPacket.isPacketOfType(pcpp::IPv4))
        {
            // 排除背景流量
            pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
            pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

            if((ip_addrs_str_set.count(srcIP.toString()) != 0) || (ip_addrs_str_set.count(destIP.toString()) != 0))
            {
                continue;
            }
        }
   
        collector.collectStats(&parsedPacket);
	}

	// print stats summary
	std::cout << std::endl << std::endl
		<< "SSL STATS SUMMARY" << std::endl
		<< "=============" << std::endl;
	printStatsSummary(collector);

	// close input file
	reader->close();

	// free reader memory
	delete reader;
}

void ssl_packet_collector(char *filename, std::set<std::string> &ip_addrs_str_set)
{
    analyzeSSLFromPcapFile(std::string(filename), ip_addrs_str_set);
}