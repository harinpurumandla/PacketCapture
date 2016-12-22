/*
 * packetCapture.h
 *
 *  Created on: Oct 15, 2013
 *      Author: Jacob Saunders
 */

#ifndef PACKETCAPTURE_H_
#define PACKETCAPTURE_H_

//Define this so asprintf is available. Requires GNU C
#define _GNU_SOURCE
//Generic libraries of C functions.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//libpcap
#include <pcap.h>
//Custom library used for a string to int call, bundled.
#include "extraFunctions.h"
//Used for the power function.
#include <math.h>
//Include for inet_ntoa
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//Extra includes for TCP and IP structures.
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


//Define a boolean variable type and associated keywords entirely
//because I am used to languages with them. :)
#define bool int
#define true 1
#define false 0

//Define methods.
int main ( int argc, char *argv[] );
pcap_t* openSource(bool inputFile, const char* inputSource);
void installFilter(pcap_t* source, const char* filter);
void readPackets(pcap_t* source, FILE* outputFile, int packetLimit);
void handlePacket(int packetNum, struct pcap_pkthdr *packetHeader, const u_char *packetData,
		FILE* outputFile);
void outputString(const char* string, FILE* file);

//Define packet structures. Taken from: www.tcpdump.org/pcap.htm
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

int linkHeaderSize = 0;

#endif /* PACKETCAPTURE_H_ */
