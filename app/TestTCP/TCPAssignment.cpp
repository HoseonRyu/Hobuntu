/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <E/Networking/IPv4/E_IPv4.hpp>
#include <arpa/inet.h>


namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

SocketObject::SocketObject()
{

}

SocketObject::SocketObject(int fd) {
	this->fd = fd;
	bzero(&this->addr, sizeof(struct sockaddr));
	this->is_bound = false;
}
in_port_t SocketObject::get_port(){
	return ((struct sockaddr_in *)&this->addr)->sin_port;
}
uint32_t SocketObject::get_ip_address(){
	return ((struct sockaddr_in *)&this->addr)->sin_addr.s_addr;
}
void SocketObject::set_family(int family){
	((struct sockaddr_in *)&this->addr)->sin_family = family;
}
void SocketObject::set_port(int port){
	((struct sockaddr_in *)&this->addr)->sin_port = htons(port);
}
void SocketObject::set_ip_address(uint8_t* ip){
	memcpy (&(((struct sockaddr_in *)&this->addr)->sin_addr.s_addr), ip, 4);
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int protocolFamily, int type, int protocol){
	int fd = SystemCallInterface::createFileDescriptor(pid);
	SocketObject *so = new SocketObject(fd);
	so->domain = protocolFamily;
	so->type = type;
	so->protocol = protocol;
	this->socket_map[fd] = so;
	SystemCallInterface::returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	delete socket_map[fd];
	this->socket_map.erase(fd);	
	SystemCallInterface::removeFileDescriptor(pid, fd);
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}
bool TCPAssignment::is_binding_overlap (SocketObject *so1, SocketObject *so2){
	uint32_t ip1 = so1->get_ip_address();
	uint32_t ip2 = so2->get_ip_address();
	if (htonl(ip1) == 0 || htonl(ip2) == 0){
		return so1->get_port() == so2->get_port();
	} else {
		return (so1->get_port() == so2->get_port()) && ip1 == ip2;
	}
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *myaddr, socklen_t addrlen)
{

	std::map<int, SocketObject*>::iterator iter;

	if(this->socket_map.find(sockfd) == this->socket_map.end()) {
		// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(&(this->socket_map[sockfd]->addr), myaddr, addrlen);

	SocketObject* so = socket_map[sockfd];
	for (iter = this->socket_map.begin(); iter != this->socket_map.end(); ++iter){
		if (!iter->second->is_bound)
			continue; // examine itself
		else {
			if (this->is_binding_overlap(so, iter->second)) {
				SystemCallInterface::returnSystemCall(syscallUUID, -1);
				return;
			}
		}
	}  

	/****** Binding complete! ******/
	so->is_bound = true;
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname (UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	if(this->socket_map.find(sockfd) == this->socket_map.end()) {
		// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	SocketObject* so = socket_map[sockfd];
	if(!so->is_bound){
		// socket is not bound.
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &so->addr, *addrlen);
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

int TCPAssignment::implicit_bind(int sockfd) {
	SocketObject *clientSo = socket_map[sockfd];
	std::map<int, SocketObject*>::iterator iter;
	
	uint8_t ip[4];
	this->getHost()->getIPAddr(ip, 0);
	clientSo->set_family(AF_INET);
	clientSo->set_ip_address(ip);

	bool is_overlaped = true;

	while (is_overlaped) {
		is_overlaped = false;
		int port = rand() % 48128 + 1024; // 1024 ~ 49151 random port
		clientSo->set_port(port);

		// check whether port is overlaped
		for (iter = this->socket_map.begin(); iter != this->socket_map.end(); ++iter){
			if (!iter->second->is_bound)
				continue; // don't examine unbound socket
			else {
				if (this->is_binding_overlap(clientSo, iter->second)) {
					is_overlaped = true; // wrong port number
				}
			}
		}
	}

	// Binding complete
	clientSo->is_bound = true;
	return 0;
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *serv_addr, socklen_t addrlen) {
	
	if(this->socket_map.find(sockfd) == this->socket_map.end()) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	if (addrlen < 0) { // invaild parameter
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	SocketObject *clientSo = socket_map[sockfd];

	if (!clientSo->is_bound) { // if not bound
		this->implicit_bind (sockfd);
		// print (debug)
		struct in_addr ipst;
		ipst.s_addr = clientSo->get_ip_address();
		printf("Client implicit bind: port %d, ip: %s\n", clientSo->get_port(), inet_ntoa(ipst));
	}

	/* Header Management*/
	uint8_t header[20];
	memset(header, 0, 20);

	// Source Port, Destination Port
	((uint16_t *)header)[0] = clientSo->get_port();
	((uint16_t *)header)[1] = ((struct sockaddr_in *)serv_addr)->sin_port;

	((uint32_t *)header)[1] = htonl(0); // Sequence Number
	((uint32_t *)header)[2] = htonl(0); // ACK Number
	((uint8_t *)header)[12] = 0x50; // Offset
	((uint8_t *)header)[13] = 0x02; // SYN Flag
	((uint16_t *)header)[7] = htons(51200); // Initial Window Size (51200)
	((uint16_t *)header)[8] = this->get_checksum(header, 20); // Checksum

	this->hex_dump(header, 0, 20); // print function (debugging)

	/* Packet Management */
	Packet *connPacket = this->allocatePacket(TCP_OFFSET+20);
	
	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	((uint32_t *)src_ip)[0] = clientSo->get_ip_address();
	((uint32_t *)dest_ip)[0] = ((struct sockaddr_in *)serv_addr)->sin_addr.s_addr;

	connPacket->writeData(IP_OFFSET+12, src_ip, 4); // Source IP (IP Header)
	connPacket->writeData(IP_OFFSET+16, dest_ip, 4); // Dest IP (IP Header)
	connPacket->writeData(TCP_OFFSET, header, 20); // TCP Header
	this->sendPacket("IPv4", connPacket);

	SystemCallInterface::returnSystemCall(syscallUUID, 0); // connect complete
	//this->freePacket(connPacket);
}

unsigned short TCPAssignment::get_checksum(void* header, int len){
	int sum = 0;
	int i;
	for (i=0;i<len/2;i++){
		sum += ((unsigned short *)header)[i];
		sum = (sum + (sum >> 16)) & 0xFFFF;
	};
	return ~((unsigned short)sum);
}


void TCPAssignment::hex_dump(void* buf, int ofs, int size){
	printf("===========\n");
	for (int i=0; i<size;i++){
		printf("%02hhx ", ((char *)buf)[i]);
		if (i%4 == 3)
			printf("\n");
	}
	printf("===========\n");
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int, param.param3_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
					static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	printf(" packetArrived!\n");
}

void TCPAssignment::timerCallback(void* payload)
{
	
}

}