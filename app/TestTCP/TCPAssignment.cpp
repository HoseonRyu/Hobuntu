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
	this->socket_map = {};
}

void TCPAssignment::finalize()
{

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
	SocketObject* so = this->socket_map[fd];
	so->is_bound = false;

	delete this->socket_map[fd];
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

	SocketObject* so = this->socket_map[sockfd];
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

	SocketObject* so = this->socket_map[sockfd];
	if(!so->is_bound){
		// socket is not bound.
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &so->addr, *addrlen);
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
	// printf("************ Listen Called! ************\n");
	if(this->socket_map.find(sockfd) == this->socket_map.end()) {
		// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	SocketObject* so = this->socket_map[sockfd];
	so->is_listening = true;
	so->backlog = backlog;
	so->state = State::LISTEN;
	so->pid = pid;
	SystemCallInterface::returnSystemCall(syscallUUID, 0);	
}

// Implicit binding with random port(1024~49151) and current ip address 
int TCPAssignment::implicit_bind(int sockfd) {
	SocketObject *clientSo = this->socket_map[sockfd];
	std::map<int, SocketObject*>::iterator iter;
	
	uint8_t ip[4];
	this->getHost()->getIPAddr(ip, 0);
	clientSo->set_family(AF_INET);
	clientSo->set_ip_address(ip);

	bool is_overlaped = true;
	while (is_overlaped) { // Repeat until not be overlaped
		is_overlaped = false;
		int port = rand() % 48128 + 1024; // 1024 ~ 49151 random port
		clientSo->set_port(port);

		// check whether port is overlaped
		for (iter = this->socket_map.begin(); iter != this->socket_map.end(); ++iter){
			if (!iter->second->is_bound)
				continue; // don't examine unbound socket
			else {
				if (this->is_binding_overlap(clientSo, iter->second)) {
					is_overlaped = true; // overlaped: wrong port number
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

	SocketObject *clientSo = this->socket_map[sockfd];
	if (!clientSo->is_bound) { // if not bound
		this->implicit_bind (sockfd);
	}

	/* Header Management*/
	uint8_t header[20];
	memset(header, 0, 20);

	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	((uint32_t *)src_ip)[0] = clientSo->get_ip_address();
	((uint32_t *)dest_ip)[0] = ((struct sockaddr_in *)serv_addr)->sin_addr.s_addr;

	// Source Port, Destination Port
	((uint16_t *)header)[0] = clientSo->get_port();
	((uint16_t *)header)[1] = ((struct sockaddr_in *)serv_addr)->sin_port;

	((uint32_t *)header)[1] = htonl(clientSo->seq_num++); // Sequence Number
	((uint32_t *)header)[2] = htonl(0); // ACK Number
	((uint8_t *)header)[12] = 0x50; // Offset
	((uint8_t *)header)[13] = FLAG_SYN; // SYN Flag
	((uint16_t *)header)[7] = htons(51200); // Initial Window Size (51200)
	((uint16_t *)header)[8] = this->get_TCPchecksum(header, src_ip, dest_ip, 20); // Checksum

	/* Packet Management */
	Packet *connPacket = this->allocatePacket(TCP_OFFSET+20);
	
	connPacket->writeData(IP_OFFSET+12, src_ip, 4); // Source IP (IP Header)
	connPacket->writeData(IP_OFFSET+16, dest_ip, 4); // Dest IP (IP Header)
	connPacket->writeData(TCP_OFFSET, header, 20); // TCP Header
	this->sendPacket("IPv4", connPacket);

	clientSo->syscallUUID = syscallUUID;
	clientSo->state = State::SYN_SENT;

	//SystemCallInterface::returnSystemCall(syscallUUID, 0); // connect complete
	//this->freePacket(connPacket);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	if(this->socket_map.find(sockfd) == this->socket_map.end()) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	SocketObject* clientSo = this->socket_map[sockfd];
	if(clientSo->state != State::ESTABLISHED) {
		// client socket is not connected
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &clientSo->peer_addr, *addrlen);
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	// printf("************ Accept Called! ************\n");
	if(this->socket_map.find(sockfd) == this->socket_map.end()) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	SocketObject* serverSo = this->socket_map[sockfd];

	// blocking 구현 <미완>
	
	serverSo->syscallUUID = syscallUUID;

	if (serverSo->accept_fd != -1) { // Already Connected
		memcpy(addr, &serverSo->peer_addr, *addrlen);
		SystemCallInterface::returnSystemCall(syscallUUID, serverSo->accept_fd);
	} else {
		serverSo->temp_addr = addr;
	}
}

unsigned short TCPAssignment::get_TCPchecksum(void* header, uint8_t *src_ip, uint8_t *dest_ip, int len){
	// Construct pseudo header
	uint8_t pseudo_header[PSEUDO_HEADER_LEN]; 
	memset(pseudo_header, 0, PSEUDO_HEADER_LEN);
	memcpy(pseudo_header, src_ip, 4); // source ip
	memcpy(pseudo_header+4, dest_ip, 4); // dest ip
	pseudo_header[9] = 0x06; // TCP protocol
	((uint16_t *)pseudo_header)[5] = htons ((uint16_t)len); // length

	// Get sum
	unsigned int sum = 0;
	int i;
	for (i=0;i<PSEUDO_HEADER_LEN/2;i++){
		sum += ((unsigned short *)pseudo_header)[i];
		sum = (sum + (sum >> 16)) & 0xFFFF;
	};
	for (i=0;i<len/2;i++){
		sum += ((unsigned short *)header)[i];
		sum = (sum + (sum >> 16)) & 0xFFFF;
	};
	return ~((unsigned short)sum);
}


// For debug uses
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
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
		case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
			static_cast<struct sockaddr*>(param.param2_ptr),
			static_cast<socklen_t*>(param.param3_ptr));
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
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
			static_cast<struct sockaddr *>(param.param2_ptr),
			static_cast<socklen_t*>(param.param3_ptr));
		break;
		default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	//printf("Packet Arrived!\n");
	//extract address
	uint8_t src_ip[4];
	uint8_t dest_ip[4];
	packet->readData(IP_OFFSET+12, src_ip, 4);
	packet->readData(IP_OFFSET+16, dest_ip, 4);

	uint8_t src_port[2];
	uint8_t dest_port[2];
	packet->readData(TCP_OFFSET+0, src_port, 2);
	packet->readData(TCP_OFFSET+2, dest_port, 2);

	// Header setting
	uint8_t header[20];
	memset(header, 0, 20);
	packet->readData(TCP_OFFSET, header, 20);

	int seq_num = ntohl(((int *)header)[1]);
	int ack_num = ntohl(((int *)header)[2]); // ack_num 체크하는거 짜기 (미완)
	uint8_t flag = header[13];

	int send_seq = 1;
	SocketObject* recvSo;
	recvSo = this->getSocketObject(*((uint32_t *)dest_ip), *((uint16_t *)dest_port));

	// if socket is not available, ignore packet
	if (recvSo == NULL) { 
		this->freePacket(packet);
		return;
	}

	/*** Received Message Handling ***/
	//swap ip, port of src/dest
	Packet* myPacket = this->clonePacket(packet);
	myPacket->writeData(IP_OFFSET+12, dest_ip, 4);
	myPacket->writeData(IP_OFFSET+16, src_ip, 4);
	memcpy(header, dest_port, 2);
	memcpy(header+2, src_port, 2);
	if (recvSo->state == State::SYN_SENT) {   // Client Side
		if ((flag & FLAG_SYN) != 0) { // SYN Flag Received
			/*** Client: Connection Established! Send ACK ***/

			((uint32_t *)header)[1] = htonl(ack_num); // Sequence Number
			((uint32_t *)header)[2] = htonl(seq_num+1); // ACK Number
			((uint8_t *)header)[13] = FLAG_ACK; // ACK Flag
			((uint16_t *)header)[8] = 0x0000; // initial checksum
			((uint16_t *)header)[8] = this->get_TCPchecksum(header, dest_ip, src_ip, 20); // Checksum

			myPacket->writeData(TCP_OFFSET, header, 20);
			this->sendPacket("IPv4", myPacket);
			this->freePacket(packet);

			/**** Connection ESTABLISHED! ****/
			// Update peer socket of client socket
			struct sockaddr_in peer_addr;
			socklen_t len = sizeof(struct sockaddr_in);
			memset(&peer_addr, 0, len);
			peer_addr.sin_family = AF_INET;
			peer_addr.sin_port = *((uint16_t *)src_port);
			peer_addr.sin_addr.s_addr = *((uint32_t *)src_ip);
			memcpy(&recvSo->peer_addr, &peer_addr, len);
			
			recvSo->state = State::ESTABLISHED; // connection is established
			SystemCallInterface::returnSystemCall(recvSo->syscallUUID, 0); // unblock connect()
		}
	} else if (recvSo->state == State::LISTEN) { // Server Side
		if ((flag & FLAG_SYN) != 0) { // SYN Flag Received
			// printf("Server: SYN Received!\n");
			/*** Server: Connection Request Received! Send SYN+ACK ***/

			((uint32_t *)header)[1] = htonl(recvSo->seq_num++); // Sequence Number
			((uint32_t *)header)[2] = htonl(seq_num+1); // ACK Number
			((uint8_t *)header)[13] = FLAG_ACK | FLAG_SYN; // SYN, ACK Flag
			((uint16_t *)header)[8] = 0x0000; // initial checksum
			((uint16_t *)header)[8] = this->get_TCPchecksum(header, dest_ip, src_ip, 20); // Checksum

			myPacket->writeData(TCP_OFFSET, header, 20);
			this->sendPacket("IPv4", myPacket);
			this->freePacket(packet);

			recvSo->state = State::SYN_RECV;
		}
	} else if (recvSo->state == State::SYN_RECV) { // Server Side
		if ((flag & FLAG_ACK) != 0) {
			// printf("Server: ACK Received!\n");
			// client ip, port 맞게 왔는지 체크? <미완>
			// ACK num도 맞게 왔는지 체크

			/**** Connection ESTABLISHED! ****/
			// Update peer socket of server socket
			struct sockaddr_in peer_addr;
			socklen_t len = sizeof(struct sockaddr_in);
			memset(&peer_addr, 0, len);
			peer_addr.sin_family = AF_INET;
			peer_addr.sin_port = *((uint16_t *)src_port);
			peer_addr.sin_addr.s_addr = *((uint32_t *)src_ip);
			memcpy(&recvSo->peer_addr, &peer_addr, len);

			recvSo->state = State::LISTEN; // Back to Listen 이해 필요

			// Insert accept_fd into socket_map
			int accept_fd = SystemCallInterface::createFileDescriptor(recvSo->pid);
			SocketObject *acceptSo = new SocketObject(accept_fd);
			this->socket_map[accept_fd] = acceptSo;
			acceptSo->is_bound = true;
			acceptSo->state = State::ESTABLISHED;
			memcpy(&acceptSo->addr, &recvSo->addr, len);
			
			// printf("Listen Socket fd:%d\n", recvSo->fd);
			// printf("Accept Socket fd:%d\n", accept_fd);

			// printf("Listen port: %d\n", recvSo->get_port());
			// printf("Accept port: %d\n", acceptSo->get_port());

			if(recvSo->temp_addr != NULL)
				memcpy(recvSo->temp_addr, &recvSo->peer_addr, len);
			recvSo->accept_fd = accept_fd;
			SystemCallInterface::returnSystemCall(recvSo->syscallUUID, accept_fd); // unblock accept()
		}
	}

	if ((flag & FLAG_FIN) != 0){ // FIN flag is set (미완)
		((uint32_t *)header)[1] = htonl(send_seq); // Sequence Number
		((uint32_t *)header)[2] = htonl(seq_num+1); // ACK Number
		((uint8_t *)header)[13] = FLAG_ACK; // ACK Flag
		((uint16_t *)header)[8] = 0x0000; // initial checksum
		((uint16_t *)header)[8] = this->get_TCPchecksum(header, dest_ip, src_ip, 20); // Checksum

		myPacket->writeData(TCP_OFFSET, header, 20);

		this->sendPacket("IPv4", myPacket);
		this->freePacket(packet);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	
}

// Find SocketObject using given ip and port number (network order)
SocketObject* TCPAssignment::getSocketObject(uint32_t ip, uint16_t port){
	// ip = 0 인 경우도 고려해서 짜기 (미완)
	for (auto &kv : this->socket_map){
		SocketObject* so = kv.second;
		//printf("[%d]-> (%d, %d)\n", kv.first, so->get_ip_address(), so->get_port());
		if (so->is_bound == true) {
			if (so->get_port() == port) {
				if (ip == 0 || so->get_ip_address() == 0 ||
					so->get_ip_address() == ip)
					return so;
			}
		}
	}

	return NULL; // Not Found;  	
}

}

/**** 혼돈의 데이타 구조 바꾸기..... 
backlog, wait_list 만들고 
Context (SocketObject)도 커넥션 구별할 수 있게 만들기 ***/