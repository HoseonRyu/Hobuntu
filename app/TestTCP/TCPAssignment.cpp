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

#define VERBOSE 0

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
	SocketObject *so = new SocketObject(pid, fd);
// so->domain = protocolFamily;
// so->type = type;
// so->protocol = protocol;


	this->socket_map[pid][fd] = so;
	SystemCallInterface::returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
	SocketObject* so = this->socket_map[pid][fd];
	so->is_bound = false;

	delete this->socket_map[pid][fd];
	this->socket_map[pid].erase(fd);	
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
	SocketObject* so;
	if((so = getSocketObject(pid, sockfd)) == NULL) {
	// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(&(so->local_addr), myaddr, addrlen);

	for (auto &kv : this->socket_map[pid]){
		SocketObject* so2 = kv.second;
		if (!so2->is_bound)
			continue; // ignore unboud sockets
		else {
			if(this->is_binding_overlap(so, so2)) {
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
	SocketObject* so;
	if((so = getSocketObject(pid, sockfd)) == NULL) {
		// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	if(!so->is_bound){
		// socket is not bound.
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &so->local_addr, *addrlen);
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
	// printf("************ Listen Called! ************\n");
	SocketObject* so;
	if((so = getSocketObject(pid, sockfd)) == NULL) {
		// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	so->is_listening = true;
	so->backlog_max = backlog;
	so->state = State::LISTEN;
	SystemCallInterface::returnSystemCall(syscallUUID, 0);	
}

// Implicit binding with random port(1024~49151) and current ip address 
int TCPAssignment::implicit_bind(int pid, int sockfd) {
	SocketObject *clientSo = this->socket_map[pid][sockfd];
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
		for (auto &kv : this->socket_map[pid])
		{
			if(!kv.second->is_bound)
				continue; // don't examine unbound socket
			else {
				if (this->is_binding_overlap(clientSo, kv.second)) {
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
	SocketObject* clientSo;
	if((clientSo = getSocketObject(pid, sockfd)) == NULL) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	if (addrlen < 0) { // invaild parameter
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	if (!clientSo->is_bound) { // if not bound
		this->implicit_bind (pid, sockfd);
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
	
	clientSo->syscallUUID = syscallUUID;
	clientSo->state = State::SYN_SENT;
	memcpy(&clientSo->peer_addr, serv_addr, addrlen); 

	connPacket->writeData(IP_OFFSET+12, src_ip, 4); // Source IP (IP Header)
	connPacket->writeData(IP_OFFSET+16, dest_ip, 4); // Dest IP (IP Header)
	connPacket->writeData(TCP_OFFSET, header, 20); // TCP Header
	this->sendPacket("IPv4", connPacket);
	//SystemCallInterface::returnSystemCall(syscallUUID, 0); // connect complete
	//this->freePacket(connPacket);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	SocketObject* clientSo;
	if((clientSo = getSocketObject(pid, sockfd)) == NULL) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	if(clientSo->state != State::ESTABLISHED) {
		// client socket is not connected
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	memcpy(addr, &clientSo->peer_addr, *addrlen);
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	SocketObject* listenSo;
	if (VERBOSE) printf("Accept Called!\n");
	if((listenSo = getSocketObject(pid, sockfd)) == NULL) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	
	listenSo->syscallUUID = syscallUUID;

	if (listenSo->pending_queue.size() >= 1) { // Connection Pending 
		SocketObject* acceptSo = listenSo->pending_queue.front();
		if (acceptSo->state == State::ESTABLISHED) {
			if (VERBOSE) printf("Established Context Pop!\n");
			memcpy(addr, &acceptSo->peer_addr, *addrlen);
			listenSo->pending_queue.pop();
			SystemCallInterface::returnSystemCall(syscallUUID, acceptSo->fd);
		} else {
			listenSo->temp_addr = addr;
		}
	} else {
		listenSo->temp_addr = addr;
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

	/*** Received Message Handling ***/
	//swap ip, port of src/dest
	Packet* myPacket = this->clonePacket(packet);
	myPacket->writeData(IP_OFFSET+12, dest_ip, 4);
	myPacket->writeData(IP_OFFSET+16, src_ip, 4);
	memcpy(header, dest_port, 2);
	memcpy(header+2, src_port, 2);
	
	SocketObject* recvSo;
	SocketObject* listenSo;
	recvSo = this->getSocketObjectByContext(
		*((uint32_t *)dest_ip), *((uint16_t *)dest_port), *((uint32_t *)src_ip), *((uint16_t *)src_port));	

	if ((flag & FLAG_SYN) != 0) { // SYN Flag Received	
		if (recvSo == NULL) {
			listenSo = this->getListenSocketByContext(*((uint32_t *)dest_ip), *((uint16_t *)dest_port));
			if (listenSo != NULL) {
				// Server Side
				if (VERBOSE) printf("LISTEN: SYN is Received!\n");

				/*** Server: Connection Request (SYN) Received! Send SYN+ACK ***/

				// Context Creation
				bool success = false;
				if (listenSo->backlog < listenSo->backlog_max ) { // check backlog value
					socklen_t len = sizeof(struct sockaddr_in);

					int accept_fd = SystemCallInterface::createFileDescriptor(listenSo->pid);
					SocketObject *acceptSo = new SocketObject(listenSo->pid, accept_fd);
					memcpy(&acceptSo->local_addr, &listenSo->local_addr, len);
					acceptSo->state = State::SYN_RECV;
					acceptSo->is_bound = true;

					// Update peer socket of server socket
					struct sockaddr_in peer_addr;
					memset(&peer_addr, 0, len);
					peer_addr.sin_family = AF_INET;
					peer_addr.sin_port = *((uint16_t *)src_port);
					peer_addr.sin_addr.s_addr = *((uint32_t *)src_ip);
					memcpy(&acceptSo->peer_addr, &peer_addr, len);

					// Insert accept_fd into socket_map
					this->socket_map[listenSo->pid][accept_fd] = acceptSo;

					if (VERBOSE) printf("Context Created...\n");
					listenSo->pending_queue.push(acceptSo);
					listenSo->backlog++;
					success = true;
					
				}

				((uint32_t *)header)[1] = htonl(listenSo->seq_num++); // Sequence Number
				((uint32_t *)header)[2] = htonl(seq_num+1); // ACK Number
				if (success)
					((uint8_t *)header)[13] = FLAG_ACK | FLAG_SYN; // SYN, ACK Flag
				else
					((uint8_t *)header)[13] = FLAG_ACK | FLAG_RST; // RST, ACK Flag
				((uint16_t *)header)[8] = 0x0000; // initial checksum
				((uint16_t *)header)[8] = this->get_TCPchecksum(header, dest_ip, src_ip, 20); // Checksum
				myPacket->writeData(TCP_OFFSET, header, 20);
				this->sendPacket("IPv4", myPacket);
				this->freePacket(packet);
			}
		} else {
			if (recvSo->state == State::SYN_SENT) { // Client Side
				/*** Client: SYN Received! Connection Established! Send ACK ***/
				if (VERBOSE) printf("Client: Connection Established!\n");

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
					
				recvSo->state = State::ESTABLISHED; 
				SystemCallInterface::returnSystemCall(recvSo->syscallUUID, 0); // unblock connect()
			} 	
		}
	} else if (recvSo != NULL && recvSo->state == State::SYN_RECV) { // Server Side
		if ((flag & FLAG_ACK) != 0) { // ACK is Received
			if (VERBOSE) printf("SERVER: ACK is Received!\n");
			/**** Connection ESTABLISHED! ****/
			recvSo->state = State::ESTABLISHED; // connection is established

			listenSo = this->getListenSocketByContext(*((uint32_t *)dest_ip), *((uint16_t *)dest_port));
			listenSo->backlog--; // update backlog value
			
			if (listenSo->temp_addr != NULL) { // accept() is already called
				memcpy(listenSo->temp_addr, &recvSo->peer_addr, sizeof(struct sockaddr_in));
				listenSo->temp_addr = NULL;
				listenSo->pending_queue.pop();
				SystemCallInterface::returnSystemCall(listenSo->syscallUUID, recvSo->fd); // unblock accept()
			} else {
				// wait accept();
			}
		}
	}
	if ((flag & FLAG_FIN) != 0) { // FIN flag is set (미완)
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

// backlog 안되면 지우는거?

void TCPAssignment::timerCallback(void* payload)
{
	
}

/* Find SocketObject using given pid and fd */
SocketObject* TCPAssignment::getSocketObject(int pid, int fd){
	if(this->socket_map.find(pid) == this->socket_map.end()) {
		return NULL; // pid not found in socket_map
	}
	auto map = this->socket_map[pid];
	if(map.find(fd) == map.end()) {
		return NULL; // fd not found in map
	}
	return map[fd];
}

/* Find SocketObject using given Context (network order) */
SocketObject* TCPAssignment::getSocketObjectByContext(
	uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port){
	for (auto &kv : this->socket_map){
		auto map = kv.second; 
		for (auto &kv2 : map) {
			SocketObject* so = kv2.second;
			//printf("[%d]-> (%d, %d)\n", kv.first, so->get_ip_address(), so->get_port());
			if (so->is_bound == true) {
				if (so->get_port() == local_port && so->get_port(REMOTE) == remote_port) {
					if (local_ip == 0 || so->get_ip_address() == 0 || so->get_ip_address() == local_ip)
						if (remote_ip == 0 || so->get_ip_address(REMOTE) == 0 || so->get_ip_address(REMOTE) == remote_ip)
							return so;
					}
				}
			}
		}

	return NULL; // Not Found;  	
}

/* Find Listen SocketObject using given Context (network order) */
SocketObject* TCPAssignment::getListenSocketByContext(uint32_t local_ip, uint16_t local_port){
	for (auto &kv : this->socket_map){
		auto map = kv.second; 
		for (auto &kv2 : map) {
			SocketObject* so = kv2.second;
			//printf("[%d]-> (%d, %d)\n", kv.first, so->get_ip_address(), so->get_port());
			if (so->is_bound == true) {
				if (so->get_port() == local_port) {
					if (local_ip == 0 || so->get_ip_address() == 0 || so->get_ip_address() == local_ip)
						if (so->is_listening)
							return so;
					}
				}
			}
		}

	return NULL; // Not Found;  	
}

}

/* TO DO List
	Close State 구현
	Time out
	client -- RST 받았을때 구현
	Connect - Close 구현
	Accept Synchronize 확인
	잘못 왔을때도 ACK 보내기

	*/
