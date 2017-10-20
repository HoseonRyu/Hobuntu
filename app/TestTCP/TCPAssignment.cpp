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
	SocketObject* so;
	if((so = TCPAssignment::getSocketObject(pid, fd)) == NULL) {
	// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	if (so->is_peer_set) {
		// SEND FIN Flag
		TCPHeader* tcp = new TCPHeader();
		tcp->src_ip = so->get_ip_address();
		tcp->src_port = so->get_port();
		tcp->dest_ip = so->get_ip_address(REMOTE);
		tcp->dest_port = so->get_port(REMOTE);
		tcp->seq_num = htonl(so->seq_num);
		tcp->offset = 0x50;
		tcp->flag = FLAG_FIN;
		tcp->window_size = htons(51200);

		Packet* packet = this->allocatePacket(TCP_OFFSET+20);
		packet->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
		this->sendPacket("IPv4", packet);
		delete tcp;
		so->ack_num = so->seq_num+1;

		// change state
		if (so->state == State::CLOSE_WAIT){ // server
			so->state = State::LAST_ACK;
			if (VERBOSE) printf("close() Client %d: CLOSE_WAIT -> LAST_ACK\n", so->fd);
		}
		else { // 
			if (VERBOSE) printf("close() Client %d: ESTABLISHED -> FIN_WAIT_1\n", so->fd);
			so->state = State::FIN_WAIT_1;
		}
	} else {
		// Socket Termination
		delete this->socket_map[pid][fd];
		this->socket_map[pid].erase(fd);	
		SystemCallInterface::removeFileDescriptor(pid, fd);
	}
	SystemCallInterface::returnSystemCall(syscallUUID, 0);		
}

bool TCPAssignment::is_binding_overlap (SocketObject *so1, SocketObject *so2) {
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
	if((so = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) {
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
	if (so->get_ip_address() == 0) {
		uint8_t ip[4];
		this->getHost()->getIPAddr(ip, 0);
		so->set_ip_address(ip);
	}
	so->is_bound = true;
	SystemCallInterface::returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname (UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	SocketObject* so;
	if((so = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) {
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
	if((so = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) {
		// socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	if (so->is_listening) {
		// socket is already listening
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
		clientSo->set_port(htons(port));

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
	if((clientSo = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) {
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
	if (VERBOSE) { // printing (debug)
		struct sockaddr_in t_addr;
		t_addr.sin_addr.s_addr = clientSo->get_ip_address();
		printf("Socket Implicit Bind= port:%d ip:%s\n", 
			ntohs(clientSo->get_port()), inet_ntoa(t_addr.sin_addr));
	}

	/* Header Calculation */
	TCPHeader* tcp = new TCPHeader();
	tcp->src_ip = clientSo->get_ip_address();
	tcp->dest_ip = ((struct sockaddr_in *)serv_addr)->sin_addr.s_addr;
	
	tcp->src_port = clientSo->get_port();
	tcp->dest_port = ((struct sockaddr_in *)serv_addr)->sin_port;
	
	tcp->seq_num = htonl(clientSo->seq_num); // Sequence Number
	tcp->ack_num = htonl(0); // ACK Number
	tcp->offset = 0x50; // Offset
	tcp->flag = FLAG_SYN; // SYN Flag
	tcp->window_size = htons(51200); // Initial Window Size (51200)

	clientSo->syscallUUID = syscallUUID;
	clientSo->state = State::SYN_SENT;
	memcpy(&clientSo->peer_addr, serv_addr, addrlen); // set peer_addr
	clientSo->is_peer_set = true; 
	clientSo->ack_num = clientSo->seq_num+1;

	/* Packet Management */
	Packet *connPacket = this->allocatePacket(TCP_OFFSET+20);
	connPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
	this->sendPacket("IPv4", connPacket);
	delete tcp;

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	SocketObject* clientSo;
	if((clientSo = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	if(!clientSo->is_peer_set) {
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
	if((listenSo = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) {
		// client socket is not constructed
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	
	listenSo->syscallUUID = syscallUUID;

	if (listenSo->pending_queue.size() >= 1) { // Connection Pending 
		SocketObject* acceptSo = listenSo->pending_queue.front();
		if (acceptSo->is_established) {
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
	// Header setting
	TCPHeader* tcp = new TCPHeader(packet);

	int seq_num = ntohl(tcp->seq_num);
	uint8_t flag = tcp->flag;

	/*** Received Message Handling ***/

	// Packet* myPacket = this->allocatePacket(TCP_OFFSET+20);
	Packet* myPacket = this->clonePacket(packet);
	
	SocketObject* recvSo;
	SocketObject* listenSo;
	recvSo = TCPAssignment::getSocketObjectByContext(tcp->dest_ip, tcp->dest_port, tcp->src_ip, tcp->src_port);	
	listenSo = TCPAssignment::getListenSocketByContext(tcp->dest_ip, tcp->dest_port);
	if (recvSo == NULL && listenSo == NULL) {
		// no socket to handle
		if (flag != FLAG_ACK) {
			// just send ACK for packet
			tcp->swap_ip();
			tcp->swap_port();
			tcp->seq_num = htonl(0); // Sequence Number
			tcp->ack_num = htonl(seq_num+1); // ACK Number
			tcp->flag = FLAG_ACK; // ACK Flag
			myPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
			this->sendPacket("IPv4", myPacket);
			this->freePacket(packet);
			delete tcp;
			return;
		}
	}

	// Sequence Number Handle
	if (recvSo != NULL && IS_SET(flag, FLAG_ACK) && recvSo->ack_num == ntohl(tcp->ack_num)) {
		recvSo->seq_num++;
	}

	if (IS_SET(flag, FLAG_SYN)) { // SYN Flag Received	
		if (recvSo == NULL) {
			// Server Side (Listen Socket)
			if (VERBOSE) printf("LISTEN: SYN is Received!\n");

			/*** Server: Connection Request (SYN) Received! Send SYN+ACK ***/

			// Context Creation
			bool success = false;
			if (listenSo->backlog < listenSo->backlog_max ) { // check backlog value
				socklen_t len = sizeof(struct sockaddr_in);

				int accept_fd = SystemCallInterface::createFileDescriptor(listenSo->pid);
				SocketObject *acceptSo = new SocketObject(listenSo->pid, accept_fd); // Create new SocketObject
				memcpy(&acceptSo->local_addr, &listenSo->local_addr, len); // copy address 
				acceptSo->state = State::SYN_RECV;
				acceptSo->is_bound = true;
				acceptSo->seq_num = listenSo->seq_num;
				acceptSo->ack_num = listenSo->ack_num+1; // packet will be sent

				// Update peer socket of server socket
				acceptSo->set_family(AF_INET, REMOTE);
				acceptSo->set_port(tcp->src_port, REMOTE);
				acceptSo->set_ip_address(tcp->src_ip, REMOTE);
				acceptSo->is_peer_set = true;

				// Insert accept_fd into socket_map
				this->socket_map[listenSo->pid][accept_fd] = acceptSo;

				if (VERBOSE) printf("Context Created...\n");
				listenSo->pending_queue.push(acceptSo);
				listenSo->backlog++;
				success = true;
				
			}

			// Packet Management
			tcp->swap_ip();
			tcp->swap_port();
			tcp->seq_num = htonl(listenSo->seq_num); // Sequence Number
			tcp->ack_num = htonl(seq_num+1); // ACK Number
			if (success)
				tcp->flag = FLAG_ACK | FLAG_SYN; // SYN, ACK Flag
			else
				tcp->flag = FLAG_ACK | FLAG_RST; // RST, ACK Flag
			myPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
			this->sendPacket("IPv4", myPacket);
			listenSo->ack_num = listenSo->seq_num+1;


		} else {
			if (recvSo->state == State::SYN_SENT) { // Client Side
				if (IS_SET(flag, FLAG_ACK)) { // ACK+SYN Received 
					/*** Client: SYN Received! Connection Established! Send ACK ***/
					if (VERBOSE) printf("Client: Connection Established!\n");

					/**** Connection ESTABLISHED! ****/
					// Update peer socket of client socket
					recvSo->state = State::ESTABLISHED; 
					recvSo->is_established = true;
						
					// Packet Management
					this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);
					SystemCallInterface::returnSystemCall(recvSo->syscallUUID, 0); // unblock connect()
				} else { // Only SYN Received (Simultaneous Open)
					if (VERBOSE) printf("Simultaneous Open: SYN_SENT -> SYN_RECV\n");
					recvSo->state = State::SYN_RECV;
					// Packet Management
					tcp->swap_ip();
					tcp->swap_port();
					tcp->seq_num = htonl(recvSo->seq_num); // Sequence Number
					tcp->ack_num = htonl(seq_num+1); // ACK Number
					tcp->flag = FLAG_ACK | FLAG_SYN; // SYN+ACK Flag
					myPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
					this->sendPacket("IPv4", myPacket);
					recvSo->ack_num = recvSo->seq_num+1;

				}
			} else if (recvSo->state == State::SYN_RECV) {
				if (IS_SET(flag, FLAG_ACK)) {
					if (VERBOSE) printf("Simultaneous Open: SYN_RECV -> ESTABLISHED\n");
					recvSo->state = State::ESTABLISHED; // connection is established
					recvSo->is_established = true;
					this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);

					SystemCallInterface::returnSystemCall(recvSo->syscallUUID, 0); // unblock connect() (Simultaneous open)
				}
			}
		}
	} else if (recvSo != NULL && recvSo->state == State::SYN_RECV) { // Server Side
		if (IS_SET(flag, FLAG_ACK)) { // ACK is Received
			if (VERBOSE) printf("SERVER: ACK is Received!\n");
			/**** Connection ESTABLISHED! ****/
			recvSo->state = State::ESTABLISHED; // connection is established
			recvSo->is_established = true;
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
	if (IS_SET(flag, FLAG_FIN)) { // FIN flag is set 
		if (recvSo != NULL) {
			if(recvSo->state == State::ESTABLISHED) { // server
				if (VERBOSE) printf("Server %d: ESTABLISHED -> CLOSE_WAIT\n", recvSo->fd);
				recvSo->state = State::CLOSE_WAIT;

				this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);

			} else if (recvSo->state == State::FIN_WAIT_1) {// client
				if (IS_SET(flag, FLAG_ACK)) { // FIN+ACK
					if (VERBOSE) printf("Client %d: FIN_WAIT_1 -> TIME_WAIT\n", recvSo->fd);
					recvSo->state = State::TIME_WAIT;

					this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);

					// TO DO : TIME_WAIT timeout 
				} else {
					if (VERBOSE) printf("Client %d: FIN_WAIT_1 -> CLOSING\n", recvSo->fd);
					recvSo->state = State::CLOSING;
					this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);
				}
			} else if (recvSo->state == State::FIN_WAIT_2) { // client
				if (VERBOSE) printf("Client %d: FIN_WAIT_2 -> TIME_WAIT\n", recvSo->fd);
				recvSo->state = State::TIME_WAIT;

				this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);

				// TO DO : TIME_WAIT timeout 
			}
		}
	} else if (IS_SET(flag, FLAG_ACK)) {
		if (recvSo->state == State::FIN_WAIT_1) { // client
			if (VERBOSE) printf("Client %d: FIN_WAIT_1 -> FIN_WAIT_2\n", recvSo->fd);
			recvSo->state = State::FIN_WAIT_2;
		} else if (recvSo->state == State::LAST_ACK) {
			if (VERBOSE) printf("Server %d: LAST_ACK -> CLOSED \n", recvSo->fd);
			recvSo->state = State::CLOSED;
			
			// Socket Termination
			int pid = recvSo->pid;
			int fd = recvSo->fd;
			delete this->socket_map[pid][fd];
			this->socket_map[pid].erase(fd);	
			SystemCallInterface::removeFileDescriptor(pid, fd);
		} else if (recvSo->state == State::CLOSING) {
			if (VERBOSE) printf("Socket %d: CLOSING -> TIME_WAIT\n", recvSo->fd);
			recvSo->state = State::TIME_WAIT;

			// this->send_ACK_Packet(seq_num, recvSo, tcp, myPacket);

			// TO DO: TIME_WAIT timeout
		}
	}
	this->freePacket(packet);
	delete tcp;
}

void TCPAssignment::timerCallback(void* payload)
{
	
}

void TCPAssignment::send_ACK_Packet(int ack_num, SocketObject* so, TCPHeader* tcp, Packet* packet){
	tcp->swap_ip();
	tcp->swap_port();
	tcp->seq_num = htonl(so->seq_num); // Sequence Number
	tcp->ack_num = htonl(ack_num); // ACK Number
	tcp->flag = FLAG_ACK; // ACK Flag
	packet->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
	this->sendPacket("IPv4", packet);
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
	Backlog에서 거절 당하면 socket 처리
	client -- RST 받았을때 구현
	Connect - Close 구현
	Accept Synchronize 확인
	잘못 왔을때도 ACK 보내기

	*/
