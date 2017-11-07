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
#include <E/E_TimeUtil.hpp>
#include <E/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <map>

#define VERBOSE 0
#define MAX(a,b) (a>b)?a:b
#define MIN(a,b) (a>b)?b:a
#define ABS(a,b) (a>b)?a-b:b-a
#define currentTime() this->getHost()->getSystem()->getCurrentTime()

#define ALPHA 0.125
#define BETA 0.25
#define K 4
#define InitDevRTT 100000

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
	so->devRTT = InitDevRTT;
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
		tcp->src_ip = so->get_boundIP_address(this->getHost());
		tcp->src_port = so->get_port();
		tcp->dest_ip = so->get_ip_address(REMOTE);
		tcp->dest_port = so->get_port(REMOTE);
		tcp->seq_num = htonl(so->seq_num);
		tcp->offset = 0x50;
		tcp->flag = FLAG_FIN;
		tcp->window_size = htons(51200);

		so->sent_FIN_seqnum = so->seq_num;
		Packet* packet = this->allocatePacket(TCP_OFFSET+20);
		packet->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
		this->sendPacket("IPv4", packet);
		delete tcp;
		so->ack_num = so->seq_num+1;
		so->seq_num++;

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
	tcp->src_ip = clientSo->get_boundIP_address(this->getHost());
	tcp->dest_ip = ((struct sockaddr_in *)serv_addr)->sin_addr.s_addr;
	
	tcp->src_port = clientSo->get_port();
	tcp->dest_port = ((struct sockaddr_in *)serv_addr)->sin_port;
	
	tcp->seq_num = htonl(clientSo->local_seq_base); // Sequence Number
	tcp->ack_num = htonl(0); // ACK Number
	tcp->offset = 0x50; // Offset
	tcp->flag = FLAG_SYN; // SYN Flag
	tcp->window_size = htons(51200); // Initial Window Size (51200)

	clientSo->syscallUUID = syscallUUID;
	clientSo->state = State::SYN_SENT;
	memcpy(&clientSo->peer_addr, serv_addr, addrlen); // set peer_addr
	clientSo->is_peer_set = true; 

	/* Packet Management */
	Packet *connPacket = this->allocatePacket(TCP_OFFSET+20);
	connPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
	this->sendPacket("IPv4", connPacket);
	delete tcp;
	clientSo->ack_num = clientSo->seq_num+1;
	clientSo->seq_num++;
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

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count) {
	SocketObject* so;
	if((so = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) { // socket is invalid
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	if (!so->is_peer_set) { // socket is not connected
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	so->isReading = true;
	so->syscallUUID = syscallUUID;
	so->read_remainSize = count;
	so->read_buf = buf;
	so->read_count = 0;
	internal_read(so);
}

void TCPAssignment::internal_read(SocketObject* so) {
	while (so->read_remainSize > 0) {
		if (so->read_internalIndex == -1) { // internal Segment Buffer has no data
			if (so->readBuffer.empty()) { // No Packet Pending 
				break;	// block read()
			}

			/* Read One Segment  */
			auto iter = so->readBuffer.begin();
			Packet* recvPacket = iter->second;
			size_t recvPayloadSize = recvPacket->getSize() - TCP_DATA_OFFSET;
			recvPacket->readData(TCP_DATA_OFFSET, so->read_internalBuffer, recvPayloadSize); 
			so->read_internalIndex = 0; // init internal Buffer
			so->read_internalSize = recvPayloadSize;
			
			so->readBuffer.erase(iter->first); // erase from readBuffer
			this->freePacket(iter->second);
		} else { // internal Segment Buffer has data
			size_t availableSize = so->read_internalSize - so->read_internalIndex;
			if (so->read_remainSize <= availableSize){ // internal Buffer has enough data to provide read()
				// if (VERBOSE)
				// 	printf("Copy index %03d~%03lu\n", so->read_internalIndex, so->read_internalIndex + so->read_remainSize-1);
				memcpy(so->read_buf, so->read_internalBuffer+so->read_internalIndex, so->read_remainSize);
				so->read_internalIndex += so->read_remainSize;
				so->read_count += so->read_remainSize; 
				so->rwnd += so->read_remainSize;

				/* Reading Complete! */
				if (so->read_internalIndex == so->read_internalSize) {
					so->read_internalIndex = -1;
				}
 				so->isReading = false;
				so->read_remainSize = 0;
				SystemCallInterface::returnSystemCall(so->syscallUUID, so->read_count); // unblock read()
				break;
			} else { // internal Buffer has small number of data to provide read()
				// if (VERBOSE)
				// 	printf("Copy index2 %03d~%03lu\n", so->read_internalIndex, so->read_internalIndex+availableSize-1);
				memcpy(so->read_buf, so->read_internalBuffer+so->read_internalIndex, availableSize);
				so->read_internalIndex = -1; // reset internal Buffer
				so->read_remainSize -= availableSize;
				so->read_count += availableSize;
				so->read_buf = (uint8_t *)so->read_buf + availableSize;
				so->rwnd += availableSize;
			}
		}
	}
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count) {
	SocketObject* so;

	if((so = TCPAssignment::getSocketObject(pid, sockfd)) == NULL) { // socket is invalid
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}
	if (!so->is_peer_set) { // socket is not connected
		SystemCallInterface::returnSystemCall(syscallUUID, -1);
		return;
	}

	so->isWriting = true;
	so->write_internalBuffer = malloc(count);
	memcpy(so->write_internalBuffer, buf, count);
	so->write_internalIndex = 0;
	so->write_remainSize = count;
	so->syscallUUID = syscallUUID;
	so->write_count = 0;
	internal_write(so);
}

void TCPAssignment::internal_write(SocketObject* so) {
	while (so->write_remainSize > 0) {
		// printf("cwnd: %lAd\n", so->cwnd);
		size_t availableSize = so->cwnd - so->sendWindowPayloadSize;

		if (!so->expectedACKBuffer.empty() && ((uint32_t )so->seq_num < so->expectedACKBuffer.rbegin()->first)) {
			// During retransmission;
			// TO DO :: 차례로 다음것을 보내는 코드 만들기. (지금은 맨처음껏만 계속 보냄)
			struct packet_data *pd = so->expectedACKBuffer[so->seq_num - so->local_seq_base + MSS]; // MSS 아닐때?
			Packet* packet = pd->packet;
			size_t writeSize = packet->getSize() - TCP_DATA_OFFSET;
			if (availableSize >= writeSize) {
				pd->packet = this->clonePacket(packet);
				this->sendPacket("IPv4", packet);

				pd->sent_time = currentTime();
				so->seq_num += writeSize;
				so->sendWindowPayloadSize += writeSize;
				if (VERBOSE)
					printf("Port %hd\tRetransmit with ACK number %u\n", ntohs(so->get_port()), so->seq_num - so->local_seq_base + MSS);
			} else {
				break; // block write()
			}
		} else {
			size_t writeSize = MIN(so->write_remainSize, MSS);
			writeSize = MIN(writeSize, availableSize);

			/* Flow Control */
			if (so->rwnd_peer == 0) { 
				writeSize = 1;
			} else {
				writeSize = MIN(writeSize, so->rwnd_peer);
			}

			if (availableSize == 0) { // Buffer is Full
				break; // block write()
			} else {
				// printf("writeSize:%lu\n",writeSize);
				/* Send Packet with writeSize */
				TCPHeader *tcp = new TCPHeader();
				tcp->src_ip = so->get_boundIP_address(this->getHost());
				tcp->src_port = so->get_port();
				tcp->dest_ip = so->get_ip_address(REMOTE);
				tcp->dest_port = so->get_port(REMOTE);
				tcp->seq_num = htonl(so->seq_num);
				tcp->ack_num = htonl(so->ack_num);
				tcp->offset = 0x50;
				tcp->window_size = htons(51200);
				tcp->flag = FLAG_ACK;
				tcp->payload = (uint8_t *) so->write_internalBuffer + so->write_internalIndex;
				tcp->payload_size = writeSize;

				Packet* packet = this->allocatePacket(TCP_OFFSET+20+writeSize);
				packet->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
				packet->writeData(TCP_OFFSET+20, (uint8_t *)so->write_internalBuffer + so->write_internalIndex, writeSize);
				Packet* ACKpacket = this->clonePacket(packet);
				this->sendPacket("IPv4", packet);
				delete tcp;

				so->write_internalIndex += writeSize;
				so->seq_num += writeSize;


				// printf("expectedACKBuffer %u inserted\n", so->seq_num - so->local_seq_base);
				struct packet_data *pd = (struct packet_data *)malloc(sizeof(struct packet_data));
				memset(pd, 0, sizeof(struct packet_data));
				pd->packet = ACKpacket;
				pd->sent_time = this->getHost()->getSystem()->getCurrentTime();
				so->expectedACKBuffer[so->seq_num - so->local_seq_base] = pd;
				so->sendWindowPayloadSize += writeSize;


				/* Set Timer */
				if (!so->isTcpTimerRunning) {
					TimerPayload *tp = new TimerPayload(TIMER::TIME_OUT, so);
					so->tcpTimer = TimerModule::addTimer(tp, TimeUtil::makeTime(so->timeoutInterval, TimeUtil::USEC));
					so->isTcpTimerRunning = true;
					so->tp = tp;
				}
				
				so->write_remainSize -= writeSize;
				so->write_count += writeSize;

				// printf("*Send expectedACK %u with timeout %u\n", so->seq_num - so->local_seq_base, so->timeoutInterval);
				/* set up Timer */
			}
		}
		
	}

	if (so->write_remainSize == 0) {
		/* Writing Finished */
		so->isWriting = false;
		free(so->write_internalBuffer);
		SystemCallInterface::returnSystemCall(so->syscallUUID, so->write_count); // unblock write()
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
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
		case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
	
	SocketObject* recvSo;
	SocketObject* listenSo;
	recvSo = TCPAssignment::getSocketObjectByContext(tcp->dest_ip, tcp->dest_port, tcp->src_ip, tcp->src_port);	
	if (recvSo == NULL)
		recvSo = TCPAssignment::getListenSocketByContext(tcp->dest_ip, tcp->dest_port);
	if (recvSo == NULL) {
		// no socket to handle
		delete tcp;
		return;
	}

	Packet* myPacket = this->clonePacket(packet);
	switch (recvSo->state) {
		case State::LISTEN:
		{
			if (IS_SET(flag, FLAG_SYN)){
				if (VERBOSE) printf("LISTEN: SYN is Received!\n");

				/*** Server: Connection Request (SYN) Received! Send SYN+ACK ***/

				// Context Creation
				bool success = false;
				if (recvSo->backlog < recvSo->backlog_max ) { // check backlog value
					socklen_t len = sizeof(struct sockaddr_in);

					int accept_fd = SystemCallInterface::createFileDescriptor(recvSo->pid);
					SocketObject *acceptSo = new SocketObject(recvSo->pid, accept_fd); // Create new SocketObject
					memcpy(&acceptSo->local_addr, &recvSo->local_addr, len); // copy address 
					acceptSo->state = State::SYN_RECV;
					acceptSo->is_bound = true;
					acceptSo->seq_num = recvSo->local_seq_base+1; // packet will be sent
					acceptSo->ack_num = seq_num+1; // packet will be sent
					acceptSo->peer_seq_base = ntohl(tcp->seq_num);
					acceptSo->expected_recvSeqNum = 1;
					acceptSo->recvBase = 1;
					acceptSo->sendBase = 1;
					acceptSo->local_ack_base = seq_num;


					// Update peer socket of server socket
					acceptSo->set_family(AF_INET, REMOTE);
					acceptSo->set_port(tcp->src_port, REMOTE);
					acceptSo->set_ip_address(tcp->src_ip, REMOTE);
					acceptSo->is_peer_set = true;

					// Insert accept_fd into socket_map
					this->socket_map[recvSo->pid][accept_fd] = acceptSo;

					if (VERBOSE) printf("Context Created...\n");
					recvSo->pending_queue.push(acceptSo);
					recvSo->backlog++;
					success = true;
					
				}

				// Packet Management
				tcp->swap_ip();
				tcp->swap_port();
				tcp->seq_num = htonl(recvSo->local_seq_base); // Sequence Number
				tcp->ack_num = htonl(seq_num+1); // ACK Number
				if (success)
					tcp->flag = FLAG_ACK | FLAG_SYN; // SYN, ACK Flag
				else
					tcp->flag = FLAG_ACK | FLAG_RST; // RST, ACK Flag

				myPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
				this->sendPacket("IPv4", myPacket);
				recvSo->ack_num = recvSo->seq_num+1;
			}
		}
		break;
		case State::SYN_SENT:
		{
			if (IS_SET(flag, FLAG_SYN)){ 
				if (IS_SET(flag, FLAG_ACK)) {// ACK+SYN Received 
					/*** Client: SYN+ACK Received! Connection Established! Send ACK ***/
					if (VERBOSE) printf("Client: Connection Established!\n");
					/**** Connection ESTABLISHED! ****/
					this->initializeSocketEstablished(recvSo, tcp);
						
					// Packet Management
					this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);
					recvSo->local_ack_base = seq_num;
					SystemCallInterface::returnSystemCall(recvSo->syscallUUID, 0); // unblock connect()
				} else { // Only SYN Received (Simultaneous Open)
					if (VERBOSE) printf("Simultaneous Open: SYN_SENT -> SYN_RECV\n");
					recvSo->state = State::SYN_RECV;
					// Packet Management
					tcp->swap_ip();
					tcp->swap_port();
					tcp->seq_num = htonl(recvSo->seq_num-1); // Sequence Number
					tcp->ack_num = htonl(seq_num+1); // ACK Number
					tcp->flag = FLAG_ACK | FLAG_SYN; // SYN+ACK Flag
					myPacket->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
					this->sendPacket("IPv4", myPacket);
					recvSo->ack_num = recvSo->seq_num+1;
					// recvSo->seq_num++;

				}
			}
		}
		break;
		case State::SYN_RECV:
		{
			if (IS_SET(flag, FLAG_SYN)){
				if (IS_SET(flag, FLAG_ACK)) {
					if (VERBOSE) printf("Simultaneous Open: SYN_RECV -> ESTABLISHED\n");
					/**** Connection ESTABLISHED! ****/
					this->initializeSocketEstablished(recvSo, tcp);
					this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);
					SystemCallInterface::returnSystemCall(recvSo->syscallUUID, 0); // unblock connect() (Simultaneous open)
				} 
			} else {
				if (IS_SET(flag, FLAG_ACK)) { // ACK is Received
					if (VERBOSE) printf("SERVER: ACK is Received!\n");
					/**** Connection ESTABLISHED! ****/
					this->initializeSocketEstablished(recvSo, tcp);
					recvSo->peer_seq_base -= 1; // Current Sequnce Number is 1.
					listenSo = getListenSocketByContext(tcp->dest_ip, tcp->dest_port);
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
		}
		break;
		case State::ESTABLISHED:
		{
			if (IS_SET(flag, FLAG_FIN)) {
				if (VERBOSE) printf("Server %d: ESTABLISHED -> CLOSE_WAIT\n", recvSo->fd);
				recvSo->state = State::CLOSE_WAIT;
				SystemCallInterface::returnSystemCall(recvSo->syscallUUID, recvSo->read_count); // unblock read()
				this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);
			} else {
				this->process_received_data(recvSo, tcp, myPacket);
			}
		}
		break;
		case State::FIN_WAIT_1:
		{
			if (IS_SET(flag, FLAG_FIN)) {
				if (IS_SET(flag, FLAG_ACK)) { // FIN+ACK
					if (ntohl(tcp->ack_num) == recvSo->sent_FIN_seqnum + 1) { // ACK for FIN pacekt
						if (VERBOSE) printf("Client %d: FIN_WAIT_1 -> TIME_WAIT\n", recvSo->fd);
						recvSo->state = State::TIME_WAIT;

						this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);

						// TIME_WAIT timeout
						TimerPayload* tp = new TimerPayload(TIMER::TIME_WAIT, recvSo);
						TimerModule::addTimer(tp, TimeUtil::makeTime(TCP_TIMEWAIT_LEN, TimeUtil::SEC));
					} else {
						process_received_data(recvSo, tcp, myPacket);
					}
				} else {
					if (VERBOSE) printf("Client %d: FIN_WAIT_1 -> CLOSING\n", recvSo->fd);
					recvSo->state = State::CLOSING;
					//this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);
				}
			} else {
				if (IS_SET(flag, FLAG_ACK)) { // ACK
					if (ntohl(tcp->ack_num) == recvSo->sent_FIN_seqnum + 1) { // ACK for FIN pacekt
						if (VERBOSE) printf("Client %d: FIN_WAIT_1 -> FIN_WAIT_2\n", recvSo->fd);
						recvSo->state = State::FIN_WAIT_2;	
					} else {
						process_received_data(recvSo, tcp, myPacket);
					}
				} 
			} 
		}
		break;
		case State::FIN_WAIT_2:
		{
			if (IS_SET(flag, FLAG_FIN)) {
				if (VERBOSE) printf("Client %d: FIN_WAIT_2 -> TIME_WAIT\n", recvSo->fd);
				recvSo->state = State::TIME_WAIT;

				this->send_ACK_Packet(seq_num+1, recvSo, tcp, myPacket);

				// TIME_WAIT timeout
				TimerPayload* tp = new TimerPayload(TIMER::TIME_WAIT, recvSo);
				TimerModule::addTimer(tp, TimeUtil::makeTime(TCP_TIMEWAIT_LEN, TimeUtil::SEC));
			} else {
				this->process_received_data(recvSo, tcp, myPacket);
			}
		}
		break;
		case State::LAST_ACK:
		{
			if (IS_SET(flag, FLAG_ACK)) {
				if (VERBOSE) printf("Server %d: LAST_ACK -> CLOSED \n", recvSo->fd);
				recvSo->state = State::CLOSED;
				
				// Socket Termination
				int pid = recvSo->pid;
				int fd = recvSo->fd;
				delete this->socket_map[pid][fd];
				this->socket_map[pid].erase(fd);	
				SystemCallInterface::removeFileDescriptor(pid, fd);
			}
		}
		break;
		case State::CLOSING:
		{
			if (IS_SET(flag, FLAG_ACK)) {
				if (VERBOSE) printf("Socket %d: CLOSING -> TIME_WAIT\n", recvSo->fd);
				recvSo->state = State::TIME_WAIT;

				this->send_ACK_Packet(seq_num, recvSo, tcp, myPacket);

				// TIME_WAIT timeout
				TimerPayload* tp = new TimerPayload(TIMER::TIME_WAIT, recvSo);
				TimerModule::addTimer(tp, TimeUtil::makeTime(TCP_TIMEWAIT_LEN, TimeUtil::SEC));
			}
		}
	}
	this->freePacket(packet);
	delete tcp;
}

void TCPAssignment::initializeSocketEstablished(SocketObject* so, TCPHeader* tcp){
	so->state = State::ESTABLISHED; 
	so->is_established = true;
	so->peer_seq_base = ntohl(tcp->seq_num);
	so->expected_recvSeqNum = 1;
	so->recvBase = 1;
	so->sendBase = 1;
}

void TCPAssignment::timerCallback(void* payload)
{
	TimerPayload* tp = (TimerPayload* )payload;
	SocketObject *targetSo = tp->so;

	switch (tp->type) {
		case TIMER::TIME_WAIT:
		{
			int pid = targetSo->pid;
			int fd = targetSo->fd;
			delete this->socket_map[pid][fd];
			this->socket_map[pid].erase(fd);
			if (VERBOSE) printf("Socket %d Terminated\n", fd);
			delete tp;	
		}
		break;
		case TIMER::TIME_OUT:
		{
			targetSo->tcpTimer = false;
			if (targetSo->cwnd == MSS) {
				targetSo->sshthresh = MSS;
			} else {
				targetSo->sshthresh = targetSo->cwnd / 2;
			}
			targetSo->cwnd = MSS; // Return Slow start
			targetSo->dupACKcount = 0;
			targetSo->sendWindowPayloadSize = 0;
			targetSo->congestionState = Congestion::SlowStart;

			/* retransmit oldest unacked packet */
			if (targetSo->state == State::ESTABLISHED || targetSo->state == State::FIN_WAIT_1) {
				if (!targetSo->expectedACKBuffer.empty()) {
					auto oldestBuffer = targetSo->expectedACKBuffer.begin();
					uint32_t expectedACKnum = oldestBuffer->first;
					struct packet_data *pd = oldestBuffer->second;
					Packet* packet = pd->packet;
					pd->packet = this->clonePacket(packet);
					this->sendPacket("IPv4", packet);
					targetSo->sendWindowPayloadSize += packet->getSize() - TCP_DATA_OFFSET;
					targetSo->congestionPacketSize = targetSo->cwnd;

					if (VERBOSE) {
						printf("========TIMEOUT==========\n");
						printPort(targetSo);
						printf("Retransmit pacekt with expectedACK %u\n", expectedACKnum);
					}

					// MSS 안될때?

					/* start Timer */
					pd->sent_time = currentTime();
					targetSo->tcpTimer = TimerModule::addTimer(tp, TimeUtil::makeTime(targetSo->timeoutInterval, TimeUtil::USEC));
					targetSo->isTcpTimerRunning = true;
					targetSo->seq_num = expectedACKnum;
				}

			}
			// 연속해서 계속 다시 received된 segment도 보내는 문제?

			
			// printf("%lu elements\n", targetSo->expectedACKBuffer.size());
		}
		break;
	}
}

void TCPAssignment::process_received_data(SocketObject* so, TCPHeader* tcp, Packet* packet) {
	uint32_t recvSeqNum = ntohl(tcp->seq_num) - so->peer_seq_base;
	uint32_t recvDataLength = packet->getSize()- TCP_DATA_OFFSET;
	int flag = tcp->flag;
	// printf("Received Seq:%u\tExpected Seq:%u\n",recvSeqNum, so->expected_recvSeqNum);

	if (IS_SET(flag, FLAG_ACK)) {
		uint32_t recvACKNum = ntohl(tcp->ack_num) - so->local_seq_base;
		so->rwnd_peer = ntohs(tcp->window_size); // update peer's window size
		if (so->receivedACKBuffer.count(recvACKNum) == 1) {
			so->dupACKcount++;
			printf("Dup ACK!\n");
		} else {
			so->dupACKcount = 0;
		}

		if (so->expectedACKBuffer.count(recvACKNum) == 1) { // acceptable ACK received
			/* Calculate RTT and Timeout Value */
			struct packet_data *recvPd = so->expectedACKBuffer[recvACKNum];

			uint32_t sampleRTT = TimeUtil::getTime(this->getHost()->getSystem()->getCurrentTime() - recvPd->sent_time, TimeUtil::USEC);
			so->estimatedRTT = (1 - ALPHA) * so->estimatedRTT + ALPHA * sampleRTT;
			// if(VERBOSE)
			// 	printf("Port: %hd\tACK   %u   RTT:   %u    Time:    %lu\n", ntohs(so->get_port()), recvACKNum, sampleRTT, currentTime()/1000);
			so->devRTT = (1 - BETA)*so->devRTT + BETA * ABS(sampleRTT, so->estimatedRTT);
			so->timeoutInterval = so->estimatedRTT + K * 10000;

			// printf("timeoutInterval%u\n",so->timeoutInterval);  
			// if(VERBOSE) printf("congestionPacketSize:%u\n", so->congestionPacketSize);

			so->receivedACKBuffer[recvACKNum] = packet;
			
			while (!so->receivedACKBuffer.empty()) {
				auto received = so->receivedACKBuffer.begin();
				auto expected = so->expectedACKBuffer.begin();
				if (expected->first > received->first) {
					break; // wait first expected ACK
				}
				struct packet_data *pd = expected->second;
				so->sendBase = expected->first;	// Move sendBase
				if (so->seq_num - so->local_seq_base < so->sendBase) {
					so->seq_num = so->sendBase + so->local_seq_base;
				}
				uint32_t successPayloadSize = pd->packet->getSize() - TCP_DATA_OFFSET;
				
				/* Delete Packet from Buffer */ 
				if (so->congestionState == Congestion::SlowStart) 
					so->sendWindowPayloadSize -= successPayloadSize;
				else
					so->congestionPacketSize -= successPayloadSize;	
				this->freePacket(expected->second->packet);
				free(pd);
				
				// Free resource
				// printf("============expectd first: %u, received first:%u\n",expected->first, received->first);
				if (expected->first == received->first) {
					so->receivedACKBuffer.erase(received);
					this->freePacket(received->second);
				}
				so->expectedACKBuffer.erase(expected);
			}	


			/* Congestion control */
			switch (so->congestionState) {
				case Congestion::SlowStart:
				{
					so->cwnd += MSS;		// +MSS for every ACK
					if (so->cwnd > so->sshthresh) {
					if (VERBOSE) {
						printPort(so);
						printf("Transition: SlowStart -> CA\n");
					}
						so->congestionState = Congestion::Avoidance; // state Transition
						so->congestionPacketSize = so->cwnd;
					} 
				}
				break;
				case Congestion::Avoidance:
				{
					if (so->congestionPacketSize <= 0) { // one RTT is finished
						so->cwnd += MSS; // +MSS for RTT
						so->sendWindowPayloadSize = 0;	// write can send data
						so->congestionPacketSize =  so->cwnd;
					} 
				}
				break;
			}


			/* Timer Management */
			if (so->isTcpTimerRunning) {
				TimerModule::cancelTimer(so->tcpTimer);
				so->isTcpTimerRunning = false;
				delete so->tp;
			}
			if (!so->expectedACKBuffer.empty()) { // if unacked Packet exist
				TimerPayload *tp = new TimerPayload(TIMER::TIME_OUT, so);
				so->tcpTimer = TimerModule::addTimer(tp, TimeUtil::makeTime(so->timeoutInterval, TimeUtil::USEC));
				so->isTcpTimerRunning = true;
			}

			if (so->isWriting) {
				internal_write(so);
			}

		}

		if (recvDataLength > 0) { // if packet has payload
			if (recvSeqNum < so->recvBase + so->rwnd) {
				/* insert Window Buffer */
				so->recvWindowBuffer[recvSeqNum] = packet;
				so->rwnd -= recvDataLength;
				
				/* Send ACK Packet */
				Packet* ackPacket = this->allocatePacket(TCP_OFFSET+20);
				tcp->window_size = htons(so->rwnd);
				if (recvSeqNum == so->expected_recvSeqNum){ // correct data with correct order
					send_ACK_Packet(so->ack_num+recvDataLength, so, tcp, ackPacket);
				} else {
					send_ACK_Packet(so->ack_num, so, tcp, ackPacket); 
				}

				/* Process if well-ordered sequence exits */
				while (!so->recvWindowBuffer.empty()) {
					auto received = so->recvWindowBuffer.begin();
					if (so->expected_recvSeqNum != received->first) {
						break; // wait until correct ordered sequence packet
					}

					so->expected_recvSeqNum += recvDataLength;
					so->recvBase += recvDataLength;
					so->readBuffer[recvSeqNum] = packet;	// insert Read Buffer
					so->recvWindowBuffer.erase(recvSeqNum);
				}
				if (so->isReading){
					internal_read(so);
				}
			}
		}
	}
}

void TCPAssignment::send_ACK_Packet(int ack_num, SocketObject* so, TCPHeader* tcp, Packet* packet){
	tcp->swap_ip();
	tcp->swap_port();
	tcp->seq_num = htonl(so->seq_num); // Sequence Number
	tcp->ack_num = htonl(ack_num); // ACK Number
	tcp->flag = FLAG_ACK; // ACK Flag
	packet->writeData(0, tcp->calculateHeader(), TCP_OFFSET+20);
	this->sendPacket("IPv4", packet);
	so->ack_num = ack_num;
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

void TCPAssignment::map_dump (std::map<uint32_t, Packet *> m, const char* name){
	printf("%s: [", name);
	for (auto &kv : m) {
		printf("%u, " ,kv.first);
	}
	printf("]\n");
}

void TCPAssignment::map_dump (std::map<uint32_t, struct packet_data *> m, const char* name){
	printf("%s: [", name);
	for (auto &kv : m) {
		printf("%u, " ,kv.first);
	}
	printf("]\n");
}

void TCPAssignment::printPort(SocketObject* so){
	printf("Port %hu\t", ntohs(so->get_port()));
}

}



/* TO DO List,
	client -- RST 받았을때 구현
	Timeout 되었을때 buffer 에 남은 것들 어찌 해야하는지?
	*/
