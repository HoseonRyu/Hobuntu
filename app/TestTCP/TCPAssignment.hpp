/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Packet.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <map>
#include <queue>

#include <E/E_TimerModule.hpp>

#define IP_OFFSET 14
#define TCP_OFFSET IP_OFFSET+20
#define PSEUDO_HEADER_LEN 12

#define REMOTE false

#define FLAG_ACK 0x10
#define FLAG_RST 0x04
#define FLAG_SYN 0x02
#define FLAG_FIN 0x01

#define IS_SET(flag, test) ((flag & test) != 0)

namespace E
{

enum State {
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_RECV,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSE_WAIT,
	CLOSING,
	LAST_ACK,
	TIME_WAIT
};

enum SOCKET {
	CLIENT,
	SERVER,
	NONE = -1
};

class SocketObject {
public:
	int fd;							// socket file descriptor
	int pid;						// process id
	int type;						// is socket client or server?

	/*
	// parameter from socket() function
	int domain;	
	int type;
	int protocol;
	*/
	struct sockaddr local_addr;			// Address information of socket
	struct sockaddr peer_addr;		// Address information of peer socket
	bool is_bound;					// true if socket is bound

	State state;					// TCP state

	// For Internel Data transfer
	UUID syscallUUID;
	int seq_num;
	int ack_num;

	// For Server socket
	int accept_fd;
	bool is_listening;
	int backlog_max;
	struct sockaddr* temp_addr;

	int backlog;
	std::queue<SocketObject *> pending_queue;

	// all of value is network-order
	SocketObject(){}
	SocketObject(int pid_, int fd_){
		this->pid = pid_;
		this->fd = fd_;
		this->type = SOCKET::NONE;

		// // Default Value of Socket (IPv4)
		// this->domain = AF_INET;
		// this->type = SOCK_STREAM;
		// this->protocol = IPPROTO_TCP;

		this->seq_num = 0;
		memset(&this->local_addr, 0, sizeof(struct sockaddr));
		memset(&this->peer_addr, 0, sizeof(struct sockaddr));
		this->is_bound = false;
		this->state = State::CLOSED;

		this->temp_addr = NULL;
		this->accept_fd = -1;
		this->is_listening = false;
		this->backlog_max = 0;
		this->backlog = 0;
	}
	sa_family_t get_family(bool local = true){
		struct sockaddr *addr = (local) ? &this->local_addr : &this->peer_addr;
		return ((struct sockaddr_in *)addr)->sin_family;
	}
	in_port_t get_port(bool local = true){
		struct sockaddr *addr = (local) ? &this->local_addr : &this->peer_addr;
		return ((struct sockaddr_in *)addr)->sin_port;
	}
	uint32_t get_ip_address(bool local = true){
		struct sockaddr *addr = (local) ? &this->local_addr : &this->peer_addr;
		return ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	}
	void set_family(int family, bool local = true){
		struct sockaddr *addr = (local) ? &this->local_addr : &this->peer_addr;
		((struct sockaddr_in *)addr)->sin_family = family;
	}
	void set_port(int port, bool local = true){
		struct sockaddr *addr = (local) ? &this->local_addr : &this->peer_addr;
		((struct sockaddr_in *)addr)->sin_port = htons(port);
	}
	void set_ip_address(uint8_t* ip, bool local = true){
		struct sockaddr *addr = (local) ? &this->local_addr : &this->peer_addr;
		memcpy (&(((struct sockaddr_in *)addr)->sin_addr.s_addr), ip, 4);
	}
};

/* TCP Header Class for Packet <-> TCP Header Management
 * ALL values is network-ordered */
class TCPHeader {
private:
	uint8_t* header;
public:
	uint32_t src_ip;
	uint32_t dest_ip;

	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t offset;
	uint8_t flag;
	uint16_t window_size;
	//uint16_t checksum;
	uint16_t urgent;

	TCPHeader() {
		init_value();
		this->header = (uint8_t *)malloc(TCP_OFFSET+20);
	}
	TCPHeader(Packet* packet) {
		this->header = (uint8_t *)malloc(TCP_OFFSET+20);
		this->getHeaderFromPacket(packet);
	}
	~TCPHeader() {
		free(this->header);
	}
	uint8_t* calculateHeader() {
		*(uint32_t *)(header+IP_OFFSET+12) = this->src_ip;
		*(uint32_t *)(header+IP_OFFSET+16) = this->dest_ip;
		
		*(uint16_t *)(header+TCP_OFFSET+0) = this->src_port;
		*(uint16_t *)(header+TCP_OFFSET+2) = this->dest_port;
		*(uint32_t *)(header+TCP_OFFSET+4) = this->seq_num;
		*(uint32_t *)(header+TCP_OFFSET+8) = this->ack_num;
		*(uint8_t *)(header+TCP_OFFSET+12) = this->offset;
		*(uint8_t *)(header+TCP_OFFSET+13) = this->flag;
		*(uint16_t *)(header+TCP_OFFSET+14) = this->window_size;
		*(uint16_t *)(header+TCP_OFFSET+16) = 0x0000; //initial checksum
		*(uint16_t *)(header+TCP_OFFSET+18) = this->urgent;
		*(uint16_t *)(header+TCP_OFFSET+16) = this->get_TCPchecksum(header, 20);
		return header;
	}
	void swap_ip() {
		uint32_t temp = this->src_ip;
		this->src_ip = this->dest_ip;
		this->dest_ip = temp;
	}
	void swap_port(){
		uint16_t temp = this->src_port;
		this->src_port = this->dest_port;
		this->dest_port = temp;
	}
	void getHeaderFromPacket(Packet* packet){
		packet->readData(0, this->header, TCP_OFFSET+20);
		this->src_ip 	= *(uint32_t *)(header+IP_OFFSET+12);
		this->dest_ip 	= *(uint32_t *)(header+IP_OFFSET+16);
		this->src_port 	= *(uint16_t *)(header+TCP_OFFSET+0);
		this->dest_port = *(uint16_t *)(header+TCP_OFFSET+2);
		this->seq_num = *(uint32_t *)(header+TCP_OFFSET+4);
		this->ack_num = *(uint32_t *)(header+TCP_OFFSET+8);
		this->offset = *(uint8_t *)(header+TCP_OFFSET+12);
		this->flag = *(uint8_t *)(header+TCP_OFFSET+13);
		this->window_size = *(uint16_t *)(header+TCP_OFFSET+14);
		this->urgent = *(uint16_t *)(header+TCP_OFFSET+18);
	}
private:
	void init_value(){
		src_ip = 0;
		dest_ip = 0;
		src_port = 0;
		dest_port = 0;
		seq_num = 0;
		ack_num = 0;
		offset = 0;
		flag = 0;
		window_size = 0;
		urgent = 0;
	}
	/* len is length of only TCP Header */
	unsigned short get_TCPchecksum(uint8_t* header, int len) {
		// Construct pseudo header
		uint8_t pseudo_header[PSEUDO_HEADER_LEN]; 
		memset(pseudo_header, 0, PSEUDO_HEADER_LEN);
		memcpy(pseudo_header, header+IP_OFFSET+12, 4); // source ip
		memcpy(pseudo_header+4, header+IP_OFFSET+16, 4); // dest ip
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
			sum += *(unsigned short *)(header+TCP_OFFSET+2*i);
			sum = (sum + (sum >> 16)) & 0xFFFF;
		};
		return ~((unsigned short)sum);
	}
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
public:
	std::map<int, std::map<int, SocketObject*>> socket_map;
private:
	virtual void timerCallback(void* payload) final;
public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	void syscall_socket(UUID syscallUUID, int pid, int protocolFamily, int type, int protoco) ;
	void syscall_close(UUID syscallUUID, int pid, int param1);
	void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *myaddr, socklen_t addrlen);
	void syscall_getsockname (UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	
	void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr* serv_addr, socklen_t addrlen);
	void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	
	SocketObject* getSocketObject(int pid, int fd);
	SocketObject* getSocketObjectByContext(uint32_t local_ip, uint16_t local_port, 
		uint32_t remote_ip, uint16_t remote_port);
	SocketObject* getListenSocketByContext(uint32_t local_ip, uint16_t local_port);
	bool is_binding_overlap (SocketObject *so1, SocketObject *so2);
	void hex_dump(void* buf, int ofs, int size);
	int implicit_bind (int pid, int sockfd);
	unsigned short get_TCPchecksum(void* header, uint8_t *src_ip, uint8_t *dest_ip, int len);
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};


}

#endif /* E_TCPASSIGNMENT_HPP_ */