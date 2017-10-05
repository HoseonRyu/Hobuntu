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
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <map>

#include <E/E_TimerModule.hpp>

namespace E
{

enum State {
	CLOSED,
	SYN_SENT,
	ESTABLISHED
};

class SocketObject {
public:
	int fd;
	
	int domain;
	int type;
	int protocol;

	struct sockaddr addr;
	struct sockaddr peer_addr;
	bool is_bound;

	State state;

	Host* host;
	UUID syscallUUID;
	int seq_num;

	// all of value is network-order
	SocketObject(){}
	SocketObject(int fd_){
		this->fd = fd_;
		this->seq_num = 0;
		bzero(&this->addr, sizeof(struct sockaddr));
		this->is_bound = false;
		this->state = State::CLOSED;
	}
	sa_family_t get_family(){
		return ((struct sockaddr_in *)&this->addr)->sin_family;
	}
	in_port_t get_port(){
		return ((struct sockaddr_in *)&this->addr)->sin_port;
	}
	uint32_t get_ip_address(){
		return ((struct sockaddr_in *)&this->addr)->sin_addr.s_addr;
	}
	void set_family(int family){
		((struct sockaddr_in *)&this->addr)->sin_family = family;
	}
	void set_port(int port){
		((struct sockaddr_in *)&this->addr)->sin_port = htons(port);
	}
	void set_ip_address(uint8_t* ip){
		memcpy (&(((struct sockaddr_in *)&this->addr)->sin_addr.s_addr), ip, 4);
	}
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
public:
	std::map<int, SocketObject*> socket_map;
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
	
	SocketObject* getSocketObject(uint32_t ip, uint16_t port);
	bool is_binding_overlap (SocketObject *so1, SocketObject *so2);
	void hex_dump(void* buf, int ofs, int size);
	int implicit_bind (int sockfd);
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

#define IP_OFFSET 14
#define TCP_OFFSET IP_OFFSET+20
#define PSEUDO_HEADER_LEN 12


#define FLAG_ACK 0x10
#define FLAG_SYN 0x02
#define FLAG_FIN 0x01

#endif /* E_TCPASSIGNMENT_HPP_ */