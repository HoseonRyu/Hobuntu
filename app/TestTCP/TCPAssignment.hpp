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

class SocketObject {
private:
	
public:
	int fd;
	
	int domain;
	int type;
	int protocol;

	struct sockaddr addr;
	bool is_bound;

	Host* host;

	SocketObject();
	SocketObject(int fd);
	in_port_t get_port();
	uint32_t get_ip_address();
	void set_family(int family);
	void set_port(int port);
	void set_ip_address(uint8_t* ip);
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
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
	bool is_binding_overlap (SocketObject *so1, SocketObject *so2);
	void syscall_getsockname (UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr* serv_addr, socklen_t addrlen);
	void hex_dump(void* buf, int ofs, int size);
	int implicit_bind (int sockfd);
	unsigned short get_checksum(void* header, int len);
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

#endif /* E_TCPASSIGNMENT_HPP_ */