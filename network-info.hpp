#ifndef ND_NETWORK_INFO_HPP
#define ND_NETWORK_INFO_HPP

#include <ndn-cxx/face.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <iostream>
#include <chrono>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/util/scheduler.hpp>

#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/security/safe-bag.hpp>

#include <boost/asio.hpp>
#include <sstream>

#include "nd-tlv.hpp"
namespace ndn{

class NetworkInfo
{
public:
  NetworkInfo(std::string port = std::to_string(6363))
    : m_port(port)
  {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    char netmask[NI_MAXHOST];
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == NULL)
        continue;

      s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
      s = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

      if (ifa->ifa_addr->sa_family==AF_INET) {
        if (s != 0) {
          printf("getnameinfo() failed: %s\n", gai_strerror(s));
          exit(EXIT_FAILURE);
        }
        if (ifa->ifa_name[0] == 'l' && ifa->ifa_name[1] == 'o')   // Loopback
          continue;
        printf("\tInterface : <%s>\n", ifa->ifa_name);
        printf("\t  Address : <%s>\n", host);
        
        m_ipAddr = host;
        m_netmask = netmask;
        break;
      }
    }
    freeifaddrs(ifaddr);
  }
  std::string& getIpAddr() {
    return m_ipAddr;
  }
  std::string& getPort() {
    return m_port;
  }
  std::string& getNetmask() {
    return m_netmask;
  }
private:
  std::string m_ipAddr;
  std::string m_port;
  std::string m_netmask;
};

}

#endif