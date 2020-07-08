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
#include "nd-client.hpp"

using namespace ndn;

class Options
{
public:
  Options()
    : m_flatID("alice")
  {
  }
public:
  ndn::Name m_flatID;
};


// class NetworkInfo
// {
// public:
//   NetworkInfo(std::string port = std::to_string(6363))
//     : m_port(port)
//   {
//     struct ifaddrs *ifaddr, *ifa;
//     int family, s;
//     char host[NI_MAXHOST];
//     char netmask[NI_MAXHOST];
//     if (getifaddrs(&ifaddr) == -1) {
//         perror("getifaddrs");
//         exit(EXIT_FAILURE);
//     }

//     for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
//       if (ifa->ifa_addr == NULL)
//         continue;

//       s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
//       s = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

//       if (ifa->ifa_addr->sa_family==AF_INET) {
//         if (s != 0) {
//           printf("getnameinfo() failed: %s\n", gai_strerror(s));
//           exit(EXIT_FAILURE);
//         }
//         if (ifa->ifa_name[0] == 'l' && ifa->ifa_name[1] == 'o')   // Loopback
//           continue;
//         printf("\tInterface : <%s>\n", ifa->ifa_name);
//         printf("\t  Address : <%s>\n", host);
        
//         m_ip_addr = host;
//         m_netmask = netmask;
//         break;
//       }
//     }
//     freeifaddrs(ifaddr);
//   }
//   std::string getIpAddr() {
//     return m_ip_addr;
//   }
//   std::string getPort() {
//     return m_port;
//   }
//   std::string getNetmask() {
//     return m_netmask;
//   }
// private:
//   std::string m_ip_addr;
//   std::string m_port;
//   std::string m_netmask;
// };

class BootstrapClient{
public:
  BootstrapClient(const Name& flatID)
    : m_flatID(flatID)
  {
  }

  ~BootstrapClient()
  {
    delete m_ndClient;
  }

  void sendSignOnReq() 
  {
    Interest interest("/ndn/sign-on/1234");
    m_face.expressInterest(interest, bind(&BootstrapClient::onSignOnRes, this, _1, _2),
                                     bind(&BootstrapClient::onNack, this, _1, _2),
                                     bind(&BootstrapClient::onSignOnTimeout, this, _1));
  }

  void sendCertReq() 
  {
    Name req_name(m_root);
    auto session = std::to_string(random::generateSecureWord64());
    req_name.append("cert").append(m_flatID).append(session);
    Interest req(req_name);

    // ten seconds lifetime
    req.setInterestLifetime(10_s);
    req.setMustBeFresh(true);
    m_face.expressInterest(req, bind(&BootstrapClient::onCertRes, this, _1, _2),
                                     bind(&BootstrapClient::onNack, this, _1, _2),
                                     bind(&BootstrapClient::onCertReqTimeout, this, _1));
  }


  // void sendArrivalInterest()
  // {
  //   Name name(m_root);
  //   name.append("nd").append("arrival").append(std::to_string(m_cert.getIdentity().size())).append(m_cert.getIdentity())
  //       .append(m_networkinfo.getIpAddr()).append(m_networkinfo.getPort())
  //       .appendTimestamp();

  //   Interest interest(name);
  //   interest.setInterestLifetime(10_s);
  //   interest.setMustBeFresh(true);
  //   interest.setNonce(4);
  //   interest.setCanBePrefix(false); 

  //   std::cout << "NDND (Client): Arrival Interest: " << interest << std::endl;

  //   m_face.expressInterest(interest, bind(&BootstrapClient::onArrivalAck, this, _1, _2), 
  //                                    bind(&BootstrapClient::onNack, this, _1, _2),
  //                                    bind(&BootstrapClient::onArrivalTimeout, this, _1)); //no expectation
  // }


  // void sendNeighborDiscoveryInterest()
  // {
  //   Name name(m_root);
  //   name.append("nd").append("nd-info").appendTimestamp();

  //   Interest interest(name);
  //   interest.setInterestLifetime(10_s);
  //   interest.setMustBeFresh(true);
  //   interest.setNonce(4);
  //   interest.setCanBePrefix(false); 

  //   std::cout << "NDND (Client): Info Interest: " << interest << std::endl;

  //   m_face.expressInterest(interest, bind(&BootstrapClient::onNeighborDiscoveryData, this, _1, _2), 
  //                                    bind(&BootstrapClient::onNack, this, _1, _2),
  //                                    bind(&BootstrapClient::onNeighborDiscoveryTimeout, this, _1)); //no expectation
  // }




private:
  void onSignOnRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;

    // this is anchor
    security::v2::Certificate anchor(data.getContent().blockFromValue());
    m_root = anchor.getIdentity();

    std::cout << "system root prefix: " << m_root << std::endl;
    std::cout << "anchor cert: " << anchor << std::endl;


    m_anchor = anchor;

    sendCertReq();
  }


  void onCertRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    security::SafeBag safebag(data.getContent().blockFromValue());
    const char* passwd = "1234";

    Name identityName(m_root);
    identityName.append(m_flatID);
    m_keyChain.importSafeBag(safebag, passwd, strlen(passwd));
    security::v2::Certificate cert(safebag.getCertificate());
    m_cert = cert;
    
    // this is my cert
    std::cout << m_cert << std::endl;

    // sendArrivalInterest();
    addConnectivity();
  }

  void addConnectivity()
  {
    m_ndClient = new nd::NDClient(m_root, m_cert, &m_face);
    m_ndClient->sendArrivalInterest();
  }
  // void onArrivalAck(const Interest& interest, const Data& data)
  // {
  //   std::cout << data << std::endl;
  //   sendNeighborDiscoveryInterest();
  // }


  // void onNeighborDiscoveryData(const Interest& interest, const Data& data)
  // {
  //   std::cout << data << std::endl;

  //   Block payload(data.getContent().value(), data.getContent().value_size());
  //   payload.parse();
  //   std::cout << "Output Block: " << payload << std::endl;
  //   if (payload.type() != nd::tlv::NeighborInfo)
  //     std::cout << "wrong start: " << payload.type() << std::endl;

  //     // Param
  //     Block::element_const_iterator val = payload.find(nd::tlv::NeighborParameter);
  //     // now are name + ip + port

  //     // Name
  //     while(val != payload.elements_end())
  //     {
  //       Block param = *val;
  //       param.parse();
  //       std::cout << "Output Block: " << param << std::endl;
  //       Block::element_const_iterator param_val = param.find(tlv::Name);
  //       if (param_val != param.elements_end())
  //       {
  //         Name neighbor_name;
  //         neighbor_name.wireDecode(param.get(tlv::Name));
  //         std::cout << neighbor_name << std::endl;
  //       }
  //       // Ip
  //       param_val = param.find(nd::tlv::NeighborIpAddr);
  //       if (param_val != param.elements_end())
  //       {
  //         std::string ip_str = readString(*param_val);
  //         std::cout << ip_str << std::endl;
  //       }
  //       // Port
  //       param_val = param.find(nd::tlv::NeighborPort);
  //       if (val != param.elements_end())
  //       {
  //         std::string port = readString(*param_val);
  //         std::cout << port << std::endl;
  //       }

  //       payload.erase(val);
  //       val = payload.find(nd::tlv::NeighborParameter);
  //     }
  // }



  void onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
  }

  void onSignOnTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
    sendSignOnReq();
  }

  void onCertReqTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
    sendCertReq();
  }
  
  // void onArrivalTimeout(const Interest& interest)
  // {
  //   std::cout << "Timeout " << interest << std::endl;
  //   sendArrivalInterest();
  // }

  // void onNeighborDiscoveryTimeout(const Interest& interest)
  // {
  //   std::cout << "Timeout " << interest << std::endl;
  //   sendNeighborDiscoveryInterest(); 
  // }

public:
  bool is_ready = false;    // Ready after creating face and route to ND server

  KeyChain m_keyChain;
  security::v2::Certificate m_anchor;
  security::v2::Certificate m_cert;

  Name m_flatID;
  Name m_root;

  Face m_face;
  NetworkInfo m_networkinfo;
  nd::NDClient *m_ndClient;
  
};


class Program
{
public:
  explicit Program(const Options& options)
    : m_options(options)
  {
    // Init client
    m_client = new BootstrapClient(m_options.m_flatID);
    m_client->sendSignOnReq();
  }


  ~Program() {
    delete m_client;
  }

  BootstrapClient *m_client;

private:
  const Options m_options;
  boost::asio::io_service m_io_service;
};


int
main(int argc, char** argv)
{
  Options opt;
  Program program(opt);
  program.m_client->m_face.processEvents();
}