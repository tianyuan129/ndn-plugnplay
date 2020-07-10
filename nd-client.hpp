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
#include <boost/asio.hpp>
#include <sstream>

#include "nd-tlv.hpp"
#include "network-info.hpp"

namespace ndn{
namespace nd{

class NDClient{
public:
  NDClient(const Name& rootPrefix, 
           const std::string& rvIpAddr,
           security::v2::Certificate& certificate,
           Face* face);

  // this will learn route to RV by self learning
  NDClient(const Name& rootPrefix,
           security::v2::Certificate& certificate,
           Face* face);

  ~NDClient();
  // TODO: remove face on SIGINT, SIGTERM
  void registerRoute(const Name& routeName, int faceId,
                     int cost = 0, bool isRvRoute = false);

  void onRvProbeInterest(const Interest& interest);
  
  void sendArrivalInterest();

//   void registerSubPrefix();

  void sendNeighborDiscoveryInterest();

// private:
  void onArrivalAck(const Interest& interest, const Data& data);


  void onNeighborDiscoveryData(const Interest& interest, const Data& data);

  void onNack(const Interest& interest, const lp::Nack& nack);

  void onTimeout(const Interest& interest);

  void onArrivalTimeout(const Interest& interest);

  void onNeighborDiscoveryTimeout(const Interest& interest);

  void onRegisterRouteDataReply(const Interest& interest, const Data& data,
                                bool isRvRoute);

  void onAddFaceDataReply(const Interest& interest, const Data& data,
                          const std::string& uri, bool isRvRoute);

  void onDestroyFaceDataReply(const Interest& interest, const Data& data);
  void addFace(const std::string& uri, bool isRvRoute = false);

  void destroyFace(int faceId);

  void onSetStrategyDataReply(const Interest& interest, const Data& data);

  void setStrategy(const std::string& uri, const std::string& strategy);

public:
  bool is_ready = false;    // Ready after creating face and route to ND server
  Name m_root;
  Face *m_face;
  KeyChain m_keyChain;

  security::v2::Certificate m_cert;

  NetworkInfo m_networkInfo;
  std::string m_rvIpAddr;
  int m_rvFaceId;
  
  Scheduler *m_scheduler;
  uint8_t m_buffer[4096];
  size_t m_len;
  std::map<std::string, std::string> m_uriToPrefix;
};

} //namespace nd
} //namespace ndn