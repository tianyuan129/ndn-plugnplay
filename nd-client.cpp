
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
#include "nfdc-helpers.h"
#include "nd-param.hpp"
#include "nd-client.hpp"

namespace ndn{
namespace nd{


NDClient::NDClient(const Name& rootPrefix, 
                   const std::string& rvIpAddr,
                   security::v2::Certificate& certificate,
                   Face* face)
    : m_root(rootPrefix)
    , m_rvIpAddr(rvIpAddr)
    , m_cert(certificate)
    , m_face(face)
{
  m_scheduler = new Scheduler(m_face->getIoService());
  is_ready = false;

  // Bootstrap face and route to server
  std::stringstream ss;
  ss << "udp4://" << m_rvIpAddr << ':' << "6363";
  addFace(ss.str());
}

NDClient::NDClient(const Name& rootPrefix,
                   security::v2::Certificate& certificate,
                   Face* face)
    : m_root(rootPrefix)
    , m_cert(certificate)
    , m_face(face)
{
  m_scheduler = new Scheduler(m_face->getIoService());
  is_ready = true;
}

NDClient::~NDClient()
{
  delete m_scheduler;
}
  // TODO: remove face on SIGINT, SIGTERM
void
NDClient::registerRoute(const Name& routeName, int faceId, int cost, bool isRvRoute) 
{
  Interest interest = prepareRibRegisterInterest(routeName, faceId, m_keyChain, cost);
  m_face->expressInterest(interest, bind(&NDClient::onRegisterRouteDataReply, this, _1, _2, isRvRoute),
                                   bind(&NDClient::onNack, this, _1, _2),
                                   bind(&NDClient::onTimeout, this, _1));
}

void
NDClient::onRvProbeInterest(const Interest& interest)
{
  NDParam neighborParam(m_networkInfo);
  neighborParam.setName(m_cert.getIdentity());

  Data result;
  result.setName(interest.getName());
  result.setContent(neighborParam.wireEncode());
  result.setFreshnessPeriod(time::milliseconds(4000));
  m_keyChain.sign(result, signingByCertificate(m_cert));
  m_face->put(result);
  std::cout << "reply probe with data: " << result << std::endl;
}

void  
NDClient::sendArrivalInterest()
{
  if (!is_ready) {
    std::cout << "not ready, try again" << std::endl;
    m_scheduler->schedule(time::seconds(1), [this] {
        sendArrivalInterest();
    });
    return;
  }

  Name name(m_root);
  name.append("nd").append("arrival").append(std::to_string(m_cert.getIdentity().size())).append(m_cert.getIdentity())
      .append(m_networkInfo.getIpAddr()).append(m_networkInfo.getPort())
      .appendTimestamp();

  Interest interest(name);
  interest.setInterestLifetime(10_s);
  interest.setMustBeFresh(true);
  interest.setNonce(4);
  interest.setCanBePrefix(false); 

  std::cout << "Arrival Interest: " << interest << std::endl;

  m_face->expressInterest(interest, bind(&NDClient::onArrivalAck, this, _1, _2), 
                                    bind(&NDClient::onNack, this, _1, _2),
                                    bind(&NDClient::onArrivalTimeout, this, _1)); //no expectation
}

void
NDClient::sendNeighborDiscoveryInterest()
{
  if (!is_ready)
    return;

  Name name(m_root);
  name.append("nd").append("nd-info").appendTimestamp();

  Interest interest(name);
  interest.setInterestLifetime(10_s);
  interest.setMustBeFresh(true);
  interest.setNonce(4);
  interest.setCanBePrefix(false); 

  std::cout << "Info Interest: " << interest << std::endl;

  m_face->expressInterest(interest, bind(&NDClient::onNeighborDiscoveryData, this, _1, _2), 
                                    bind(&NDClient::onNack, this, _1, _2),
                                    bind(&NDClient::onNeighborDiscoveryTimeout, this, _1)); //no expectation
}

// private:
void
NDClient::onArrivalAck(const Interest& interest, const Data& data)
{
  std::cout << data << std::endl;
  Name name(m_cert.getIdentity());
  name.append("nd-info");
  m_face->setInterestFilter(InterestFilter(name), bind(&NDClient::onRvProbeInterest, this, _2), nullptr);
  sendNeighborDiscoveryInterest();
}

void
NDClient::onNeighborDiscoveryData(const Interest& interest, const Data& data)
{
  std::cout << data << std::endl;

  Block neighborInfo(data.getContent().value(), data.getContent().value_size());
  neighborInfo.parse();
  std::cout << "Output Block: " << neighborInfo << std::endl;
  if (neighborInfo.type() != nd::tlv::NeighborInfo)
    std::cout << "wrong start: " << neighborInfo.type() << std::endl;

  // Param
  Block::element_const_iterator infoVal = neighborInfo.find(nd::tlv::NeighborParameter);

  // Parse all neighbor parameters till the end
  while(infoVal != neighborInfo.elements_end())
  {
    Name nameParam;
    std::string ipParam, portParam;
    NDParam neighborParam(*infoVal);
    nameParam = neighborParam.getName();
    ipParam = neighborParam.getIpAddr();
    portParam = neighborParam.getPort();
    neighborInfo.erase(infoVal);
    infoVal = neighborInfo.find(nd::tlv::NeighborParameter);

    // add face and route
    if (ipParam == m_networkInfo.getIpAddr())
    {
      std::cout << "my self ip returned, do nothing" << std::endl;
      continue;
    }

    std::stringstream ss;
    ss << "udp4://" << ipParam << ':' << portParam;
    m_uriToPrefix[ss.str()] = nameParam.toUri();
    addFace(ss.str());
    setStrategy(nameParam.toUri(), BEST_ROUTE);
  }
}
void
NDClient::onNack(const Interest& interest, const lp::Nack& nack)
{
  std::cout << "received Nack with reason " << nack.getReason()
            << " for interest " << interest << std::endl;
}
void
NDClient::onTimeout(const Interest& interest)
{
  std::cout << "Timeout " << interest << std::endl;
}

void
NDClient::onArrivalTimeout(const Interest& interest)
{
  std::cout << "Timeout " << interest << std::endl;
  sendArrivalInterest();
}
  
void
NDClient::onNeighborDiscoveryTimeout(const Interest& interest)
{
  std::cout << "Timeout " << interest << std::endl;
  sendNeighborDiscoveryInterest(); 
}

void 
NDClient::onRegisterRouteDataReply(const Interest& interest, const Data& data,
                                   bool isRvRoute)
{
  Block responseBlock = data.getContent().blockFromValue();
  responseBlock.parse();

  std::cout << responseBlock << std::endl;

  Block statusCodeBlock = responseBlock.get(STATUS_CODE);
  Block statusTextBlock = responseBlock.get(STATUS_TEXT);
  short responseCode = readNonNegativeIntegerAs<int>(statusCodeBlock);
  char responseText[1000] = {0};
  memcpy(responseText, statusTextBlock.value(), statusTextBlock.value_size());

  if (responseCode == OK) {

    Block controlParams = responseBlock.get(CONTROL_PARAMETERS);
    controlParams.parse();

    Block nameBlock = controlParams.get(ndn::tlv::Name);
    Name routeName(nameBlock);
    Block faceIdBlock = controlParams.get(FACE_ID);
    int faceId = readNonNegativeIntegerAs<int>(faceIdBlock);
    Block originBlock = controlParams.get(ORIGIN);
    int origin = readNonNegativeIntegerAs<int>(originBlock);
    Block routeCostBlock = controlParams.get(COST);
    int routeCost = readNonNegativeIntegerAs<int>(routeCostBlock);
    Block flagsBlock = controlParams.get(FLAGS);
    int flags = readNonNegativeIntegerAs<int>(flagsBlock);

    std::cout << "\nRegistration of route succeeded:" << std::endl;
    std::cout << "Status text: " << responseText << std::endl;

    std::cout << "Route name: " << routeName.toUri() << std::endl;
    std::cout << "Face id: " << faceId << std::endl;
    std::cout << "Origin: " << origin << std::endl;
    std::cout << "Route cost: " << routeCost << std::endl;
    std::cout << "Flags: " << flags << std::endl;

    if (isRvRoute) {
      is_ready = true;
      std::cout << "NDND (Client): Bootstrap succeeded\n";
    }

    is_ready = true;
  }
  else {
    std::cout << "\nRegistration of route failed." << std::endl;
    std::cout << "Status text: " << responseText << std::endl;
  }
}
void
NDClient::onAddFaceDataReply(const Interest& interest, const Data& data,
                             const std::string& uri, bool isRvRoute) 
{
  short responseCode;
  char responseText[1000] = {0};
  int faceId;                      // Store faceid for deletion of face
  Block responseBlock = data.getContent().blockFromValue();
  responseBlock.parse();

  Block statusCodeBlock = responseBlock.get(STATUS_CODE);
  Block statusTextBlock = responseBlock.get(STATUS_TEXT);
  responseCode = readNonNegativeIntegerAs<int>(statusCodeBlock);
  memcpy(responseText, statusTextBlock.value(), statusTextBlock.value_size());

  // Get FaceId for future removal of the face
  if (responseCode == OK || responseCode == FACE_EXISTS) {
    Block statusParameterBlock =  responseBlock.get(CONTROL_PARAMETERS);
    statusParameterBlock.parse();
    Block faceIdBlock = statusParameterBlock.get(FACE_ID);
    faceId = readNonNegativeIntegerAs<int>(faceIdBlock);
    std::cout << responseCode << " " << responseText << ": Added Face (FaceId: "
              << faceId << "): " << uri << std::endl;

    auto it = m_uriToPrefix.find(uri);
    if (isRvRoute) {
      Name rvRoute;
      rvRoute.append(m_root).append("nd");
      registerRoute(rvRoute, faceId, 10, isRvRoute);
      m_rvFaceId = faceId;
    }
    else if (it != m_uriToPrefix.end()) {
      registerRoute(it->second, faceId, 0, isRvRoute);
      // also register this prefix to rv
      registerRoute(it->second, m_rvFaceId, 10, isRvRoute);
    }
    else {
      std::cerr << "Failed to find prefix for uri " << uri << std::endl;
    }

  }
  else {
    std::cout << "\nCreation of face failed." << std::endl;
    std::cout << "Status text: " << responseText << std::endl;
  }
}
void
NDClient::onDestroyFaceDataReply(const Interest& interest, const Data& data) 
{
  short responseCode;
  char responseText[1000] = {0};
  char buf[1000]           = {0};   // For parsing
  int faceId;
  Block responseBlock = data.getContent().blockFromValue();
  responseBlock.parse();

  Block statusCodeBlock =       responseBlock.get(STATUS_CODE);
  Block statusTextBlock =       responseBlock.get(STATUS_TEXT);
  Block statusParameterBlock =  responseBlock.get(CONTROL_PARAMETERS);
  memcpy(buf, statusCodeBlock.value(), statusCodeBlock.value_size());
  responseCode = *(short *)buf;
  memcpy(responseText, statusTextBlock.value(), statusTextBlock.value_size());

  statusParameterBlock.parse();
  Block faceIdBlock = statusParameterBlock.get(FACE_ID);
  memset(buf, 0, sizeof(buf));
  memcpy(buf, faceIdBlock.value(), faceIdBlock.value_size());
  faceId = ntohs(*(int *)buf);

  std::cout << responseCode << " " << responseText << ": Destroyed Face (FaceId: "
            << faceId << ")" << std::endl;
}

void
NDClient::addFace(const std::string& uri, bool isRvRoute) 
{
  Interest interest = prepareFaceCreationInterest(uri, m_keyChain);
  m_face->expressInterest(interest, bind(&NDClient::onAddFaceDataReply, this, _1, _2, uri, isRvRoute),
                                   bind(&NDClient::onNack, this, _1, _2),
                                   bind(&NDClient::onTimeout, this, _1));
}

void
NDClient::destroyFace(int faceId) 
{
  Interest interest = prepareFaceDestroyInterest(faceId, m_keyChain);
  m_face->expressInterest(interest, bind(&NDClient::onDestroyFaceDataReply, this, _1, _2),
                                   bind(&NDClient::onNack, this, _1, _2),
                                   bind(&NDClient::onTimeout, this, _1));
}

void
NDClient::onSetStrategyDataReply(const Interest& interest, const Data& data) 
{
  Block responseBlock = data.getContent().blockFromValue();
  responseBlock.parse();
  int responseCode = readNonNegativeIntegerAs<int>(responseBlock.get(STATUS_CODE));
  std::string responseText = readString(responseBlock.get(STATUS_TEXT));

  if (responseCode == OK) {
    Block statusParameterBlock = responseBlock.get(CONTROL_PARAMETERS);
    statusParameterBlock.parse();
    std::cout << "\nSet strategy succeeded." << std::endl;
  } else {
    std::cout << "\nSet strategy failed." << std::endl;
    std::cout << "Status text: " << responseText << std::endl;
  }
}
void
NDClient::setStrategy(const std::string& uri, const std::string& strategy) 
{
  Interest interest = prepareStrategySetInterest(uri, strategy, m_keyChain);
  m_face->expressInterest(interest, bind(&NDClient::onSetStrategyDataReply, this, _1, _2),
                                   bind(&NDClient::onNack, this, _1, _2),
                                   bind(&NDClient::onTimeout, this, _1));
}


}//namspace nd
}//namespace ndn