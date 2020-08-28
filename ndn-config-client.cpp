#include <ndn-cxx/face.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <iostream>
#include <chrono>
#include <ndn-cxx/util/sha256.hpp>
#include <ndn-cxx/encoding/tlv-nfd.hpp>
#include <ndn-cxx/util/scheduler.hpp>

#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/security/safe-bag.hpp>
#include <ndn-cxx/security/command-interest-signer.hpp>
#include <ndn-cxx/mgmt/nfd/face-query-filter.hpp>
#include <ndn-cxx/mgmt/nfd/face-status.hpp>
#include <ndn-cxx/mgmt/nfd/control-command.hpp>
#include <boost/asio.hpp>
#include <sstream>

namespace ndn {
namespace tools {
namespace config {

using nfd::FaceQueryFilter;
using nfd::FaceStatus;
using nfd::RibRegisterCommand;
using nfd::RibUnregisterCommand;
using nfd::StrategyChoiceSetCommand;
using nfd::StrategyChoiceUnsetCommand;
using nfd::ControlParameters;

class ConfigClient{
public:
  ConfigClient()
  {
    m_session = std::to_string(random::generateSecureWord32());
    m_scheduler = new Scheduler(m_face.getIoService());
  }

  ~ConfigClient()
  {
    delete m_scheduler;
  }

  void queryFaces()
  {
    FaceQueryFilter udpFilter;
    FaceQueryFilter etherFilter;
    udpFilter.setRemoteUri("udp4://224.0.23.170:56363")
             .setLinkType(nfd::LINK_TYPE_MULTI_ACCESS);
    etherFilter.setRemoteUri("ether://[01:00:5e:00:17:aa]")
             .setLinkType(nfd::LINK_TYPE_MULTI_ACCESS);
    Block udpFilterWire = udpFilter.wireEncode();
    Block etherFilterWire = etherFilter.wireEncode();
    Name name("/localhost/nfd/faces/query");

    Name udpFilterQuery(name);
    udpFilterQuery.append(udpFilterWire);
    Interest udpFilterInterest(udpFilterQuery);
    m_face.expressInterest(udpFilterInterest, bind(&ConfigClient::processFaceQueryRes, this, _1, _2),
                                              nullptr, nullptr);

    Name etherFilterQuery(name);    
    etherFilterQuery.append(etherFilterWire);
    Interest etherFilterInterest(etherFilterQuery);
    m_face.expressInterest(etherFilterInterest, bind(&ConfigClient::processFaceQueryRes, this, _1, _2),
                                                nullptr, nullptr);
  
  }

  void sendConfigStartReq() 
  { 
    if(isReady == false) {
        m_scheduler->schedule(time::seconds(1), [this] {
          sendConfigStartReq();
      });
      return;
    }    
    Name name("/ndn/config/anchor");
    Interest interest(name);
    interest.setMustBeFresh(true);
    interest.setCanBePrefix(true);
    m_face.expressInterest(interest, bind(&ConfigClient::onConfigStartRes, this, _1, _2),
                                     bind(&ConfigClient::onNack, this, _1, _2),
                                     bind(&ConfigClient::onConfigStartTimeout, this, _1));
  }

  void sendConfigCertReq() 
  {
    if(isReady == false) {
        m_scheduler->schedule(time::seconds(1), [this] {
          sendConfigCertReq();
      });
      return;
    }    
    Name name("/ndn/config/cert");
    name.append(m_session);
    Interest interest(name);

    // ten seconds lifetime
    interest.setInterestLifetime(20_s);
    interest.setMustBeFresh(true);
    m_face.expressInterest(interest, bind(&ConfigClient::onConfigCertRes, this, _1, _2),
                                     bind(&ConfigClient::onNack, this, _1, _2),
                                     bind(&ConfigClient::onConfigCertReqTimeout, this, _1));
  }

  void sendConfigSchemaReq() 
  {
    Name name("/ndn/config/schema");
    name.append(m_session);
    Interest interest(name);

    // ten seconds lifetime
    interest.setInterestLifetime(20_s);
    interest.setMustBeFresh(true);
    m_face.expressInterest(interest, bind(&ConfigClient::onConfigSchemaRes, this, _1, _2),
                                     bind(&ConfigClient::onNack, this, _1, _2),
                                     bind(&ConfigClient::onConfigSchemaReqTimeout, this, _1));
  }
private:
  void processFaceQueryRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    Block responseBlock = data.getContent();
    responseBlock.parse();

    Block::element_const_iterator val = responseBlock.find(tlv::nfd::FaceStatus);
    while (val != responseBlock.elements_end())
    {
      FaceStatus status(*val);
      RibRegisterCommand command;
      ControlParameters param;
      uint64_t faceId = status.getFaceId();
      param.setName("/ndn/config")
           .setFaceId(faceId);

      m_faceVector.push_back(faceId);
      Name name = command.getRequestName("/localhost/nfd", param);
      security::CommandInterestSigner signer(m_keyChain);
      Interest CommandInterest = signer.makeCommandInterest(name);
      CommandInterest.setMustBeFresh(true);
      CommandInterest.setCanBePrefix(false);
      std::cout << CommandInterest << std::endl;
      // slow down to avoid authorization rejected
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      m_face.expressInterest(CommandInterest, bind(&ConfigClient::processRibCommandRes, this, _1, _2),
                                              nullptr, nullptr);

      responseBlock.erase(val);
      val = responseBlock.find(tlv::nfd::FaceStatus);
    }

    // set strategy
    StrategyChoiceSetCommand command;
    ControlParameters param;
    param.setName("/ndn/config")
         .setStrategy("/localhost/nfd/strategy/multicast/%FD%03");
    Name name = command.getRequestName("/localhost/nfd", param);
    security::CommandInterestSigner signer(m_keyChain);
    Interest CommandInterest = signer.makeCommandInterest(name);
    CommandInterest.setMustBeFresh(true);
    CommandInterest.setCanBePrefix(false);
    m_face.expressInterest(CommandInterest, bind(&ConfigClient::processStrategyCommandRes, this, _1, _2),
                                            nullptr, nullptr);
  }

  void processRibCommandRes(const Interest& interest, const Data& data)
  {
  }

  void processStrategyCommandRes(const Interest& interest, const Data& data)
  {
    // assuming OK
    isReady = true;
  }

  void onConfigStartRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    // this is anchor
    security::v2::Certificate anchor(data.getContent().blockFromValue());
    std::ofstream outfile("/usr/local/etc/ndn/pnp-trust-anchor.cert",std::ofstream::binary);
    const Block& trustAnchorBlock = anchor.wireEncode();
    {
      using namespace security::transform;
      bufferSource(trustAnchorBlock.wire(), trustAnchorBlock.size()) >> base64Encode(true) >> streamSink(outfile);
    }
    sendConfigCertReq();
  }


  void onConfigCertRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    security::SafeBag safebag(data.getContent().blockFromValue());
    security::v2::Certificate cert(safebag.getCertificate());
    const char* passwd = "1234";
    try {
      m_keyChain.importSafeBag(safebag, passwd, strlen(passwd));
    }
    catch (const security::v2::KeyChain::Error& e) {
      // same host: should not install new cert
      std::cout << "same host: pass" << std::endl;
    }
    m_cert = cert;
    auto identity = m_keyChain.getPib().getIdentity(cert.getIdentity());
    m_keyChain.setDefaultIdentity(identity);
    sendConfigSchemaReq();
  }

  void onConfigSchemaRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    std::ofstream outfile("/usr/local/etc/ndn/pnp.conf", std::ofstream::binary);
    Block schemaBlock = data.getContent();
    outfile.write((char*)schemaBlock.value(), schemaBlock.value_size());
    outfile.close();

    // unregister config route
    for (std::vector<uint64_t>::iterator it = m_faceVector.begin(); it != m_faceVector.end(); ++it) {
      RibUnregisterCommand command;
      ControlParameters param;
      param.setName("/ndn/config")
           .setFaceId(*it);

      Name name = command.getRequestName("/localhost/nfd", param);
      security::CommandInterestSigner signer(m_keyChain);
      Interest CommandInterest = signer.makeCommandInterest(name);
      CommandInterest.setMustBeFresh(true);
      CommandInterest.setCanBePrefix(false);
      std::cout << CommandInterest << std::endl;
      // slow down to avoid authorization rejected
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      m_face.expressInterest(CommandInterest, bind(&ConfigClient::processRibCommandRes, this, _1, _2),
                                              nullptr, nullptr);
    }

    // unset strategy
    StrategyChoiceUnsetCommand command;
    ControlParameters param;
    param.setName("/ndn/config");
    Name name = command.getRequestName("/localhost/nfd", param);
    security::CommandInterestSigner signer(m_keyChain);
    Interest CommandInterest = signer.makeCommandInterest(name);
    CommandInterest.setMustBeFresh(true);
    CommandInterest.setCanBePrefix(false);
    // slow down to avoid authorization rejected
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    m_face.expressInterest(CommandInterest, bind(&ConfigClient::processStrategyCommandRes, this, _1, _2),
                                            nullptr, nullptr);
  }

  void onNack(const Interest& interest, const lp::Nack& nack)
  {
    if (nack.getReason() == lp::NackReason::NO_ROUTE) {
      queryFaces();
    }
  }

  void onConfigStartTimeout(const Interest& interest)
  {
    sendConfigStartReq();
  }

  void onConfigCertReqTimeout(const Interest& interest)
  {
    sendConfigCertReq();
  }

  void onConfigSchemaReqTimeout(const Interest& interest)
  {
    sendConfigSchemaReq();
  }

public:
  // Ready after route and strategy config
  bool isReady = false;

  KeyChain m_keyChain;
  security::v2::Certificate m_anchor;
  security::v2::Certificate m_cert;

  Face m_face;
  std::string m_session;
  std::vector<uint64_t> m_faceVector;
  Scheduler *m_scheduler;
  
};

class Program
{
public:
  explicit Program()
  {
    m_client = new ConfigClient();
    m_client->queryFaces();
    m_client->sendConfigStartReq();
  }

  ~Program() {
    delete m_client;
  }

  ConfigClient *m_client;

private:
  boost::asio::io_service m_io_service;
};

} // namespace config
} // namespace tools
} // namespace ndn

int
main(int argc, char** argv)
{
  ndn::tools::config::Program program;
  program.m_client->m_face.processEvents();
}