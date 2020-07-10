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