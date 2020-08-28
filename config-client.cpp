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

using namespace ndn;

class ConfigClient{
public:
  void sendConfigStartReq() 
  { 
    Interest interest("/ndn/config");
    m_face.expressInterest(interest, bind(&ConfigClient::onConfigStartRes, this, _1, _2),
                                     bind(&ConfigClient::onNack, this, _1, _2),
                                     bind(&ConfigClient::onConfigStartTimeout, this, _1));
  }

  void sendConfigCertReq() 
  {
    Name req_name(m_root);
    session = std::to_string(random::generateSecureWord64());
    req_name.append("cert").append(session);
    Interest req(req_name);

    // ten seconds lifetime
    req.setInterestLifetime(10_s);
    req.setMustBeFresh(true);
    m_face.expressInterest(req, bind(&ConfigClient::onConfigCertRes, this, _1, _2),
                                bind(&ConfigClient::onNack, this, _1, _2),
                                bind(&ConfigClient::onConfigCertReqTimeout, this, _1));
  }


  void sendConfigSchemaReq() 
  {
    Name req_name(m_root);
    req_name.append("schema").append(session);
    Interest req(req_name);

    // ten seconds lifetime
    req.setInterestLifetime(10_s);
    req.setMustBeFresh(true);
    m_face.expressInterest(req, bind(&ConfigClient::onConfigSchemaRes, this, _1, _2),
                                bind(&ConfigClient::onNack, this, _1, _2),
                                bind(&ConfigClient::onConfigSchemaReqTimeout, this, _1));
  }
private:
  void onConfigStartRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    // this is anchor
    security::v2::Certificate anchor(data.getContent().blockFromValue());
    m_root = anchor.getIdentity();
    std::ofstream outfile("pnp-trust-anchor.cert",std::ofstream::binary);
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
    const char* passwd = "1234";

    Name identityName(m_root);
    identityName.append(session);
    m_keyChain.importSafeBag(safebag, passwd, strlen(passwd));
    security::v2::Certificate cert(safebag.getCertificate());
    m_cert = cert;
    
    // this is my cert
    std::cout << m_cert << std::endl;
    sendConfigSchemaReq();
  }

  void onConfigSchemaRes(const Interest& interest, const Data& data)
  {
    std::cout << data << std::endl;
    std::ofstream outfile("pnp.conf",std::ofstream::binary);
    Block schemaBlock = data.getContent();
    // write to outfile
    outfile.write((char*)schemaBlock.value(), schemaBlock.value_size());
    outfile.close();
  }

  void onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
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
  bool is_ready = false;    // Ready after creating face and route to ND server

  KeyChain m_keyChain;
  security::v2::Certificate m_anchor;
  security::v2::Certificate m_cert;

  Name m_root;

  Face m_face;
  std::string session;
  
};


class Program
{
public:
  explicit Program()
  {
    // Init client
    m_client = new ConfigClient();
    m_client->sendConfigStartReq();
  }


  ~Program() {
    delete m_client;
  }

  ConfigClient *m_client;

private:
  boost::asio::io_service m_io_service;
};


int
main(int argc, char** argv)
{
  Program program;
  program.m_client->m_face.processEvents();
}