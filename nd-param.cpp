#include <iostream>

#include "nd-param.hpp"
#include <ndn-cxx/encoding/encoding-buffer.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/name.hpp>

namespace ndn{
namespace nd {

NDParam&
NDParam::setName(const Name& name)
{
  m_name = name;
  m_hasFields[ND_PARAM_NAME] = true;
  m_wire.reset();
  return *this;
}

NDParam&
NDParam::setIpAddr(std::string& ipAddr)
{
  m_ipAddr = ipAddr;
  m_hasFields[ND_PARAM_IPADDR] = true;
  m_wire.reset();
  return *this;
}

NDParam&
NDParam::setPort(std::string& port)
{
  m_port = port;
  m_hasFields[ND_PARAM_PORT] = true;
  m_wire.reset();
  return *this;
}

template<ndn::encoding::Tag T>
size_t
NDParam::wireEncode(EncodingImpl<T>& encoder) const
{
  size_t totalLength = 0;

  if (m_hasFields[ND_PARAM_PORT]) {
    uint8_t buffer[m_port.length()];
    memcpy(buffer, m_port.data(), m_port.length());
    totalLength += encoder.prependByteArrayBlock(nd::tlv::NeighborPort, buffer, sizeof(buffer));
  }

  if (m_hasFields[ND_PARAM_IPADDR]) {
    uint8_t buffer[m_ipAddr.length()];
    memcpy(buffer, m_ipAddr.data(), m_ipAddr.length());
    totalLength += encoder.prependByteArrayBlock(nd::tlv::NeighborIpAddr, buffer, sizeof(buffer));
  }

  if (m_hasFields[ND_PARAM_NAME]) {
    totalLength += getName().wireEncode(encoder);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(nd::tlv::NeighborParameter);
  return totalLength;
}

NDN_CXX_DEFINE_WIRE_ENCODE_INSTANTIATIONS(NDParam);

Block
NDParam::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
NDParam::wireDecode(const Block& wire)
{
  m_wire = wire;

  m_wire.parse();

  if (m_wire.type() != nd::tlv::NeighborParameter)
    BOOST_THROW_EXCEPTION(Error("Requested decoding of NeighborParameter, but Block is of different type"));

  Block::element_const_iterator paramVal = m_wire.find(ndn::tlv::Name);
  // Name
  if (paramVal != m_wire.elements_end())
  {
    m_hasFields[ND_PARAM_NAME] = true;
    m_name.wireDecode(m_wire.get(ndn::tlv::Name));
    std::cout << m_name << std::endl;
  }
  // IpAddr
  paramVal = m_wire.find(nd::tlv::NeighborIpAddr);
  if (paramVal != m_wire.elements_end())
  {
    m_hasFields[ND_PARAM_IPADDR] = true;
    m_ipAddr = readString(*paramVal);
    std::cout << m_ipAddr << std::endl;
  }
  // Port
  paramVal = m_wire.find(nd::tlv::NeighborPort);
  if (paramVal != m_wire.elements_end())
  {
    m_hasFields[ND_PARAM_PORT] = true;
    m_port = readString(*paramVal);
    std::cout << m_port << std::endl;
  }
}

} // namespace nd
} // namespace ndn