#ifndef ND_PARAMETER_HPP
#define ND_PARAMETER_HPP

#include "nd-tlv.hpp"
#include "network-info.hpp"

#include <ndn-cxx/encoding/encoding-buffer.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/name.hpp>

namespace ndn {
namespace nd {

using ndn::Name;
using ndn::Block;
using ndn::EncodingImpl;
using ndn::EncodingEstimator;
using ndn::EncodingBuffer;

enum NDParamField {
  ND_PARAM_NAME,
  ND_PARAM_IPADDR,
  ND_PARAM_PORT,
  ND_PARAM_UBOUND
};

const std::string ND_PARAM_FIELD[ND_PARAM_UBOUND] = {
  "Name",
  "IpAddr",
  "Port",
};

class NDParam
{
public:
  class Error : public ndn::tlv::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : ndn::tlv::Error(what)
    {
    }
  };

  NDParam()
    : m_hasFields(ND_PARAM_UBOUND)
  {
  }

  // still need to set name
  NDParam(NetworkInfo& networkInfo)
    : m_hasFields(ND_PARAM_UBOUND),
      m_ipAddr(networkInfo.getIpAddr()),
      m_port(networkInfo.getPort())
  {
    m_hasFields[ND_PARAM_IPADDR] = true;
    m_hasFields[ND_PARAM_PORT] = true;
  }

  explicit
  NDParam(const Block& block)
    : m_hasFields(ND_PARAM_UBOUND)
  {
    wireDecode(block);
  }

  const Name&
  getName() const
  {
    assert(hasName());
    return m_name;
  }

  NDParam&
  setName(const Name& name);

  bool
  hasName() const
  {
    return m_hasFields[ND_PARAM_NAME];
  }

  const std::string&
  getIpAddr() const
  {
    assert(hasIpAddr());
    return m_ipAddr;
  }

  NDParam&
  setIpAddr(std::string& IpAddr);

  bool
  hasIpAddr() const
  {
    return m_hasFields[ND_PARAM_IPADDR];
  }

  const std::string&
  getPort() const
  {
    assert(hasPort());
    return m_port;
  }

  NDParam&
  setPort(std::string& Port);

  bool
  hasPort() const
  {
    return m_hasFields[ND_PARAM_PORT];
  }

  const std::vector<bool>&
  getPresentFields() const {
    return m_hasFields;
  }

  template<ndn::encoding::Tag T>
  size_t
  wireEncode(EncodingImpl<T>& block) const;

  Block
  wireEncode() const;

  void
  wireDecode(const Block& wire);

private:
  std::vector<bool> m_hasFields;
  Name m_name;
  std::string m_ipAddr;
  std::string m_port;

  mutable Block m_wire;
};

NDN_CXX_DECLARE_WIRE_ENCODE_INSTANTIATIONS(NDParam);

} // namespace nd
} // namespace ndn

#endif // ND_PARAM_HPP