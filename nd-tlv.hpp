

#ifndef ND_TLV_HPP
#define ND_TLV_HPP

#include <ndn-cxx/encoding/tlv.hpp>

namespace ndn { 
namespace nd {
namespace tlv {
    
enum {
  NeighborParameter    = 302,
  NeighborInfo         = 301,
  NeighborIpAddr       = 304,
  NeighborPort         = 305
};

} // namespace tlv
} // namespace nd
} // namespace ndn

#endif // ND_TLV_HPP