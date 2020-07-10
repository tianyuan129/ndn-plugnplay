from ndn.encoding import TlvModel, BytesField, UintField, TypeNumber, NameField, RepeatedField, ModelField

TLV_NEIGHBOR_INFO = 301
TLV_NEIGHBOR_PARAM = 302
TLV_NEIGHBOR_IPADDR = 304
TLV_NEIGHBOR_PORT = 305


class SignOnResponse(TlvModel):
    anchor = BytesField(TypeNumber.DATA)


class CertResponse(TlvModel):
    id_cert = BytesField(TypeNumber.DATA)

# NDND
class NeighborParam(TlvModel):
    name = NameField()
    ip_addr = BytesField(TLV_NEIGHBOR_IPADDR)
    port = BytesField(TLV_NEIGHBOR_PORT)

class NeighborParamAtWire(TlvModel):
    wire = BytesField(TLV_NEIGHBOR_PARAM) 

class NeighborList(TlvModel):
    neighbor_list = RepeatedField(ModelField(TLV_NEIGHBOR_PARAM, NeighborParam))

class NeighborInfo(TlvModel):
    neighbor_info = BytesField(TLV_NEIGHBOR_INFO) 