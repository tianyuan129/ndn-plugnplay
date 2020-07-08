from ndn.encoding import TlvModel, BytesField, RepeatedField, ModelField, UintField, NameField


class DeviceItem(TlvModel):
    device_name = NameField()
    device_ip = BytesField(1)
    device_port = BytesField(2)


class DeviceList(TlvModel):
    devices = RepeatedField(ModelField(1, DeviceItem))

