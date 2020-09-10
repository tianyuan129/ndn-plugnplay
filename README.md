## **ndn-plugnplay**

The aim of this repo is to automate NDN configuration and argue for the separation for connectivity and configuration.
Configure NDN nodes means configuring trust anchor, name, certificate, and trust schema.

### **Usage**

Compile and intall this [NFD](https://github.com/tianyuan129/NFD-plugnplay/tree/pnp) that is based on release 0.7.0

Assuming you're using macOS:
```
nfd-stop (just to make sure)
nfd-start
cd /this/dir
brew install zbar leveldb (you can install equivalent packages on Linux)
python3 -m venv ./venv
./venv/bin/python -m pip install -r requirements.txt
```

You can check options supported by
```
sudo ./venv/bin/python app.py --help
```

For example, you can set naming convention ``/ndn-plugnplay/device-<nonce>`` for nodes to be configured by
```
sudo ./venv/bin/python app.py --prefix ndn-plugnplay --convention device
```
This is also the default setting if you don't specify preferred system prefix and node naming convention.

Now a GUI will set up at ``127.0.0.1:6060`` and can provide visualized configuration overview in your browser.

It may take a minute to complete configuration.
You can check your trust anchor and trust schema by

```
cat /usr/local/etc/ndn/pnp-trust-anchor.cert
cat /usr/local/etc/ndn/pnp.conf 
```

To configure other nodes, put them in your current machine's one-hop WiFi or Ethernet range, then repeat above steps til their NFDs start (**and no more**).
Configuration will automatically happen and may take a minute.
Then view your trust anchor and trust schema in the same way.
