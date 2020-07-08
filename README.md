## **ndn-plugnplay**

This repo serves the purpose of facilating the development of NDN application, and ease the configuration of NDN entity. It assumes a **small**, **trusted** network with no attackers. A local controller is invovled here.

--------------

1. ### **Security Bootstrapping**

   In bootstrapping phase, one entity gets its trust anchor and certificate, together with trust schema. All three components are obtained through Interest-Data exchange with a local Controller.

   

   #### Trust Anchor 

   A new node who wants to join the NDN network first sends out Interest `/ndn/sign-on/<nonce>` to ask for the trust anchor. This Interest can be either broadcast to all faces, or unicast to the Controller. Data returned should contain Controller's self-signed certificate. Then trust anchor is installed onto the node.

   ###### Controller Connectivity

   Controller is either within the range of L2 multcast, or can be reachable through IP unicast. In the second case, controller's connectivity information should be pre-shared, in order for new nodes constructing unicast face and setting up corresponding route to it.

   

   #### Certificate

   After trust anchor installed, new coming node has already learned root prefix of this network. It then generates a one component long flat ID, indicating the identifier it wants to use inside the network and assembly an certificate request Interest named `/<root-prefix>/cert/<flat-ID>/<nonce>`. This interest is either broadcast to all faces, or unicast to controller if unicast face to controller is pre-established in previous steps.

   Controller receives this Interest, and generates the identity `/<root-prefix>/<flat-ID>` as well as anchor-signed certificate. Newly generated certificate is exported as [safebag](https://named-data.net/doc/ndn-cxx/current/specs/safe-bag.html) containing encrypted private key. Password for safebag encryption and decryption is pre-shared with default setting `"1234"`. Exported safebag is encoded into Data content in order to reply corresponding certificate request Interests.

   Upon receiving reply from Controller, node will verify the signature using trust anchor, then decrypt the safebag and install contained identity certificate. After this step, a node is already capable of producing identity-signed Data. 

   

   #### Trust Schema

   Trust Schema is offered by controller by serving prefix ` /<root-prefix>/trust-schema`. Signed Interest for asking trust schema will be sent after the node has its certificate installed. When controller wants to update trust schema for specific entity, it will send notification Interest to notify the update and expect incoming Interests.

-------------------------

2. ### **Connectivity Establishment**

   Connectivity (i.e., face and route) among NDN nodes are established by broadcast-based self-learning jointly with NDN Neighbor Discovery (NDND). After identity certificate installed, NDN nodes begin neighbor discovery by following NDND protocol. NDND requires a Rendezvous (RV) inside the network at `/<root-prefix>/nd`, and Controller will play this role. If a new node is not assigned IP address before trying to join the NDN network, it won't run NDND and relies solely on self-learning.

   Self-learning ends up with setting up L2 unicast faces, while NDND ends up with IP unicast faces. If a prefix is found reachable both from self-learning and NDND, L2 face should have lower route cost than IP face.

--------------

3. ### **Role of Controller**

   Controller serves for four purposes: 1) providing trust anchor (i.e., self-signed certificate) 2) issue certificates for nodes 3) providing trust schema 4) rendezvous of NDND. It at least registers following prefixes:

   -  `/ndn/sign-on`

   - `/<root-prefix>/cert`

   - `/<root-prefix>/trust-schema`

   - `/<root-prefix>/nd`

   If route to controller is already known, routes of above four prefixes are already known, too. 

-------------

4. ### **Example**

   A new node plugs on with ethernet switch and wants to join local NDN network with a flat-ID `alice`. Another node with flat-ID `bob` has already joined and been configured. `bob` is only reachable through IP unicast and operating at `udp4://192.168.99.157:6363`. Its connectivity information is registered on Controller's NDND RV service. 

   With knowing Controller is reachable via L2 multicast and following the self-learning steps, the new coming node first sends out Discovery Interest for `/ndn/sign-on` to Ethernet multicast face, and then learns that Controller operates on `f0:18:98:81:d8:1f`. Unicast face and route for `/ndn/sign-on` are added. After that, non-discovery Interest brings back the trust anchor `/ndn-plugnplay/KEY`

   ```
   Certificate name:
     /ndn-plugnplay/KEY/%82%ED~%0AL%85yB/self/v=1593747065010
   Validity:
     NotBefore: 19700101T000000
     NotAfter: 20400703T033105
   Public key bits:
     MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECJKQePNojqhMuE3L3YtchXzVtGEo
     PCOKhEi4/qKcQTY51qbFySUvMKeY8ZtkVSsalhK7+umJo9ZYrC4ET7+H1g==
   Signature Information:
     Signature Type: SignatureSha256WithEcdsa
     Key Locator: Self-Signed Name=/ndn-plugnplay/KEY/%82%ED~%0AL%85yB
   ```

   

   Similarly, route for `/ndn-plugnplay/cert` is learned, and certificate for `alice` returned and been installed to the node.

   ```
   Certificate name:
     /ndn-plugnplay/alice/KEY/%B2%A1%D0%93%B7j%D0%05/controller/%FD%00%00%01s%28k%F9k
   Validity:
     NotBefore: 20200707T083712
     NotAfter: 20210707T083711
   Public key bits:
     MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFMEKjeelAYnONcySHrfxdmhrnV+/
     DTdWwRMYQXaWgItexA2T1ZW2rD7+BbDDSQ5vJFzBqqeZbzK5iL/oHaODTw==
   Signature Information:
     Signature Type: SignatureSha256WithEcdsa
     Key Locator: Name=/ndn-plugnplay/KEY/%82%ED~%0AL%85yB
   ```

   After retrieving and configuring trust schema, `/ndn-plugnplay/alice` starts registering itself to NDND RV and discovering neighbors. Then it finds `/ndn-plugnplay/bob` from RV's records, unicast face and route to `bob` are established afterwards.

   Now `alice` and `bob` and communicate and verify each other.
