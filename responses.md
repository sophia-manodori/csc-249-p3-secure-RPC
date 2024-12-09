1. Overview of Application
2. Format of an unsigned certificate
    SERVER_IP+'|'+ str(SERVER_PORT) +'|' + str(public_key[0]) +'|' + str(public_key[1])
    So, the server ip, port, public keys (in that order) (separated and as strings) are made into a joined string delinated with the "|' character. 
3. Example output (see command line trace at end)
4. **A walkthorough of the steps of a TLS handshake, and what each step accomplishes**
        * For example, one step will be: "The client encrypts the generated symmetric key before sending it to the server. If it doesn't, the VPN will be able to read the symmetric key in transit and use it to decrypt further secure communications between the client and server encrypted and HMAC'd with that key."
    1. Client sends a tls request "TLS Request" along with the server IP and port # to the vpn, who forwards the request to the server. 
    2. The server upon recieving the request responds with a signed certificate, which goes to the vpn and then the client. 
    3. the client then verifies the certificate with the certificate authority's public key to verify the server is legit. It then verifies that the signed certificate contain the correct server IP and port address. From the signed certificate the client also gets the server's public key, which it can use to encrypt the following symmetric key. The symmetric key is encrypted to ensure that nobody else knows the symmetric key, only the client and server. 
    4. The client randomly generates a symmetric key encrypted with the server's public key, and sends it to the vpn, which sends it to the server. The server sends back an aknowledgement encrypted with the symmetric key. Now both parties verifiably share a symmetric key and can use it to encrypt all future messages. 
 5. A description of two ways in which our simulation fails to achieve real security, and how these failures might be exploited by a malicious party. This is one place you can earn extra credit by discussing some less-obvious exploits. Some options for discussion are:
    
        * The asymmetric key generation scheme: this is insecure in this particular case because the private key could easily be discovered since it's equal to the maximum random value of the public key with public key's first digit subtracted. Ideally they should be both randomly generated. A malicious party could find the private key and use it to decrypt the symmetric key and subsequently the messages sent. 
        * The encryption/decryption/HMAC/verification algorithms: the entire encryption scheme is only as strong as the symmetric encryption. So, a malicious entity intercepting packets could potentially calculate the symmetric key and have access to all the data sent between the server and client. 
        * The certificate authority's public key distribution system
        * The use of python's "eval()" function: the eval() function is taking cyphertext, which means that a malicious user could hypothetically pass problematic code into it and then it would run, causing problems. It's also a very slow running function. 
6. Acknowledgements
7. (Optional) Client->Server and Server->Client application layer message format if you decide to change "process_message()" in "secure_server.py". This can be another source of extra credit if you're creative with your application.

3. Command-line traces showing the secure client, VPN, secure server, and certificate authority in operation.
certificate authority: 
Connected established with ('127.0.0.1', 50242)
Received client message: 'b'key'' [3 bytes]
Sending the certificate authority's public key (31653, 56533) to the client
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 50242) has closed the remote connection - listening 
Connected established with ('127.0.0.1', 51276)
Received client message: 'b'$127.0.0.1|65432|46150|56533'' [28 bytes]
Signing '127.0.0.1|65432|46150|56533' and returning it to the client.
Received client message: 'b'done'' [4 bytes]
('127.0.0.1', 51276) has closed the remote connection - listening 

VPN: VPN starting - listening for connections at IP 127.0.0.1 and port 55554
Connected established with ('127.0.0.1', 51280)
Received client message: 'b'127.0.0.1~IP~65432~port~Request TLS'' [35 bytes]
connecting to server at IP 127.0.0.1 and port 65432
server connection established, sending message 'Request TLS'
message sent to server, waiting for reply
Received server response: 'b'D_(24880, 56533)[127.0.0.1|65432|46150|56533]'' [45 bytes], forwarding to client
line 49
Received client message: 'b'E_(46150, 56533)[43432]'' [23 bytes], forwarding to server
Received server response: 'b'symmetric_43432[Symmetric key received]'' [39 bytes], forwarding to client
line 49
Received client message: 'b'HMAC_55578[symmetric_43432[test]]'' [33 bytes], forwarding to server
Received server response: 'b'HMAC_55578[symmetric_43432[test]]'' [33 bytes], forwarding to client
line 49
VPN is done!

Secure Server: 
Generated public key '(46150, 56533)' and private key '10383'
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Prepared the formatted unsigned certificate '127.0.0.1|65432|46150|56533'
Connection established, sending certificate '127.0.0.1|65432|46150|56533' to the certificate authority to be signed
Received signed certificate 'D_(24880, 56533)[127.0.0.1|65432|46150|56533]' from the certificate authority
server starting - listening for connections at IP 127.0.0.1 and port 65432
Connected established with ('127.0.0.1', 51281)
Connected established with client for TLS handshake
Sending signed certificate to client 'D_(24880, 56533)[127.0.0.1|65432|46150|56533]'
recieved symmetric key 43432
TLS handshake complete: established symmetric key '43432', acknowledging to client
Received client message: 'b'HMAC_55578[symmetric_43432[test]]'' [33 bytes]
Decoded message 'test' from client
Responding 'test' to the client
Sending encoded response 'HMAC_55578[symmetric_43432[test]]' back to the client
server is done!

secure client: 
Connecting to the certificate authority at IP 127.0.0.1 and port 55553
Connection established, requesting public key
Received public key (31653, 56533) from the certificate authority for verifying certificates
Client starting - connecting to VPN at IP 127.0.0.1 and port 55554
client starting - connecting to Server at IP 127.0.0.1 and port 65432
127.0.0.1t65432
connection established, symmetric key 'E_(46150, 56533)[43432]'
message sent, waiting for reply
TLS handshake complete: sent symmetric key '43432', waiting for acknowledgement
symmetric_43432[Symmetric key received]
Received acknowledgement 'Symmetric key received', preparing to send message
Sending message 'HMAC_55578[symmetric_43432[test]]' to the server
Message sent, waiting for reply
Received raw response: 'b'HMAC_55578[symmetric_43432[test]]'' [33 bytes]
Decoded message 'test' from server
client is done!
