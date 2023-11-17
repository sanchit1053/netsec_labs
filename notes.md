

## OPENSSL 

- Example Usage
    - `openssl enc -aes-128-cbc -[e/d] -in plain.txt -out cipher.bin -K 00112233445566778889aabbccddeeff -iv 0102030405060708`
    - The K should be capital 
    - the values are in hexadecimal
- To get the ciphers check `openssl enc -ciphers`

## OFB
- Same IV then given P1, C1, and C2
- P2 = (P1 ^ C1) ^ C2

## RSA
- Create RSA private key:
   - openssl genrsa -out <outfile> <bits>
- Create RSA Public key:
   - openssl rsa -in <private-key> -pubout -out <outfile>
- Encryption using RSA:
   - openssl pkeyutl -encrypt -in <plain-text-file> -out <out-file> -pubin -inkey <public-key>
- Decryption using RSA:
   - openssl pkeyutl -decrypt -in <cipher-text-file> -out <outfile> -inkey <private-key>
- Verify if given public key and private key pair is valid or not:
   - echo "Verified" | openssl pkeyutl -encrypt -pubin -inkey <public-key> | openssl pkeyutl -decrypt -inkey <private-key>
- Extract the details(primes,modulus,public key, private key) from private key file:
   - openssl rsa -in <private-key> -text -noout

## EC
Elliptic-curve Diffie–Hellman (ECDH) is a key agreement framework that allows two parties, each having an elliptic-curve public–private key pair, to establish a shared secret. We will explore this here.

Elliptic Curve Cryptography (ECC) is extensively used within public key encryption, including with TLS, Bitcoin, Ethereum etc. We will first use OpenSSL to create a public-private key pair. For this we will first generate a random private key (priv), and then generate a public key point (i.e. private multiplied by G), using a generator (G) which is a generator point on a given selected elliptic curve. Then we will also see how to derive a shared secret between two parties who have EC key pairs.

We will assume below that Alice wants to communicate with Bob using ECDH, the terminology used is as per this.
- To first see what are the curves available, use `opensSl ecparam -list_curves`
- Let us first generate a private key for Alice. We need to specify which curve we will use to generate relevant size key. In this example, we have used secp256k1.
`openssl ecparam -name secp256k1 -genkey -out alicepriv.pem`
    - Use “cat alicepriv.pem” to view your key.
- If we want to see what are the ECC parameters associated with this key, you can use `openssl ecparam -in alicepriv.pem -text -param_enc explicit -noout`
    - This specifies the prime defining the finite field, the coefficients a, b of the curve, the generator (both the x- and y-coordinates of the point are packed into a single string), the order or size q of the generated group, and the cofactor also.
- Let us now generate the public key based on the private key via `openssl ec -in alicepriv.pem -pubout -out alicepub.pem`. You can checkout the key via `cat alicepub.pem`.
- The “pem” format has a lot of extra stuff (e.g. BEGIN …) and also it is base-64 encoded. It does not really tell what the actual public and private keys are. To find this you can use `openssl ec -in alicepriv.pem -text -noout`. 
- You need to repeat steps 2 and 4 for generating Bob’s private and public key.
- Now that we have the relevant keys, we can derive a shared key using the below command. This is from the perspective of Alice. `openssl pkeyutl -derive -out abkey1.pem -inkey alicepriv.pem -peerkey bobpub.pem` The abkey1.pem is a shared symmetric key that Alice derived based on its private key and Bob’s public key. This is the key she will use to encrypt messages sent to Bob using any of the symmetric key algorithms like AES etc (e.g. using openssl enc).
- You can also do the same as above but from Bob’s perspective. Name the key abkey2.pem
- You can check via “xxd” if the keys abkey1.pem and abkey2.pem are the same. They should be, if you did things correctly!
- To encrypt with base64 encoded key file use below:
    - `openssl enc -<algo> -base64 -k $(base64 shared.pem) -iv <iv> -e -in <input-file> -out <output-file>`
    - These are important in cases where key files and their bytes are a bit weird and not easily readable.

## Attack
- Given __e__, __n__ and an oracle that decrypts text
- to get oracle to decrypt cipher text
- calculate $c * (2 ^ e) % n$
- decipher and then $ d / 2 $ is the decrpytion of c

#### ascii ↔ long
```python
#!/usr/bin/python3
import Crypto.Util.number as nb
import argparse

# Initialize the Parser
parser = argparse.ArgumentParser(description ='Plain text to long converter')
  
# Adding Arguments
parser.add_argument('pt', 
                    type = str,
                    help ='Plain Text')
m = parser.parse_args().pt
print("Your plain text: " + m, end="\n\n")
print("Plain text to long conversion: ", nb.bytes_to_long(m.encode('utf-8')), end = "\n\n")

parser.add_argument('longval', 
                    type = int,
                    help ='Long value')
longval = parser.parse_args().longval
print("Your long value:", longval, end="\n\n")
print("Long to ascii conversion: ", nb.long_to_bytes(longval).decode('utf-8'), end = "\n\n")
```

## Hashes MACS
- Supported algorithms
    - `openssl dgst -list`
- Creating a Hash
    - `openssl dgst <dgsttype> <filename>`
- Creating signed hash HMAC
    - `openssl dgst -md5 -hmac "SECRET_KEY" <silename>` 
- Signing files (private.pem is a generated private key)
    - SIGN : `openssl dgst -sha256 -sign private.pem -out data.sig data`
    - VERIFY : `openssl dgst -sha256 -verify public.pem -signature data.sig data`

## CA
Full Procedure

##### Making a CA
- create the private key of Albert using the “openssl genrsa” command you used in earlier activities. The name of the file must be "ca-key.pem".
- Enter the directory and run the following command to generate the self-signed certificate for the CA: `openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -config openssl.cnf`
- Fill the required details
- File ca-key.pem contains the CA’s keys
- File ca-cert.pem is the certificate which contains its public key
- You can explore the key via `openssl x509 -in ca-key.pem -text` and the certificates via `openssl x509 -in ca-cert.pem -text`

##### Agent key and ask to sign
- Within it, create keys via “openssl genrsa” (covered before). The name of the key must be "agent-key.pem"
- To generate a Certificate Signing Request (CSR) which includes the agent’s public key and identity information, use 'openssl req -new -key agent-key.pem -out agent-csr.pem -config openssl.cnf'
- Enter the required information
-  Above command is quite similar to the one we used in creating self-signed certificate for the CA. The main difference is the-x509 option. Without it, the command generates a request; with it, the command generates a self-signed certificate.
-  Explore the csr via `openssl req -in agent-csr.pem -text`
-  This agent-csr.pem is sent to the CA, who after necessary background checks will issue a certificate. We will mimic this action by copying agent's CSR to the boss's directory. Do that.

##### CA sign the key
- Albert can turn the CSR into an X509 certificate (agent-cert.pem), using `openssl ca -in agent-csr.pem -out agent-cert.pem -cert ca-cert.pem -keyfile ca-key.pem -config openssl.cnf`

##### Examine the certificate
- Copy agent-cert.pem from Boss's folder to agent's
- Examine the certificate via `openssl x509 -in agent-cert.pem -text`
- Verify that the certificate works. For this copy ca.crt from boss’s folder to the agent’s folder (all agents need root CA's certificate anyways) and then type  `openssl verify -CAfile ca-cert.pem agent-cert.pem`

##### tsl/ssl
- Edit the "/etc/apache2/sites-available/ssl-serv.conf" file where in “SSLCACertificateFile” variable put path of the CA certificate, in "SSLCertificateFile" variable put the path of the server certificate and in "SSLCertificateKeyFile" variable put the path of the server key. Save the ssl-serv.conf file and exit from it
- Now run the following commands: 
    1. a2ensite ssl-serv 
    2. service apache2 start or service apache2 restart (if apache is already running)
- Now access the webserver on https://localhost:443/ and the flag1 will be found at https://localhost:443/flag1.txt. This is a publicly available information which anyone without any issues can access.

## Scapy
```python
#!/usr/bin/python3

from scapy.all import *

def work(x):
    if x[0].haslayer(Raw):
        return x[0][0][Raw].load
    else:
        return "NOTHING"
# Put the interface of loopback interface.
# use ifconfig command and find interface which has "inet 127.0.0.1"
interfaces = ['lo']

# filter can be tcp udp icmp
pkt = sniff(iface=interfaces, filter='tcp', count=100, prn=lambda x: work(x))
```

SPOOFING
```python
#!/usr/bin/python3

from scapy.all import *

# Create IP Packet
ippacket = IP()
# Put IP address to spoof here
ippacket.src = '127.0.0.1'

# Your ethernet IP address, typically the one with interface eth0, ensXX, wlan0, or equivalent.
# Do no use localhost or 127.0.0.1 since with scapy it won't work 
ippacket.dst = '192.168.65.4'

# Create ICMP Packet
icmppacket = ICMP()

#Create Final packet
packetToSend = ippacket/icmppacket

# Send the packet
send(packetToSend)

```

## DDOS
```python
#!/usr/bin/python           # This is server.py file                                                                                                                                                                           

import socket               # Import socket module
import thread

def on_new_client(clientsocket,addr):
    while True:
        msg = clientsocket.recv(1024)
        #do some checks and if msg == someWeirdSignal: break:
        print addr, ' >> ', msg
        msg = raw_input('SERVER >> ')
        #Maybe some code to compute the last digit of PI, play game or anything else can go here and when you are done.
        clientsocket.send(msg)
    clientsocket.close()

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
port = 50000                # Reserve a port for your service.

print 'Server started!'
print 'Waiting for clients...'

s.bind((host, port))        # Bind to the port
s.listen(5)                 # Now wait for client connection.

print 'Got connection from', addr
while True:
   c, addr = s.accept()     # Establish connection with client.
   thread.start_new_thread(on_new_client,(c,addr))
   #Note it's (addr,) not (addr) because second parameter is a tuple
   #Edit: (c,addr)
   #that's how you pass arguments to functions when creating new threads using thread module.
s.close()
```

## XSS
- To listen on some port on your machine you can use "netcat" using command: nc -lknvp <port>. This basically mimics a service running on the specified port on the machine where the command is run.
- Alternatively, you can host your own HTTP server(Since the request will come from XSS payload as an HTTP request) using Python:
    - For Python3: sudo python3 -m http.server <port>
    - For Python2: sudo python -m SimpleHTTPServer <port>
-
