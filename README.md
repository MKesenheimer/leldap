# leldap - low effort ldap injection scanner
A scanner to search and exploit LDAP injection vulnerabilities.


## Installation
```
git clone --recurse-submodules git@github.com:MKesenheimer/leldap.git
```

## Usage examples
Use leldap on a request intercepted by Burp:
```
./leldap.py -r examples/get.req
```

Use leldap on a request intercepted by Burp with Burp as a proxy on port 8080:
```
./leldap.py -r examples/get.req --proxy 127.0.0.1:8080
```
In general it is a good idea to observe with a proxy what a tool is doing.

Encode the payload:
```
./leldap.py -r examples/get.req --proxy 127.0.0.1:8080 --encode base64
```

Test leldap on the vulnerable web app `ldap-ctf`:
```
./examples/ldap-ctf/start.sh
 ./leldap.py -r examples/ldap-ctf.req --proxy 127.0.0.1:8080 --module brute --protocol http 
```

