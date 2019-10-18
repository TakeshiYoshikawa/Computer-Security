# DES/3DES
 
## Prerequisites

Install Crypto++ for C/C++

```
sudo apt-get install libcrypto++
```

## How to Compile

```
g++ -DNDEBUG -g3 -O2 -Wall -Wextra -o filename filename.cpp -l:libcryptopp.a
```
