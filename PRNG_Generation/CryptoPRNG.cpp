#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#include <iostream>

using namespace CryptoPP;
using namespace std;

int main(){
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    string k;

    // true = /dev/random; false = /dev/urandom

    for(int i = 0; i < 36; i++){
        k.clear();
        OS_GenerateRandomBlock(false, key, key.size());
        HexEncoder hex(new StringSink(k));
        hex.Put(key, key.size());
        hex.MessageEnd();

        cout << "Key: " << k << endl;
    }
}