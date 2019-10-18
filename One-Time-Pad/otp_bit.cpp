#include <iostream>
#include <bitset>
#include <functional>
#include <cmath>
#include <string>
#include <random>
#include <chrono>

class RNG{
    private:
    public:
        int genRandomNumber(){
            //Ressalvas sobre o uso desse gerador, faltou consultar com maior profundidade.
            std::random_device rd;
            unsigned seed = rd();
            std::default_random_engine dre(seed);
            std::srand(dre());
            return dre();
        }
};

class OneTimePad{
    private:
        std::bit_xor<void> bx;
        std::bitset<32> key;
        std::bitset<32> cipherText;

    public:
        OneTimePad(){
            RNG rng;
            this->key = std::bitset<32> (rng.genRandomNumber());
            std::cout << key << " (Key)" << std::endl;
        }

        std::bitset<32> encrypt(std::bitset<32> message){
            cipherText = bx(message, key);
            return cipherText;
        }

        std::bitset<32> decrypt(){
            return bx(cipherText, key);
        }
};

int main(){
    std::bitset<32> message(1000000000);
    std::cout << message << " (Plain Text)" << std::endl;
    
    OneTimePad otp;
    std::cout << otp.encrypt(message) << " (Cipher Text)" << std::endl;
    std::cout << otp.decrypt() << " (Original Text)" << std::endl;
    return 0;
}
