#include <bits/stdc++.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "des.h"
#include "rsa.h"

using namespace std;

int main(){
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    // RSA parameter setup: select primes p and q, compute n, phi, and private exponent d
    uint64_t p = 2147483647;
    uint64_t q = 2147483629;
    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    uint64_t d = mod_inverse(e, phi);

    SOCKET server=socket(AF_INET,SOCK_STREAM,0);

    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port=htons(8080);

    bind(server,(sockaddr*)&addr,sizeof(addr));
    listen(server,1);

    SOCKET client=accept(server,NULL,NULL);

    // RSA Handshake: Send public modulus n to client (16 hex chars)
    stringstream n_ss;
    n_ss << hex << uppercase << setw(16) << setfill('0') << n;
    string n_hex = n_ss.str();
    send(client, n_hex.c_str(), n_hex.size(), 0);

    // Receive 128-char encrypted session key from client
    char enc_key_buf[129];
    memset(enc_key_buf, 0, 129);
    recv(client, enc_key_buf, 128, 0);
    string encrypted_key_hex(enc_key_buf);

    // Decrypt the session key
    string key = decryptKeyRSA(encrypted_key_hex, d, n);
    cout << "Shared Secret Key (Decrypted): " << key << endl;

    // Prepare DES keys
    vector<vector<string>> keys256;
    for(int i = 0; i < 4; i++){
        string subkey = key.substr(i * 16, 16);
        keys256.push_back(generateKeys(hex2bin(subkey)));
    }

    char buffer[1024];

    while(true){
        memset(buffer,0,1024);
        recv(client,buffer,1024,0);

        string ct(buffer);

        if(ct=="exit") break;

        // Extract IV and decrypt block-by-block in CTR mode (block size is 64 bits = 16 hex characters)
        string pt = "";
        if (ct.size() >= 16) {
            string iv_hex = ct.substr(0, 16);
            string ciphertext_only = ct.substr(16);
            uint64_t iv_val = stoull(iv_hex, nullptr, 16);

            for(size_t i = 0; i < ciphertext_only.size(); i += 16){
                string block = ciphertext_only.substr(i, 16);
                if(block.size() < 16) {
                    block.append(16 - block.size(), '0');
                }
                string counter_bin = bitset<64>(iv_val).to_string();
                string keystream_bin = encrypt256(counter_bin, keys256);
                string pt_bin = XOR(hex2bin(block), keystream_bin);
                pt += bin2hex(pt_bin);
                iv_val++;
            }
        }

        // Convert hex plaintext to ASCII text
        string text = "";
        for(size_t i = 0; i < pt.size(); i += 2){
            string byteStr = pt.substr(i, 2);
            char ch = (char)strtol(byteStr.c_str(), nullptr, 16);
            text += ch;
        }

        cout << "\n--- Message Received ---" << endl;
        cout << "Ciphertext (Hex): " << ct << endl;
        cout << "Decrypted (Hex):  " << pt << endl;
        cout << "Decrypted (Text): " << text << endl;
        cout << "------------------------" << endl;
    }

    WSACleanup();
    return 0;
}