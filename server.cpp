#include <bits/stdc++.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "des.h"

using namespace std;

int main(){
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    string key;
    while(true){
        cout<<"Key (64 hex chars / 256 bits): ";
        cin>>key;
        if(key.size() == 64){
            bool valid = true;
            for(char c : key){
                if(!isxdigit(c)){
                    valid = false;
                    break;
                }
            }
            if(valid) break;
        }
        cout<<"Invalid key. Must be exactly 64 hex characters.\n";
    }

    vector<vector<string>> keys256;
    for(int i = 0; i < 4; i++){
        string subkey = key.substr(i * 16, 16);
        keys256.push_back(generateKeys(hex2bin(subkey)));
    }

    SOCKET server=socket(AF_INET,SOCK_STREAM,0);

    sockaddr_in addr{};
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port=htons(8080);

    bind(server,(sockaddr*)&addr,sizeof(addr));
    listen(server,1);

    SOCKET client=accept(server,NULL,NULL);

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