#include <bits/stdc++.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "des.h"

using namespace std;

vector<string> split(string s){
    while(s.size()%16) s+="0";
    vector<string> v;
    for(int i=0;i<s.size();i+=16) v.push_back(s.substr(i,16));
    return v;
}

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

    SOCKET sock=socket(AF_INET,SOCK_STREAM,0);

    sockaddr_in serv{};
    serv.sin_family=AF_INET;
    serv.sin_port=htons(8080);
    inet_pton(AF_INET,"127.0.0.1",&serv.sin_addr);

    connect(sock,(sockaddr*)&serv,sizeof(serv));

    cin.ignore();

    random_device rd;
    mt19937_64 generator(rd());

    while(true){
        string msg;
        cout<<"You: ";
        getline(cin,msg);

        if(msg=="exit"){
            send(sock,"exit",4,0);
            break;
        }

        uint64_t iv_val = generator();
        stringstream iv_ss;
        iv_ss << hex << uppercase << setw(16) << setfill('0') << iv_val;
        string iv_hex = iv_ss.str();

        stringstream ss;
        for(char c:msg)
            ss<<hex<<setw(2)<<setfill('0')<<(int)c;

        string hex=ss.str();
        auto blocks=split(hex);

        string ct=iv_hex;
        for(auto &b:blocks) {
            string counter_bin = bitset<64>(iv_val).to_string();
            string keystream_bin = encrypt256(counter_bin, keys256);
            string ct_bin = XOR(hex2bin(b), keystream_bin);
            ct += bin2hex(ct_bin);
            iv_val++;
        }

        send(sock,ct.c_str(),ct.size(),0);
    }

    WSACleanup();
}