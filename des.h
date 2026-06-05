#ifndef DES_H
#define DES_H

#include <bits/stdc++.h>
using namespace std;

string hex2bin(string s);
string bin2hex(string s);

string permute(string in,int *table,int n);
string shiftLeft(string k,int s);

vector<string> generateKeys(string key);

string XOR(string a,string b);
string sbox(string in);

string encrypt(string pt, vector<string> keys);
string decrypt(string ct, vector<string> keys);

string encrypt256(string pt, const vector<vector<string>>& keys);
string decrypt256(string ct, const vector<vector<string>>& keys);

#endif