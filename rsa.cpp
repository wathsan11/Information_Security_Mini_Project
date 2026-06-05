#include "rsa.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

using namespace std;

uint64_t mod_mult(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)(((unsigned __int128)a * b) % m);
}

uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t m) {
    uint64_t res = 1;
    base = base % m;
    while (exp > 0) {
        if (exp & 1) res = mod_mult(res, base, m);
        base = mod_mult(base, base, m);
        exp >>= 1;
    }
    return res;
}

int64_t extGCD(int64_t a, int64_t b, int64_t &x, int64_t &y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int64_t x1, y1;
    int64_t d = extGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - y1 * (a / b);
    return d;
}

uint64_t mod_inverse(uint64_t e, uint64_t phi) {
    int64_t x, y;
    extGCD(e, phi, x, y);
    return (x % (int64_t)phi + (int64_t)phi) % (int64_t)phi;
}

string encryptKeyRSA(const string& secret_key, uint64_t e, uint64_t n) {
    if (secret_key.size() != 64) {
        throw invalid_argument("Secret key must be exactly 64 hex characters.");
    }
    stringstream result;
    for (int i = 0; i < 8; i++) {
        string chunk = secret_key.substr(i * 8, 8);
        uint64_t val = stoull(chunk, nullptr, 16);
        uint64_t enc = mod_pow(val, e, n);
        result << hex << uppercase << setw(16) << setfill('0') << enc;
    }
    return result.str();
}

string decryptKeyRSA(const string& encrypted_key_hex, uint64_t d, uint64_t n) {
    if (encrypted_key_hex.size() != 128) {
        throw invalid_argument("Encrypted key must be exactly 128 hex characters.");
    }
    stringstream result;
    for (int i = 0; i < 8; i++) {
        string chunk = encrypted_key_hex.substr(i * 16, 16);
        uint64_t val = stoull(chunk, nullptr, 16);
        uint64_t dec = mod_pow(val, d, n);
        result << hex << uppercase << setw(8) << setfill('0') << dec;
    }
    return result.str();
}
