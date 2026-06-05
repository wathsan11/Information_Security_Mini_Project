#ifndef RSA_H
#define RSA_H

#include <string>
#include <vector>
#include <stdint.h>

uint64_t mod_mult(uint64_t a, uint64_t b, uint64_t m);
uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t m);
uint64_t mod_inverse(uint64_t e, uint64_t phi);

// Encrypts a 64-char hex key into a 128-char hex string using RSA public key (e, n)
std::string encryptKeyRSA(const std::string& secret_key, uint64_t e, uint64_t n);

// Decrypts a 128-char hex string back to a 64-char hex key using RSA private key (d, n)
std::string decryptKeyRSA(const std::string& encrypted_key_hex, uint64_t d, uint64_t n);

#endif // RSA_H
