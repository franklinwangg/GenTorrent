#pragma once
#ifndef S_IDA_HPP
#define S_IDA_HPP

#include <string>
#include <vector>
#include <set>
#include <random>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstdint>

#include "crypto_utils.hpp"     // Must provide encryptAES / decryptAES / etc.
#include "key_generation.hpp"   // Must provide generateAESKey()

namespace encrypt_p2p {

//=============================================================================
// 1) GF(256) Implementation for Shamir Secret Sharing
//    Using x^8 + x^4 + x^3 + x + 1 (as in AES), generator = 0x03.
//=============================================================================

class GF256 {
public:
    // Addition in GF(2^8) is XOR
    static inline uint8_t add(uint8_t a, uint8_t b) {
        return static_cast<uint8_t>(a ^ b);
    }

    // Subtraction is also XOR in GF(2^8)
    static inline uint8_t subtract(uint8_t a, uint8_t b) {
        return static_cast<uint8_t>(a ^ b);
    }

    // Multiplication in GF(2^8) using log tables
    static inline uint8_t multiply(uint8_t a, uint8_t b) {
        if (a == 0 || b == 0) return 0;
        // a * b = g^(log(a) + log(b))
        int sum = LOG_TABLE[a] + LOG_TABLE[b];
        if (sum >= 255) sum -= 255;
        return EXP_TABLE[sum];
    }

    // Division in GF(2^8) using log tables
    static inline uint8_t divide(uint8_t a, uint8_t b) {
        if (b == 0) throw std::runtime_error("Division by zero in GF256");
        if (a == 0) return 0;
        // a / b = g^(log(a) - log(b))
        int diff = LOG_TABLE[a] - LOG_TABLE[b];
        if (diff < 0) diff += 255;
        return EXP_TABLE[diff];
    }

    // Exponentiation: x^power in GF(2^8)
    static inline uint8_t pow(uint8_t x, int power) {
        if (x == 0) {
            // 0^0 = 1 in some contexts, but usually we treat 0^power=0 if power>0
            return (power == 0) ? 1 : 0;
        }
        // x^power = g^( (log(x) * power) mod 255 )
        long tmp = static_cast<long>(LOG_TABLE[x]) * power;
        tmp = tmp % 255;
        if (tmp < 0) tmp += 255;
        return EXP_TABLE[tmp];
    }

    // Initialize the exponent and log tables
    static void initTables() {
        if (!tablesInitialized) {
            generateTables();
            tablesInitialized = true;
        }
    }

private:
    // Multiplication in GF(2^8) without using tables (for table generation)
    static uint8_t rawMultiply(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        uint8_t highBit;
        
        for (int i = 0; i < 8; i++) {
            if (b & 1) {
                p ^= a;
            }
            
            highBit = (a & 0x80);
            a <<= 1;
            if (highBit) {
                a ^= 0x1B; // The reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
            }
            
            b >>= 1;
        }
        
        return p;
    }
    
    // Generate the exponent and log tables
    static void generateTables() {
        // Fill EXP_TABLE using the generator 0x03
        EXP_TABLE[0] = 0x01; // g^0 = 1
        for (int i = 1; i < 255; i++) {
            // g^i = g^(i-1) * g, where g = 0x03
            EXP_TABLE[i] = rawMultiply(EXP_TABLE[i-1], 0x03);
        }
        EXP_TABLE[255] = EXP_TABLE[0]; // For convenience
        
        // Fill LOG_TABLE using EXP_TABLE
        LOG_TABLE[0] = 0; // Undefined, but we'll set it to 0
        for (int i = 0; i < 255; i++) {
            LOG_TABLE[EXP_TABLE[i]] = i;
        }
    }

    // Tables for exponentiation and logarithm in GF(256)
    static inline uint8_t EXP_TABLE[256] = {0};
    static inline uint8_t LOG_TABLE[256] = {0};
    static inline bool tablesInitialized = false;
};

//=============================================================================
// 2) ShamirSecretSharing: Splitting & Combining
//    Splits a `secret` (e.g. 32-byte AES key) into n shares, requiring k to
//    reconstruct. The shares are (x, shareBytes).
//=============================================================================

class ShamirSecretSharing {
public:
    // Split a secret (bytes) into n shares, k required to reconstruct
    static std::vector<std::pair<uint8_t, std::vector<uint8_t>>> split(
        const std::string& secret, int n, int k
    ) {
        // Initialize GF256 tables if not already done
        GF256::initTables();
        
        if (k > n) {
            throw std::runtime_error("Shamir split: k > n not allowed");
        }
        if (k <= 0 || n <= 0) {
            throw std::runtime_error("Shamir split: k and n must be positive");
        }

        // Convert secret to bytes
        std::vector<uint8_t> secretBytes(secret.begin(), secret.end());
        size_t secretLen = secretBytes.size();

        // Random generator for polynomial coefficients
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(1, 255);

        // Initialize n shares with x coordinates 1..n
        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> shares;
        shares.reserve(n);
        for (int i = 1; i <= n; i++) {
            shares.push_back(std::make_pair(
                static_cast<uint8_t>(i),
                std::vector<uint8_t>(secretLen, 0)
            ));
        }

        // Process each byte of the secret separately
        for (size_t byteIdx = 0; byteIdx < secretLen; byteIdx++) {
            // Create a random polynomial of degree (k - 1)
            // with constant term = secretBytes[byteIdx]
            std::vector<uint8_t> poly(k);
            poly[0] = secretBytes[byteIdx]; // constant term

            // Random coefficients for higher terms
            for (int i = 1; i < k; i++) {
                poly[i] = static_cast<uint8_t>(dist(gen));
            }

            // Evaluate the polynomial at x in [1..n]
            for (int i = 0; i < n; i++) {
                uint8_t x = shares[i].first;
                shares[i].second[byteIdx] = evaluatePoly(poly, x);
            }
        }

        return shares;
    }

    // Combine k shares to reconstruct the original secret
    static std::string combine(
        const std::vector<std::pair<uint8_t, std::vector<uint8_t>>>& shares, int k
    ) {
        // Initialize GF256 tables if not already done
        GF256::initTables();
        
        if ((int)shares.size() < k) {
            throw std::runtime_error("Shamir combine: not enough shares");
        }

        // All shares must have the same byte length
        const size_t secretLen = shares[0].second.size();
        for (const auto& sh : shares) {
            if (sh.second.size() != secretLen) {
                throw std::runtime_error("Shamir combine: inconsistent share sizes");
            }
        }

        // Check for duplicate x-coordinates or zero
        std::set<uint8_t> xvals;
        for (auto &sh : shares) {
            if (sh.first == 0 || !xvals.insert(sh.first).second) {
                throw std::runtime_error("Shamir combine: duplicate or invalid x-coordinate");
            }
        }

        // We'll use the first k shares (or pick any k distinct)
        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> kShares;
        kShares.insert(kShares.begin(), shares.begin(), shares.begin() + k);

        std::vector<uint8_t> recovered(secretLen, 0);

        // Interpolate each byte position
        for (size_t byteIdx = 0; byteIdx < secretLen; byteIdx++) {
            // For each of the k shares, get that byte
            std::vector<uint8_t> yVals(k);
            for (int i = 0; i < k; i++) {
                yVals[i] = kShares[i].second[byteIdx];
            }

            // Interpolate at x = 0 (Lagrange)
            recovered[byteIdx] = interpolateAt0(kShares, yVals);
        }

        return std::string(recovered.begin(), recovered.end());
    }

private:
    // Evaluate polynomial at point x in GF(256)
    static uint8_t evaluatePoly(const std::vector<uint8_t>& poly, uint8_t x) {
        // poly[0] + poly[1]*x + poly[2]*x^2 + ...
        uint8_t result = poly[0];
        uint8_t powerOfX = 1;

        for (size_t i = 1; i < poly.size(); i++) {
            powerOfX = GF256::multiply(powerOfX, x);
            result = GF256::add(result, GF256::multiply(poly[i], powerOfX));
        }
        return result;
    }

    // Lagrange interpolation at x=0
    static uint8_t interpolateAt0(
        const std::vector<std::pair<uint8_t, std::vector<uint8_t>>>& shares,
        const std::vector<uint8_t>& yValues
    ) {
        uint8_t result = 0;
        const int k = static_cast<int>(shares.size());

        for (int i = 0; i < k; i++) {
            uint8_t xi = shares[i].first;
            uint8_t yi = yValues[i];

            // basis = ∏(j != i) [ (0 - xj) / (xi - xj) ]
            //        = ∏(j != i) [ xj / (xi - xj) ]
            uint8_t basis = 1;
            for (int j = 0; j < k; j++) {
                if (j == i) continue;
                uint8_t xj = shares[j].first;

                uint8_t numerator   = xj; // (0 - xj) = xj in GF(2^8) because it's just add
                uint8_t denominator = GF256::subtract(xi, xj); // (xi - xj)

                uint8_t term = GF256::divide(numerator, denominator);
                basis = GF256::multiply(basis, term);
            }

            // result += yi * basis
            result = GF256::add(result, GF256::multiply(yi, basis));
        }
        return result;
    }
};

//=============================================================================
// 3) SIDA:
//    - Generate 32-byte AES key
//    - Encrypt the entire message (returns hex string) with that key
//    - Shamir-split the key into (n,k)
//    - Store each share + the same hex ciphertext in each Clove
//=============================================================================

class SIDA {
public:
    struct Clove {
        // The encrypted data (ciphertext) is stored here as a vector of bytes
        // containing the hex representation. 
        // Then we store one Shamir share of the AES key.
        std::vector<uint8_t> fragment;   // hex-coded ciphertext
        std::pair<uint8_t, std::vector<uint8_t>> keyShare;  // (x, shareBytes)
        uint32_t originalDataSize;
    };

    // Split message into n cloves
    static std::vector<Clove> split(const std::string& message, int n, int k) {
        if (n < k) {
            throw std::runtime_error("SIDA::split: n < k");
        }
        // 1) Generate a 32-byte AES key
        std::string aesKey = generateAESKey();
        if (aesKey.size() != 32) {
            aesKey.resize(32, '\0');
        }
        std::cerr << "[DEBUG] Original AES key: " << toHex(aesKey) << std::endl;

        // 2) Encrypt the message; returns a hex string
        std::string cipherHex = encryptAES(message, aesKey);
        std::cerr << "[DEBUG] Ciphertext size: " << cipherHex.size() << " bytes" << std::endl;

        // 3) Shamir-split the AES key
        auto keyShares = ShamirSecretSharing::split(aesKey, n, k);

        // 4) Build Cloves
        std::vector<uint8_t> cipherVec(cipherHex.begin(), cipherHex.end());

        std::vector<Clove> cloves;
        cloves.reserve(n);
        for (int i = 0; i < n; i++) {
            Clove c;
            c.keyShare = keyShares[i];
            c.fragment = cipherVec;
            c.originalDataSize = static_cast<uint32_t>(cipherVec.size());
            cloves.push_back(c);
        }
        return cloves;
    }

    // Combine cloves to decrypt
    static std::string combine(const std::vector<Clove>& cloves, int k) {
        // Need at least k
        if ((int)cloves.size() < k) {
            throw std::runtime_error("SIDA::combine: not enough cloves");
        }

        // 1) Filter out duplicates or invalid x=0
        std::set<uint8_t> used;
        std::vector<Clove> valid;
        valid.reserve(cloves.size());

        // sort by x
        auto sorted = cloves;
        std::sort(sorted.begin(), sorted.end(),
                  [](auto &a, auto &b){
                      return a.keyShare.first < b.keyShare.first;
                  });
        for (auto &cl : sorted) {
            uint8_t x = cl.keyShare.first;
            if (x == 0) continue;
            if (!used.count(x)) {
                used.insert(x);
                valid.push_back(cl);
            }
        }

        if ((int)valid.size() < k) {
            throw std::runtime_error("SIDA::combine: not enough valid distinct shares");
        }
        valid.resize(k);

        // 2) Rebuild AES key from Shamir shares
        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> keyShares;
        for (auto &cl : valid) {
            keyShares.push_back(cl.keyShare);
        }
        std::string aesKey = ShamirSecretSharing::combine(keyShares, k);
        std::cerr << "[DEBUG] Reconstructed AES key: " << toHex(aesKey) << std::endl;

        // Make sure we have exactly 32 bytes
        if (aesKey.size() < 32) {
            aesKey.resize(32, '\0');
        } else if (aesKey.size() > 32) {
            aesKey.erase(aesKey.begin() + 32, aesKey.end());
        }

        // 3) Take ciphertext from the first valid clove
        if (valid[0].fragment.size() < 1) {
            throw std::runtime_error("SIDA::combine: empty ciphertext fragment");
        }
        uint32_t expectedLen = valid[0].originalDataSize;
        if (valid[0].fragment.size() < expectedLen) {
            throw std::runtime_error("SIDA::combine: incomplete ciphertext data");
        }

        // Convert from stored bytes to string
        std::string cipherHex(valid[0].fragment.begin(),
                              valid[0].fragment.begin() + expectedLen);
        std::cerr << "[DEBUG] Ciphertext size before decryption: " << cipherHex.size() << " bytes" << std::endl;

        // 4) Decrypt (cipherHex is a hex-encoded string)
        return decryptAES(cipherHex, aesKey);
    }
    
    // Serialize a clove to string format
    static std::string serializeClove(const Clove& clove) {
        // Format: originalDataSize|keyShareX|keyShareBytes|fragmentBytes
        std::stringstream ss;
        
        // Original data size
        ss << clove.originalDataSize << "|";
        
        // Key share X coordinate
        ss << static_cast<int>(clove.keyShare.first) << "|";
        
        // Key share bytes (hex encoded)
        for (uint8_t byte : clove.keyShare.second) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        ss << "|";
        
        // Fragment bytes (already hex encoded)
        for (uint8_t byte : clove.fragment) {
            ss << static_cast<char>(byte);
        }
        
        return ss.str();
    }
    
    // Deserialize a string to a clove
    static Clove deserializeClove(const std::string& serialized) {
        Clove clove;
        std::istringstream iss(serialized);
        std::string token;
        
        // Parse original data size
        if (!std::getline(iss, token, '|') || token.empty()) {
            throw std::runtime_error("Invalid clove format: missing originalDataSize");
        }
        clove.originalDataSize = static_cast<uint32_t>(std::stoul(token));
        
        // Parse key share X coordinate
        if (!std::getline(iss, token, '|') || token.empty()) {
            throw std::runtime_error("Invalid clove format: missing keyShare.first");
        }
        clove.keyShare.first = static_cast<uint8_t>(std::stoi(token));
        
        // Parse key share bytes
        if (!std::getline(iss, token, '|') || token.empty()) {
            throw std::runtime_error("Invalid clove format: missing keyShare.second");
        }
        
        // Convert hex string to bytes
        clove.keyShare.second.clear();
        for (size_t i = 0; i < token.length(); i += 2) {
            if (i + 1 >= token.length()) {
                throw std::runtime_error("Invalid hex encoding in keyShare");
            }
            std::string byteString = token.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            clove.keyShare.second.push_back(byte);
        }
        
        // Parse fragment bytes
        std::string fragmentStr;
        if (!std::getline(iss, fragmentStr) || fragmentStr.empty()) {
            throw std::runtime_error("Invalid clove format: missing fragment");
        }
        
        clove.fragment.assign(fragmentStr.begin(), fragmentStr.end());
        
        return clove;
    }

private:
    static std::string toHex(const std::string& input) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned char c : input) {
            oss << std::setw(2) << (int)c;
        }
        return oss.str();
    }
};

} // namespace encrypt_p2p

#endif // S_IDA_HPP