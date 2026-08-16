#include "echoauth/crypto.hpp"
#include "echoauth/exceptions.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>
#include <random>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace echoauth {

// ============================================================================
// XOR Encryption / Decryption
// ============================================================================

std::vector<uint8_t> Crypto::xor_encrypt(
    const std::vector<uint8_t>& data,
    const std::string& key
) {
    if (key.empty() || data.empty()) {
        return data;
    }

    std::vector<uint8_t> result = data;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.length()];
    }
    return result;
}

std::vector<uint8_t> Crypto::xor_encrypt(
    const std::string& data,
    const std::string& key
) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    return xor_encrypt(bytes, key);
}

std::string Crypto::xor_encrypt_string(
    const std::string& data,
    const std::string& key
) {
    auto encrypted = xor_encrypt(data, key);
    return std::string(encrypted.begin(), encrypted.end());
}

std::string Crypto::xor_decrypt_string(
    const std::string& data,
    const std::string& key
) {
    // XOR is symmetric
    return xor_encrypt_string(data, key);
}

// ============================================================================
// HMAC-SHA256 using Windows CryptoAPI
// ============================================================================

std::string Crypto::hmac_sha256(
    const std::string& data,
    const std::string& key
) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    try {
        // Acquire crypto context
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw CryptoException("Failed to acquire crypto context");
        }

        // Create HMAC hash
        if (!CryptCreateHash(hProv, CALG_HMAC, NULL, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to create hash");
        }

        // Set HMAC algorithm to SHA256
        HMAC_INFO hmacInfo;
        hmacInfo.HashAlgid = CALG_SHA_256;
        hmacInfo.pbInnerString = NULL;
        hmacInfo.cbInnerString = 0;

        if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to set hash algorithm");
        }

        // Hash the key
        if (!CryptHashData(hHash, (BYTE*)key.c_str(), (DWORD)key.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to hash key");
        }

        // Hash the data
        if (!CryptHashData(hHash, (BYTE*)data.c_str(), (DWORD)data.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to hash data");
        }

        // Get hash result
        DWORD cbHash = 32; // SHA256 = 32 bytes
        BYTE rgbHash[32] = { 0 };
        if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to get hash value");
        }

        // Convert to hex string
        std::string result = bytes_to_hex(std::vector<uint8_t>(rgbHash, rgbHash + 32));

        // Cleanup
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return result;

    } catch (const CryptoException&) {
        throw;
    } catch (const std::exception& e) {
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        throw CryptoException(std::string("HMAC error: ") + e.what());
    }
}

// ============================================================================
// SHA256
// ============================================================================

std::string Crypto::sha256(const std::string& data) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    try {
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw CryptoException("Failed to acquire crypto context");
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to create hash");
        }

        if (!CryptHashData(hHash, (BYTE*)data.c_str(), (DWORD)data.length(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to hash data");
        }

        DWORD cbHash = 32;
        BYTE rgbHash[32] = { 0 };
        if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            throw CryptoException("Failed to get hash value");
        }

        std::string result = bytes_to_hex(std::vector<uint8_t>(rgbHash, rgbHash + 32));

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return result;

    } catch (const CryptoException&) {
        throw;
    } catch (const std::exception& e) {
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        throw CryptoException(std::string("SHA256 error: ") + e.what());
    }
}

// ============================================================================
// Random Bytes
// ============================================================================

std::vector<uint8_t> Crypto::random_bytes(size_t length) {
    std::vector<uint8_t> result(length);

    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        throw CryptoException("Failed to acquire crypto context");
    }

    if (!CryptGenRandom(hProv, (DWORD)length, result.data())) {
        CryptReleaseContext(hProv, 0);
        throw CryptoException("Failed to generate random bytes");
    }

    CryptReleaseContext(hProv, 0);
    return result;
}

// ============================================================================
// Hex Encoding/Decoding
// ============================================================================

std::string Crypto::bytes_to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t byte : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

std::vector<uint8_t> Crypto::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        result.push_back(byte);
    }
    return result;
}

// ============================================================================
// Base64 Encoding/Decoding
// ============================================================================

static const char* base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Crypto::base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    int val = 0;
    int valb = 0;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 6) {
            valb -= 6;
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
        }
    }

    if (valb > 0) {
        result.push_back(base64_chars[(val << (6 - valb)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}

std::vector<uint8_t> Crypto::base64_decode(const std::string& data) {
    std::vector<uint8_t> result;
    std::vector<int> T(256, -1);

    for (int i = 0; i < 64; i++) {
        T[base64_chars[i]] = i;
    }

    int val = 0;
    int valb = 0;

    for (char c : data) {
        if (T[(unsigned char)c] == -1) break;
        val = (val << 6) + T[(unsigned char)c];
        valb += 6;
        if (valb >= 8) {
            valb -= 8;
            result.push_back((uint8_t)((val >> valb) & 0xFF));
        }
    }

    return result;
}

} // namespace echoauth
