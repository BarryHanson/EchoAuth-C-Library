#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace echoauth {

class Crypto {
public:
    /**
     * Simple XOR encryption/decryption
     * XOR is symmetric, so same function encrypts and decrypts
     */
    static std::vector<uint8_t> xor_encrypt(
        const std::vector<uint8_t>& data,
        const std::string& key
    );

    static std::vector<uint8_t> xor_encrypt(
        const std::string& data,
        const std::string& key
    );

    static std::string xor_encrypt_string(
        const std::string& data,
        const std::string& key
    );

    static std::string xor_decrypt_string(
        const std::string& data,
        const std::string& key
    );

    /**
     * HMAC-SHA256 signature for API requests
     * Used to sign responses and verify authenticity
     */
    static std::string hmac_sha256(
        const std::string& data,
        const std::string& key
    );

    /**
     * SHA256 hash
     */
    static std::string sha256(const std::string& data);

    /**
     * Generate random bytes (for nonces, IVs, etc.)
     */
    static std::vector<uint8_t> random_bytes(size_t length);

    /**
     * Convert bytes to hex string
     */
    static std::string bytes_to_hex(const std::vector<uint8_t>& data);

    /**
     * Convert hex string to bytes
     */
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);

    /**
     * Base64 encode
     */
    static std::string base64_encode(const std::vector<uint8_t>& data);

    /**
     * Base64 decode
     */
    static std::vector<uint8_t> base64_decode(const std::string& data);
};

} // namespace echoauth
