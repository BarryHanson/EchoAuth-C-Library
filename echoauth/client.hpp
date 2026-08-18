#pragma once

#include "response.hpp"
#include "crypto.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>

namespace echoauth {

class EchoAuthClient {
public:
    /**
     * Create a new EchoAuth client
     * @param api_url Base URL of the API (e.g., "http://localhost:3001")
     * @param api_secret Shared secret for HMAC signing (from environment or config)
     * @param verify_ssl Whether to verify SSL certificates
     */
    explicit EchoAuthClient(
        const std::string& api_url,
        const std::string& api_secret,
        bool verify_ssl = true
    );

    ~EchoAuthClient();

    /**
     * Authenticate with username and password
     * @param username User's username
     * @param password User's password
     * @param hwid Hardware ID for session locking (optional)
     * @return LoginResponse with token if successful
     */
    LoginResponse login(
        const std::string& username,
        const std::string& password,
        const std::string& hwid = ""
    );

    /**
     * Refresh authentication token
     * @param refresh_token Token from initial login
     * @return LoginResponse with new token
     */
    LoginResponse refresh_token(const std::string& refresh_token);

    /**
     * Get current user information
     * @return UserInfoResponse with user details
     */
    UserInfoResponse get_user_info();

    /**
     * Get information about a license key
     * @param key The license key to check
     * @return KeyInfoResponse with key details
     */
    KeyInfoResponse get_key_info(const std::string& key);

    /**
     * Download cheat module from API
     * The downloaded data is XOR encrypted and never touches disk
     * @param cheat_id ID of the cheat module to download
     * @param xor_key Key for XOR decryption
     * @return CheatFileDownloadResponse with encrypted binary data
     */
    CheatFileDownloadResponse download_cheat(
        int cheat_id,
        const std::string& xor_key
    );

    /**
     * Verify API response signature
     * @param data Response data
     * @param signature HMAC signature from API
     * @return true if signature is valid
     */
    bool verify_response_signature(
        const std::string& data,
        const std::string& signature
    );

    /**
     * Set bearer token for authenticated requests
     * @param token JWT token from login
     */
    void set_token(const std::string& token);

    /**
     * Get current bearer token
     */
    std::string get_token() const;

    /**
     * Activate/bind key to this machine's HWID
     * @param key License key to activate
     * @return true if activation successful
     */
    bool activate_key(const std::string& key);

    /**
     * Fetch the owner's API secret from the server
     * Updates the internal api_secret_ with the owner-specific secret
     * @return true if successful
     */
    bool fetch_api_secret();

    // ===== Loader Convenience Methods =====

    /**
     * Check loader version and filename validity
     * @param loader_id ID of the loader application
     * @param current_version Version string (e.g., "1.0.0")
     * @param filename Expected loader filename
     * @return true if loader is up-to-date and filename matches
     */
    bool check_loader_version(
        int loader_id,
        const std::string& current_version,
        const std::string& filename
    );

    /**
     * Download cheat and validate PE header in one call
     * @param cheat_id ID of the cheat to download
     * @param xor_key XOR decryption key
     * @return CheatFileDownloadResponse (already decrypted and validated)
     */
    CheatFileDownloadResponse download_cheat_validated(
        int cheat_id,
        const std::string& xor_key
    );

    /**
     * Ban a user account (send ban request to API)
     * @param username Username of account to ban
     * @param hwid Hardware ID associated with account
     * @param reason Reason for ban (e.g., "Debugger detected")
     * @return true if ban request sent successfully
     */
    bool ban_account(
        const std::string& username,
        const std::string& hwid,
        const std::string& reason
    );

    /**
     * Submit log event to API
     * @param message Log message
     * @param level Log level (e.g., "critical", "warning", "info")
     * @return true if log submitted successfully
     */
    bool log_event(
        const std::string& message,
        const std::string& level
    );

    /**
     * Make HTTP GET request
     */
    std::string http_get(
        const std::string& endpoint,
        const std::map<std::string, std::string>& headers = {}
    );

    /**
     * Make HTTP POST request
     */
    std::string http_post(
        const std::string& endpoint,
        const std::string& body,
        const std::map<std::string, std::string>& headers = {}
    );

private:
    std::string api_url_;
    std::string api_secret_;
    std::string auth_token_;
    bool verify_ssl_;

    /**
     * Sign request with HMAC
     * @param data Request data to sign
     * @return HMAC-SHA256 signature in hex
     */
    std::string sign_request(const std::string& data);

    /**
     * Get standard headers for API requests
     */
    std::map<std::string, std::string> get_request_headers();

    /**
     * Parse JSON response (simplified - uses basic parsing)
     */
    static std::map<std::string, std::string> parse_json_response(
        const std::string& json
    );
};

} // namespace echoauth
