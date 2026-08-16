#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace echoauth {

struct LoginResponse {
    bool success = false;
    std::string token;
    std::string refresh_token;
    int expires_in = 0;
    std::string message;
};

struct CheatFileDownloadResponse {
    bool success = false;
    std::vector<uint8_t> file_data;  // Raw binary data
    std::string filename;
    std::string download_token;      // Single-use token
    std::string signature;            // HMAC-SHA256 signature
    int expires_in = 0;               // Token expiry in seconds
    std::string message;
};

struct UserInfoResponse {
    bool success = false;
    int user_id = 0;
    std::string username;
    std::string role;
    int owner_id = 0;
    std::string message;
};

struct KeyInfoResponse {
    bool success = false;
    std::string key;
    std::string status;
    std::string hwid;
    int64_t expiry_timestamp = 0;
    bool is_activated = false;
    std::string message;
};

struct ApiResponse {
    bool success = false;
    std::string status;
    std::map<std::string, std::string> data;
    std::string message;
    int http_status = 0;
};

} // namespace echoauth
