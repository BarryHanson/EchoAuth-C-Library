#include "echoauth/client.hpp"
#include "echoauth/crypto.hpp"
#include "echoauth/exceptions.hpp"
#include <windows.h>
#include <wininet.h>
#include <algorithm>

#pragma comment(lib, "wininet.lib")

namespace echoauth {

EchoAuthClient::EchoAuthClient(
    const std::string& api_url,
    const std::string& api_secret,
    bool verify_ssl
) : api_url_(api_url), api_secret_(api_secret), verify_ssl_(verify_ssl) {
    // Remove trailing slash if present
    if (!api_url_.empty() && api_url_.back() == '/') {
        api_url_.pop_back();
    }
}

EchoAuthClient::~EchoAuthClient() {
    // Securely clear sensitive data
    if (!auth_token_.empty()) {
        SecureZeroMemory((void*)auth_token_.data(), auth_token_.size());
        auth_token_.clear();
    }
    if (!api_secret_.empty()) {
        SecureZeroMemory((void*)api_secret_.data(), api_secret_.size());
        api_secret_.clear();
    }
}

std::map<std::string, std::string> EchoAuthClient::get_request_headers() {
    std::map<std::string, std::string> headers;
    headers["Content-Type"] = "application/json";
    headers["User-Agent"] = "EchoAuth/1.0";

    if (!auth_token_.empty()) {
        headers["Authorization"] = "Bearer " + auth_token_;
    }

    return headers;
}

std::string EchoAuthClient::sign_request(const std::string& data) {
    return Crypto::hmac_sha256(data, api_secret_);
}

LoginResponse EchoAuthClient::login(
    const std::string& username,
    const std::string& password,
    const std::string& hwid
) {
    // Build JSON body with HWID for session locking
    std::string body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"";
    if (!hwid.empty()) {
        body += ",\"hwid\":\"" + hwid + "\"";
    }
    body += "}";

    try {
        std::string response = http_post("/api/auth/login", body);

        LoginResponse login_resp;
        login_resp.success = response.find("\"status\":\"success\"") != std::string::npos;

        if (login_resp.success) {
            // Extract token (simplified parsing)
            size_t token_pos = response.find("\"token\":\"");
            if (token_pos != std::string::npos) {
                token_pos += 9; // strlen("\"token\":\"")
                size_t token_end = response.find("\"", token_pos);
                if (token_end != std::string::npos) {
                    login_resp.token = response.substr(token_pos, token_end - token_pos);
                    auth_token_ = login_resp.token;
                }
            }
        } else {
            size_t msg_pos = response.find("\"message\":\"");
            if (msg_pos != std::string::npos) {
                msg_pos += 11;
                size_t msg_end = response.find("\"", msg_pos);
                login_resp.message = response.substr(msg_pos, msg_end - msg_pos);
            }
        }

        return login_resp;

    } catch (const std::exception& e) {
        throw AuthenticationException(e.what());
    }
}

UserInfoResponse EchoAuthClient::get_user_info() {
    try {
        std::string response = http_get("/api/auth/me");

        UserInfoResponse user_info;
        user_info.success = response.find("\"status\":\"success\"") != std::string::npos;

        return user_info;

    } catch (const std::exception& e) {
        throw NetworkException(e.what());
    }
}

CheatFileDownloadResponse EchoAuthClient::download_cheat(
    int cheat_id,
    const std::string& xor_key
) {
    CheatFileDownloadResponse response;

    try {
        // Download cheat file (returns base64-encoded JSON)
        std::string endpoint = "/api/client/download";
        std::string body = "{\"cheatId\":" + std::to_string(cheat_id) + "}";
        std::string file_response = http_post(endpoint, body);

        // Parse base64 data from JSON response
        size_t data_pos = file_response.find("\"data\":\"");
        if (data_pos != std::string::npos) {
            data_pos += 8; // strlen("\"data\":\"")
            size_t data_end = file_response.find("\"", data_pos);
            if (data_end != std::string::npos) {
                std::string base64_data = file_response.substr(data_pos, data_end - data_pos);

                // Decode base64
                response.file_data = Crypto::base64_decode(base64_data);
            }
        }

        // XOR encrypt the file data before returning
        auto encrypted = Crypto::xor_encrypt(response.file_data, xor_key);
        response.file_data = encrypted;

        response.success = !response.file_data.empty();
        return response;

    } catch (const std::exception& e) {
        response.success = false;
        response.message = e.what();
        return response;
    }
}

bool EchoAuthClient::verify_response_signature(
    const std::string& data,
    const std::string& signature
) {
    std::string expected_sig = sign_request(data);
    // Use constant-time comparison to prevent timing attacks
    return std::equal(signature.begin(), signature.end(), expected_sig.begin());
}

void EchoAuthClient::set_token(const std::string& token) {
    auth_token_ = token;
}

std::string EchoAuthClient::get_token() const {
    return auth_token_;
}

bool EchoAuthClient::activate_key(const std::string& key) {
    // HWID should be provided by the caller
    // This is now a stub - activation should be implemented by the loader
    std::string hwid = Crypto::bytes_to_hex(Crypto::random_bytes(16));
    std::string body = "{\"key\":\"" + key + "\",\"hwid\":\"" + hwid + "\"}";

    try {
        std::string response = http_post("/api/client/activate", body);
        return response.find("\"status\":\"success\"") != std::string::npos;
    } catch (...) {
        return false;
    }
}

// Simplified HTTP implementations (would use libcurl in production)

std::string EchoAuthClient::http_get(
    const std::string& endpoint,
    const std::map<std::string, std::string>& headers
) {
    (void)headers; // Mark as intentionally unused for future header implementation

    HINTERNET hInternet = InternetOpenA("EchoAuth/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        throw NetworkException("Failed to open internet connection");
    }

    std::string url = api_url_ + endpoint;

    // Parse URL
    URL_COMPONENTSA urlComponents;
    ZeroMemory(&urlComponents, sizeof(urlComponents));
    urlComponents.dwStructSize = sizeof(urlComponents);
    urlComponents.dwHostNameLength = (DWORD)-1;
    urlComponents.dwUrlPathLength = (DWORD)-1;
    urlComponents.dwSchemeLength = (DWORD)-1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.length(), 0, &urlComponents)) {
        InternetCloseHandle(hInternet);
        throw NetworkException("Invalid URL format");
    }

    std::string hostName(urlComponents.lpszHostName, urlComponents.dwHostNameLength);
    std::string pathName(urlComponents.lpszUrlPath, urlComponents.dwUrlPathLength);
    if (pathName.empty()) pathName = "/";

    HINTERNET hConnect = InternetConnectA(hInternet, hostName.c_str(), urlComponents.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to connect to API");
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", pathName.c_str(), "HTTP/1.1", NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to create HTTP request");
    }

    // Add Authorization header if token is set
    if (!auth_token_.empty()) {
        std::string auth_header = "Authorization: Bearer " + auth_token_ + "\r\n";
        HttpAddRequestHeadersA(hRequest, auth_header.c_str(), (DWORD)auth_header.length(), HTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to send GET request");
    }

    // Read response
    std::string response;
    char buffer[4096];
    DWORD bytes_read;

    while (InternetReadFile(hRequest, (LPVOID)buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        response.append(buffer, bytes_read);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

std::string EchoAuthClient::http_post(
    const std::string& endpoint,
    const std::string& body,
    const std::map<std::string, std::string>& headers
) {
    (void)headers; // Mark as intentionally unused for future header implementation

    HINTERNET hInternet = InternetOpenA("EchoAuth/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) {
        throw NetworkException("Failed to open internet connection");
    }

    std::string url = api_url_ + endpoint;

    // Parse URL to extract host and path
    URL_COMPONENTSA urlComponents;
    ZeroMemory(&urlComponents, sizeof(urlComponents));
    urlComponents.dwStructSize = sizeof(urlComponents);
    urlComponents.dwHostNameLength = (DWORD)-1;
    urlComponents.dwUrlPathLength = (DWORD)-1;
    urlComponents.dwSchemeLength = (DWORD)-1;

    if (!InternetCrackUrlA(url.c_str(), (DWORD)url.length(), 0, &urlComponents)) {
        InternetCloseHandle(hInternet);
        throw NetworkException("Invalid URL format");
    }

    // Extract components
    std::string hostName(urlComponents.lpszHostName, urlComponents.dwHostNameLength);
    std::string pathName(urlComponents.lpszUrlPath, urlComponents.dwUrlPathLength);
    if (pathName.empty()) pathName = "/";

    HINTERNET hConnect = InternetConnectA(hInternet, hostName.c_str(), urlComponents.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to connect to API");
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", pathName.c_str(), "HTTP/1.1", NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to create HTTP request");
    }

    // Set Content-Type header
    const char* headers_str = "Content-Type: application/json\r\n";
    if (!HttpAddRequestHeadersA(hRequest, headers_str, (DWORD)strlen(headers_str), HTTP_ADDREQ_FLAG_REPLACE)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to set headers");
    }

    // Add Authorization header if token is set
    if (!auth_token_.empty()) {
        std::string auth_header = "Authorization: Bearer " + auth_token_ + "\r\n";
        HttpAddRequestHeadersA(hRequest, auth_header.c_str(), (DWORD)auth_header.length(), HTTP_ADDREQ_FLAG_REPLACE);
    }

    // Send request
    if (!HttpSendRequestA(hRequest, NULL, 0, (LPVOID)body.c_str(), (DWORD)body.length())) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        throw NetworkException("Failed to send POST request");
    }

    // Read response
    std::string response;
    char buffer[4096];
    DWORD bytes_read;

    while (InternetReadFile(hRequest, (LPVOID)buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        response.append(buffer, bytes_read);
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

bool EchoAuthClient::fetch_api_secret() {
    try {
        std::string response = http_get("/api/client/api-secret");

        // Parse API secret from response
        // Expected JSON: {"status":"success","data":{"apiSecret":"secret_value"},...}
        size_t secret_pos = response.find("\"apiSecret\":\"");
        if (secret_pos != std::string::npos) {
            secret_pos += 13; // strlen("\"apiSecret\":\"")
            size_t secret_end = response.find("\"", secret_pos);
            if (secret_end != std::string::npos) {
                std::string new_secret = response.substr(secret_pos, secret_end - secret_pos);
                // Securely clear old secret
                if (!api_secret_.empty()) {
                    SecureZeroMemory((void*)api_secret_.data(), api_secret_.size());
                }
                api_secret_ = new_secret;
                return true;
            }
        }

        return false;

    } catch (const std::exception& e) {
        throw NetworkException(std::string("Failed to fetch API secret: ") + e.what());
    }
}

} // namespace echoauth
