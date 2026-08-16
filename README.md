# EchoAuth C++ Library

A modern, secure C++ library for integrating EchoAuth authentication into Windows applications. Provides JWT-based authentication, cryptographic operations, and secure communication with the EchoAuth backend.

## Features

- 🔐 **Secure Authentication** - Login with username/password and HWID locking
- 🔑 **API Key Validation** - Authenticate API keys with HWID binding
- 🎮 **Cheat Module Downloads** - Securely download encrypted cheat files
- 🛡️ **Advanced Cryptography**:
  - XOR symmetric encryption/decryption
  - HMAC-SHA256 signature verification
  - SHA256 hashing
  - Base64 encoding/decoding
  - Secure random bytes generation
- 🔒 **Security Features**:
  - Hardware ID (HWID) locking for session binding
  - Response signature verification
  - Secure memory clearing
  - Clock tampering detection
- ⚠️ **Exception Handling** - Custom exception hierarchy for robust error handling
- ⚡ **Thread-Safe** - Safe for multi-threaded applications

## Requirements

- **Visual Studio 2022** or later
- **Windows SDK** (for WinInet, CryptoAPI)
- **C++17** or later
- **Platform**: Windows 7+ (x86 or x64)

## Building

### Step 1: Open the Project

```bash
cd cpp/Lib
# Open in Visual Studio
EchoAuthLib.sln
```

### Step 2: Configure

1. Select configuration: **Debug** or **Release**
2. Select platform: **x64** (recommended) or **Win32**
3. Note: x64 is recommended for modern applications

### Step 3: Build

```
Build → Build Solution (Ctrl+Shift+B)
```

Output locations:
- **Debug**: `build/Debug/EchoAuthLib.lib` or similar
- **Release**: `build/Release/EchoAuthClient.lib` or similar

### System Libraries Required

The library depends on these Windows system libraries. Add to your project:

```
wininet.lib      # HTTP/HTTPS network requests
advapi32.lib     # CryptoAPI for HMAC-SHA256
crypt32.lib      # Base64 encoding/decoding
```

## Installation in Your Project

### 1. Copy Header Files

```bash
# Copy the echoauth/ folder to your project
cp -r cpp/Lib/echoauth your_project/
```

### 2. Configure Include Directories

In Visual Studio:
1. Right-click project → Properties
2. VC++ Directories
3. Include Directories: Add path to echoauth folder parent directory

### 3. Link Library

1. Add library file to Linker Input
   - `EchoAuthLib.lib` or `EchoAuthClient.lib`
2. Add system libraries: `wininet.lib advapi32.lib crypt32.lib`

### 4. Include in Code

```cpp
#include "echoauth/client.hpp"
using namespace echoauth;
```

## Public API

### Main Client Class

```cpp
namespace echoauth {
    class EchoAuthClient {
    public:
        // Constructor
        EchoAuthClient(
            const std::string& api_url,      // e.g., "http://localhost:3001"
            const std::string& api_secret,   // API secret key
            bool verify_ssl = true           // Verify SSL certificates
        );
        
        // Authentication
        LoginResponse login(
            const std::string& username,
            const std::string& password,
            const std::string& hwid = ""     // Optional HWID for locking
        );
        
        // Download encrypted cheat
        CheatFileDownloadResponse download_cheat(
            const std::string& cheat_id,
            const std::string& xor_key
        );
        
        // Verify response signature
        bool verify_response_signature(
            const std::string& response_data,
            const std::string& signature
        );
        
        // Set authentication token
        void set_token(const std::string& token);
        
        // HTTP methods (internal use)
        std::string http_get(const std::string& endpoint);
        std::string http_post(
            const std::string& endpoint,
            const std::string& body
        );
    };
}
```

### Response Structures

```cpp
// Login response
struct LoginResponse {
    bool success;
    std::string message;
    std::string token;              // JWT token
    std::string user_id;
    int expires_in;                 // Seconds until expiry
    std::string signature;          // HMAC-SHA256 signature
};

// Cheat download response
struct CheatFileDownloadResponse {
    bool success;
    std::string message;
    std::string file_data;          // XOR encrypted binary
    std::string cheat_status;       // "Detected" or "Undetected"
    std::string signature;
};

// Generic API response
struct ApiResponse {
    bool success;
    std::string message;
    std::string data;
    std::string signature;
};
```

### Cryptography Class

```cpp
namespace echoauth {
    class Crypto {
    public:
        // XOR encryption/decryption (symmetric)
        static std::string xor_encrypt(
            const std::string& data,
            const std::string& key
        );
        static std::string xor_decrypt(
            const std::string& data,
            const std::string& key
        );
        
        // HMAC-SHA256 (for signature verification)
        static std::string hmac_sha256(
            const std::string& message,
            const std::string& key
        );
        
        // SHA256 hashing
        static std::string sha256(const std::string& data);
        
        // Base64 encoding/decoding
        static std::string base64_encode(const std::string& data);
        static std::string base64_decode(const std::string& data);
        
        // Secure random bytes
        static std::string random_bytes(size_t length);
    };
}
```

### Exception Hierarchy

```cpp
namespace echoauth {
    // Base exception
    class Exception : public std::exception {
        virtual const char* what() const noexcept;
    };
    
    // Network errors
    class NetworkException : public Exception { };
    
    // Authentication errors
    class AuthenticationException : public Exception { };
    
    // Cryptography errors
    class CryptoException : public Exception { };
    
    // Security violations
    class SecurityException : public Exception { };
    
    // Validation errors
    class ValidationException : public Exception { };
}
```

## Usage Examples

### Example 1: Basic Login

```cpp
#include "echoauth/client.hpp"
#include <iostream>

using namespace echoauth;

int main() {
    try {
        // Create client
        EchoAuthClient client("http://localhost:3001", 
                             "your-api-secret-key",
                             false);  // false to skip SSL in dev
        
        // Login
        auto login = client.login("username", "password");
        
        if (login.success) {
            std::cout << "Login successful!" << std::endl;
            std::cout << "Token: " << login.token << std::endl;
            std::cout << "Expires in: " << login.expires_in << " seconds" << std::endl;
        } else {
            std::cout << "Login failed: " << login.message << std::endl;
        }
    }
    catch (const NetworkException& e) {
        std::cout << "Network error: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
```

### Example 2: Login with HWID Locking

```cpp
#include "echoauth/client.hpp"
#include "windows.h"
#include <iostream>

using namespace echoauth;

std::string get_hwid() {
    HW_PROFILE_INFO hwProfileInfo;
    GetCurrentHwProfile(&hwProfileInfo);
    return std::string(hwProfileInfo.szHwProfileGuid);
}

int main() {
    try {
        EchoAuthClient client("http://localhost:3001", 
                             "your-api-secret-key",
                             false);
        
        // Get HWID from current machine
        std::string hwid = get_hwid();
        
        // Login with HWID locking
        auto login = client.login("username", "password", hwid);
        
        if (login.success) {
            std::cout << "Login successful! Session locked to HWID: " << hwid << std::endl;
            client.set_token(login.token);
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
```

### Example 3: Download and Decrypt Cheat

```cpp
#include "echoauth/client.hpp"
#include <iostream>

using namespace echoauth;

int main() {
    try {
        EchoAuthClient client("http://localhost:3001", 
                             "your-api-secret-key",
                             false);
        
        // First, login and set token
        auto login = client.login("username", "password");
        if (!login.success) {
            std::cerr << "Login failed: " << login.message << std::endl;
            return 1;
        }
        client.set_token(login.token);
        
        // Download encrypted cheat
        auto download = client.download_cheat("cheat_123", "xor_encryption_key");
        
        if (download.success) {
            std::cout << "Cheat status: " << download.cheat_status << std::endl;
            
            if (download.cheat_status == "Detected") {
                std::cout << "WARNING: Cheat is detected by anticheat!" << std::endl;
                // Optionally ask user if they want to continue
            }
            
            // Decrypt the cheat file
            std::string decrypted = Crypto::xor_decrypt(
                download.file_data, 
                "xor_encryption_key"
            );
            
            // Validate PE header (MZ signature)
            if (decrypted.size() >= 2 && 
                decrypted[0] == 'M' && decrypted[1] == 'Z') {
                std::cout << "Valid PE file received!" << std::endl;
                // Execute or store decrypted data
            } else {
                std::cerr << "Invalid PE header!" << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Download failed: " << download.message << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
```

### Example 4: Error Handling

```cpp
#include "echoauth/client.hpp"
#include <iostream>
#include <thread>
#include <chrono>

using namespace echoauth;

LoginResponse login_with_retry(
    EchoAuthClient& client,
    const std::string& username,
    const std::string& password,
    int max_retries = 3
) {
    for (int attempt = 1; attempt <= max_retries; attempt++) {
        try {
            return client.login(username, password);
        }
        catch (const NetworkException& e) {
            if (attempt < max_retries) {
                // Exponential backoff: 1s, 2s, 4s
                int backoff_ms = 1000 * (1 << (attempt - 1));
                std::cout << "Network error, retrying in " 
                         << backoff_ms << "ms..." << std::endl;
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(backoff_ms)
                );
            } else {
                throw;  // Max retries reached
            }
        }
        catch (const AuthenticationException& e) {
            // Don't retry auth errors
            throw;
        }
    }
    
    throw NetworkException("Max retries exceeded");
}

int main() {
    try {
        EchoAuthClient client("http://localhost:3001", 
                             "your-api-secret-key",
                             false);
        
        auto login = login_with_retry(client, "user", "pass");
        
        if (login.success) {
            std::cout << "Login successful after retry!" << std::endl;
        }
    }
    catch (const NetworkException& e) {
        std::cerr << "Network error: " << e.what() << std::endl;
    }
    catch (const AuthenticationException& e) {
        std::cerr << "Authentication failed: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
    }
    
    return 0;
}
```

## Best Practices

### Security

1. **Never hardcode credentials** - Load from config files or environment
2. **Always verify response signatures** - Check HMAC before using response data
3. **Use HWID locking** - Prevents account sharing across machines
4. **Clear sensitive data** - Use SecureZeroMemory() for passwords/tokens
5. **Use HTTPS in production** - Set verify_ssl to true

### Performance

1. **Reuse client instances** - Create once, use multiple times
2. **Cache tokens** - Don't re-authenticate on every request
3. **Handle timeouts** - Set reasonable network timeouts
4. **Parallelize carefully** - Library is thread-safe but watch shared state

### Error Handling

1. **Catch specific exceptions** - Handle each error type appropriately
2. **Implement retry logic** - Use exponential backoff for transient errors
3. **Don't retry auth errors** - Invalid credentials won't succeed on retry
4. **Log all errors** - Keep audit trail for debugging
5. **Inform users** - Show clear error messages

## Troubleshooting

### LNK1104: Cannot open file 'EchoAuthLib.lib'

- Verify library was built successfully
- Check library path in project settings
- Ensure you're using correct platform (x64 vs Win32)

### C1083: Cannot open include file 'echoauth/client.hpp'

- Verify header files are copied to project
- Check include directory in project settings
- Ensure path is correct relative to include paths

### LNK2019: Unresolved external symbol

- Link against required system libraries:
  - wininet.lib
  - advapi32.lib
  - crypt32.lib
- Verify library file exists and is in linker input

### HWID does not match

- HWID is locked to specific machine on first login
- For testing, use different HWID or reset in admin panel
- HWID retrieval: `GetCurrentHwProfile(&hwProfileInfo)`

## Architecture

### Request/Response Flow

```
1. Client creates EchoAuthClient instance
2. Client sends request (login, download, etc)
3. Backend processes request
4. Backend returns response + HMAC-SHA256 signature
5. Client verifies signature
6. Client processes response data
```

### Data Flow for Cheat Download

```
1. Login (get JWT token)
2. Request cheat download with cheat_id
3. Backend returns encrypted file
4. Client decrypts with XOR key
5. Client validates PE header
6. Application uses decrypted module
```

## Performance Metrics

- **Authentication**: ~500ms (network dependent)
- **Response Verification**: <1ms
- **XOR Decryption**: 10-50ms for typical cheat files (1-10MB)
- **Memory Overhead**: ~500KB base + temporary buffers

## License

Proprietary - EchoAuth

---

For complete API documentation and guides, see:
- Frontend documentation site: http://localhost:3000/documentation/cpp-library
- API Reference: http://localhost:3000/documentation/api-reference
