#pragma once

#include <exception>
#include <string>

namespace echoauth {

class Exception : public std::exception {
public:
    explicit Exception(const std::string& message) : message_(message) {}

    const char* what() const noexcept override {
        return message_.c_str();
    }

protected:
    std::string message_;
};

class NetworkException : public Exception {
public:
    explicit NetworkException(const std::string& message)
        : Exception("Network Error: " + message) {}
};

class AuthenticationException : public Exception {
public:
    explicit AuthenticationException(const std::string& message)
        : Exception("Authentication Error: " + message) {}
};

class CryptoException : public Exception {
public:
    explicit CryptoException(const std::string& message)
        : Exception("Crypto Error: " + message) {}
};

class SecurityException : public Exception {
public:
    explicit SecurityException(const std::string& message)
        : Exception("Security Error: " + message) {}
};

class MemoryException : public Exception {
public:
    explicit MemoryException(const std::string& message)
        : Exception("Memory Error: " + message) {}
};

class ValidationException : public Exception {
public:
    explicit ValidationException(const std::string& message)
        : Exception("Validation Error: " + message) {}
};

} // namespace echoauth
