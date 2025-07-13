#ifndef SSL_CONNECTION_H
#define SSL_CONNECTION_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

namespace SSL_Connection {

// Initializes OpenSSL library (should be called once at start)
void init_openssl();

// Cleans up OpenSSL library (should be called once at end)
void cleanup_openssl();

// Creates an SSL_CTX for server
SSL_CTX* create_server_context(const std::string& cert_path, const std::string& key_path);

// Creates an SSL_CTX for client
SSL_CTX* create_client_context();

// Generic error logging for SSL
void log_ssl_errors();

} // namespace SSL_Connection

#endif // SSL_CONNECTION_H