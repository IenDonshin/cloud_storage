#include "ssl_connection.h"
#include <iostream>

namespace SSL_Connection {

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms(); // Load all available algorithms
    std::cout << "[SSL] OpenSSL initialized." << std::endl;
}

void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
    std::cout << "[SSL] OpenSSL cleaned up." << std::endl;
}

SSL_CTX* create_server_context(const std::string& cert_path, const std::string& key_path) {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method(); // Use a modern TLS method
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cerr << "[SSL] Error loading server certificate: " << cert_path << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cerr << "[SSL] Error loading server private key: " << key_path << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[SSL] Private key does not match the public certificate." << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    std::cout << "[SSL] Server SSL context created and configured." << std::endl;
    return ctx;
}

SSL_CTX* create_client_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_client_method(); // Use a modern TLS method
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // Optional: Load trusted CA certificates to verify server
    // For a self-signed cert, you'd load the server's cert here as trusted CA.
    // SSL_CTX_load_verify_locations(ctx, "server.crt", nullptr);
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr); // Enable peer verification

    std::cout << "[SSL] Client SSL context created." << std::endl;
    return ctx;
}

void log_ssl_errors() {
    ERR_print_errors_fp(stderr);
}

} // namespace SSL_Connection