#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <memory> // For std::unique_ptr
#include <cstring> // For strlen, strcmp

// Linux Socket Headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> // For close
#include <arpa/inet.h>

// JSON library
#include "json.hpp"

// C library for bcrypt (libcrypt)
// Make sure libcrypt-dev is installed on Debian
#include <crypt.h> // For crypt()

// MySQL Connector/C++ headers
#include <mysql_connection.h>
#include <mysql_driver.h>
#include <cppconn/exception.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>

// SSL Connection Wrapper
#include "ssl_connection.h" // New header for SSL wrapper

using json = nlohmann::json;

const int PORT = 8080;
const int BUFFER_SIZE = 4096;

// MySQL Database Credentials
const std::string DB_HOST = "localhost";
const std::string DB_USER = "cloud_user";
const std::string DB_PASS = "您的实际密码"; // !!! 请务必替换为您的实际密码 !!!
const std::string DB_NAME = "cloud_drive_db";

// Global MySQL Driver instance
sql::mysql::MySQL_Driver* driver;

// --- Helper Functions ---

// Helper function to ensure all bytes are read from SSL, handling partial reads.
bool ssl_read_all(SSL* ssl, void* buf, int num_bytes_to_read, const std::string& client_ip) {
    int bytes_read = 0;
    while (bytes_read < num_bytes_to_read) {
        int ret = SSL_read(ssl, static_cast<char*>(buf) + bytes_read, num_bytes_to_read - bytes_read);
        if (ret <= 0) {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                std::cout << "[Server] Client disconnected during read: " << client_ip << std::endl;
            } else {
                ERR_print_errors_fp(stderr);
                std::cerr << "[Server] SSL_read error for client: " << client_ip << std::endl;
            }
            return false;
        }
        bytes_read += ret;
    }
    return true;
}

// Function to send JSON response over SSL
void send_json_response_ssl(SSL* ssl_handle, const json& res) {
    std::string res_str = res.dump();
    uint32_t size = htonl(res_str.length());
    SSL_write(ssl_handle, &size, sizeof(size));
    SSL_write(ssl_handle, res_str.c_str(), res_str.length());
    std::cout << "[Server] Sent response: " << res_str << std::endl;
}

// Helper function to get a database connection
std::unique_ptr<sql::Connection> get_db_connection() {
    try {
        std::unique_ptr<sql::Connection> con(driver->connect(DB_HOST, DB_USER, DB_PASS));
        con->setSchema(DB_NAME);
        return con;
    } catch (sql::SQLException &e) {
        std::cerr << "[DB Error] Could not connect to database: " << e.what() << std::endl;
        return nullptr;
    }
}

// --- Password Hashing with libcrypt ---
// This is a simplified wrapper for crypt().
// crypt() will generate its own salt based on the prefix ($2a$ for bcrypt)
// and append it to the hash. The cost factor (e.g., 10) is also part of the salt.
std::string hash_password_libcrypt(const std::string& plain_password) {
    // Standard bcrypt prefix with cost factor 10.
    // crypt() generates a random salt for us if it's not provided or is generic.
    // For specific salt generation, you'd prepend a random string to "$2a$10$".
    const char* settings = "$2a$10$"; // For bcrypt with cost 10
    char* hashed_c_str = crypt(plain_password.c_str(), settings);
    if (hashed_c_str == nullptr) {
        std::cerr << "Error: crypt() failed to hash password." << std::endl;
        return "";
    }
    return std::string(hashed_c_str);
}

// Verify password with libcrypt
bool verify_password_libcrypt(const std::string& plain_password, const std::string& stored_hash) {
    if (stored_hash.empty()) {
        return false;
    }
    // crypt() will extract the salt from the stored_hash and use it for comparison
    char* verified_hash_c_str = crypt(plain_password.c_str(), stored_hash.c_str());
    if (verified_hash_c_str == nullptr) {
        return false; // Error during verification
    }
    // Compare the newly generated hash with the stored hash
    return strcmp(stored_hash.c_str(), verified_hash_c_str) == 0;
}


// --- Request Handlers ---

// Handles user registration requests
void handle_register(SSL* ssl_handle, const json& request_payload) {
    std::string username = request_payload["username"];
    std::string plain_password = request_payload["password"];

    json response;
    response["type"] = "register_response";
    response["request_id"] = request_payload["request_id"];

    std::unique_ptr<sql::Connection> con = get_db_connection();
    if (!con) {
        response["status"] = "error";
        response["message"] = "Internal server error: DB connection failed.";
        send_json_response_ssl(ssl_handle, response);
        return;
    }

    try {
        // 1. Check if username already exists
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement("SELECT COUNT(*) FROM users WHERE username = ?"));
        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        res->next();
        if (res->getInt(1) > 0) {
            response["status"] = "error";
            response["message"] = "Username already exists.";
            send_json_response_ssl(ssl_handle, response);
            return;
        }

        // 2. Hash password using libcrypt
        std::string hashed_password = hash_password_libcrypt(plain_password);
        if (hashed_password.empty()) {
            response["status"] = "error";
            response["message"] = "Failed to hash password.";
            std::cerr << "[Server] Failed to hash password for user: " << username << std::endl;
            send_json_response_ssl(ssl_handle, response);
            return;
        }

        // 3. Insert new user into database
        pstmt.reset(con->prepareStatement("INSERT INTO users(username, hashed_password) VALUES (?, ?)"));
        pstmt->setString(1, username);
        pstmt->setString(2, hashed_password);
        pstmt->executeUpdate();

        response["status"] = "success";
        response["message"] = "Registration successful.";
        std::cout << "[Server] User registered: " << username << std::endl;
        std::cout << "[Server] Hashed password for " << username << ": " << hashed_password << std::endl;

    } catch (sql::SQLException &e) {
        std::cerr << "[DB Error] Register: " << e.what() << std::endl;
        response["status"] = "error";
        response["message"] = "Internal server error during registration.";
    }
    send_json_response_ssl(ssl_handle, response);
}

// Handles user login requests
void handle_login(SSL* ssl_handle, const json& request_payload) {
    std::string username = request_payload["username"];
    std::string plain_password = request_payload["password"];

    json response;
    response["type"] = "login_response";
    response["request_id"] = request_payload["request_id"];

    std::unique_ptr<sql::Connection> con = get_db_connection();
    if (!con) {
        response["status"] = "error";
        response["message"] = "Internal server error: DB connection failed.";
        send_json_response_ssl(ssl_handle, response);
        return;
    }

    try {
        // 1. Retrieve hashed password from database
        std::unique_ptr<sql::PreparedStatement> pstmt(con->prepareStatement("SELECT hashed_password FROM users WHERE username = ?"));
        pstmt->setString(1, username);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());

        if (res->next()) { // User found
            std::string stored_hashed_password = res->getString("hashed_password");

            // 2. Verify password using libcrypt
            if (verify_password_libcrypt(plain_password, stored_hashed_password)) {
                response["status"] = "success";
                response["message"] = "Login successful.";
                response["payload"]["session_token"] = "mock_session_token_" + username;
                std::cout << "[Server] User logged in: " << username << std::endl;
            } else {
                response["status"] = "error";
                response["message"] = "Incorrect username or password.";
            }
        } else { // User not found
            response["status"] = "error";
            response["message"] = "Incorrect username or password.";
        }

    } catch (sql::SQLException &e) {
        std::cerr << "[DB Error] Login: " << e.what() << std::endl;
        response["status"] = "error";
        response["message"] = "Internal server error during login.";
    }
    send_json_response_ssl(ssl_handle, response);
}

// --- Client Connection Handler ---

// Function executed in a new thread for each client
void handle_client(int client_sockfd, const std::string& client_ip, SSL_CTX* ssl_ctx) {
    std::cout << "[Server] New client connected from: " << client_ip << std::endl;

    // Perform SSL handshake
    SSL* ssl_handle = SSL_new(ssl_ctx);
    SSL_set_fd(ssl_handle, client_sockfd);
    if (SSL_accept(ssl_handle) <= 0) {
        ERR_print_errors_fp(stderr);
        std::cerr << "[Server] SSL handshake failed for client: " << client_ip << std::endl;
        SSL_free(ssl_handle);
        close(client_sockfd);
        return;
    }
    std::cout << "[Server] SSL handshake successful with client: " << client_ip << std::endl;

    while (true) {
        // First, receive the size of the incoming JSON string over SSL
        uint32_t json_size_net;
        if (!ssl_read_all(ssl_handle, &json_size_net, sizeof(json_size_net), client_ip)) {
            break; // Client disconnected or error
        }

        uint32_t json_size = ntohl(json_size_net);

        // Set a reasonable maximum message size (e.g., 1MB) to prevent abuse
        if (json_size == 0 || json_size > 1024 * 1024) {
             std::cerr << "[Server] Invalid or too large JSON size received from " << client_ip << ": " << json_size << std::endl;
             break;
        }

        // Dynamically allocate buffer for the JSON string
        std::vector<char> buffer(json_size);

        // Receive the JSON string itself over SSL
        if (!ssl_read_all(ssl_handle, buffer.data(), json_size, client_ip)) {
            break; // Client disconnected or error
        }

        // Use the vector data to construct the string
        std::string request_str(buffer.begin(), buffer.end());
        std::cout << "[Server] Received request from " << client_ip << ": " << request_str << std::endl;

        try {
            json request = json::parse(request_str);
            std::string type = request.value("type", "");

            if (type == "register") {
                handle_register(ssl_handle, request["payload"]);
            } else if (type == "login") {
                handle_login(ssl_handle, request["payload"]);
            } else {
                json response;
                response["type"] = "error";
                response["message"] = "Unknown request type.";
                if (request.contains("request_id")) {
                    response["request_id"] = request["request_id"];
                }
                send_json_response_ssl(ssl_handle, response);
            }
        } catch (const json::parse_error& e) {
            std::cerr << "[Server] JSON parse error: " << e.what() << std::endl;
            json response;
            response["type"] = "error";
            response["message"] = "Invalid JSON format.";
            send_json_response_ssl(ssl_handle, response);
        } catch (const json::exception& e) {
            std::cerr << "[Server] JSON exception (missing key, wrong type): " << e.what() << std::endl;
            json response;
            response["type"] = "error";
            response["message"] = "Malformed request payload.";
            send_json_response_ssl(ssl_handle, response);
        } catch (const std::exception& e) {
            std::cerr << "[Server] General error handling request: " << e.what() << std::endl;
            json response;
            response["type"] = "error";
            response["message"] = "Internal server error.";
            send_json_response_ssl(ssl_handle, response);
        }
    }

    SSL_shutdown(ssl_handle); // Shut down SSL connection
    SSL_free(ssl_handle);     // Free SSL object
    close(client_sockfd);     // Close the underlying socket
    std::cout << "[Server] Client disconnected and SSL closed: " << client_ip << std::endl;
}

// --- Main Server Function ---

int main() {
    // 1. Initialize OpenSSL
    SSL_Connection::init_openssl();

    // Initialize MySQL Driver
    try {
        driver = sql::mysql::get_mysql_driver_instance();
    } catch (sql::SQLException &e) {
        std::cerr << "Could not initialize MySQL driver: " << e.what() << std::endl;
        SSL_Connection::cleanup_openssl();
        return 1;
    }

    // Initialize SSL Context
    SSL_CTX* ssl_ctx = SSL_Connection::create_server_context("server.crt", "server.key");
    if (!ssl_ctx) {
        std::cerr << "Failed to create SSL context." << std::endl;
        SSL_Connection::cleanup_openssl();
        return 1;
    }
    
    int server_sockfd;
    sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
        perror("Error creating socket");
        SSL_CTX_free(ssl_ctx);
        SSL_Connection::cleanup_openssl();
        return 1;
    }

    int optval = 1;
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Error setting socket options");
        close(server_sockfd);
        SSL_CTX_free(ssl_ctx);
        SSL_Connection::cleanup_openssl();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        close(server_sockfd);
        SSL_CTX_free(ssl_ctx);
        SSL_Connection::cleanup_openssl();
        return 1;
    }

    if (listen(server_sockfd, 5) < 0) {
        perror("Error listening on socket");
        close(server_sockfd);
        SSL_CTX_free(ssl_ctx);
        SSL_Connection::cleanup_openssl();
        return 1;
    }

    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    while (true) {
        int client_sockfd = accept(server_sockfd, (sockaddr*)&client_addr, &client_addr_len);
        if (client_sockfd < 0) {
            perror("Error accepting connection");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

        // Pass SSL_CTX to the client handler
        std::thread client_handler(handle_client, client_sockfd, std::string(client_ip), ssl_ctx);
        client_handler.detach();
    }

    close(server_sockfd);
    SSL_CTX_free(ssl_ctx); // Free SSL context when server shuts down
    SSL_Connection::cleanup_openssl(); // 2. Cleanup OpenSSL
    return 0;
}