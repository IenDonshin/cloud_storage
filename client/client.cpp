#include <iostream>
#include <string>
#include <vector>
#include <random> // For UUID generation
#include <chrono> // For timestamp
#include <stdexcept> // For std::runtime_error

// Linux Socket Headers (These headers are generally compatible with macOS)
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h> // For close
#include <arpa/inet.h> // For inet_addr

// JSON library
#include "json.hpp" // Make sure you have this header in your project

// SSL Connection Wrapper
#include "ssl_connection.h" // New header for SSL wrapper

using json = nlohmann::json;

// --- Server Details ---
const std::string SERVER_IP = "您的Google Cloud VM的外部IP地址"; // !!! 请务必替换为您的 VM 外部 IP 地址 !!!
const int SERVER_PORT = 8080;
const int BUFFER_SIZE = 4096;

// --- Helper Functions ---

// Function to generate a simple UUID-like string for request_id
std::string generate_uuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);

    const char* hex_chars = "0123456789abcdef";
    std::string uuid_str = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for (char &c : uuid_str) {
        if (c == 'x') {
            c = hex_chars[dis(gen)];
        } else if (c == 'y') {
            c = hex_chars[dis(gen) & 0x3 | 0x8]; // Variant 10xx
        }
    }
    return uuid_str;
}

// Function to get current timestamp
long long current_timestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// Function to send JSON request and receive JSON response over SSL
json send_receive_json_ssl(SSL* ssl_handle, const json& req) {
    std::string req_str = req.dump();
    std::cout << "[Client] Sending request: " << req_str << std::endl;

    // Prepend size of JSON string (4 bytes)
    uint32_t size = htonl(req_str.length());
    SSL_write(ssl_handle, &size, sizeof(size));
    SSL_write(ssl_handle, req_str.c_str(), req_str.length());

    // First, receive the size of the incoming JSON string over SSL
    uint32_t json_size_net;
    int ret = SSL_read(ssl_handle, &json_size_net, sizeof(json_size_net));
    if (ret <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL error
        std::cerr << "[Client] Server disconnected or error receiving size." << std::endl;
        throw std::runtime_error("SSL_read failed for size."); // Throw to indicate fatal error
    }
    uint32_t json_size = ntohl(json_size_net);

    if (json_size == 0 || json_size >= BUFFER_SIZE) {
         std::cerr << "[Client] Invalid JSON size received from server: " << json_size << std::endl;
         throw std::runtime_error("Invalid JSON size from server.");
    }

    // Receive the JSON string itself over SSL
    char buffer[BUFFER_SIZE];
    ret = SSL_read(ssl_handle, buffer, json_size);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL error
        std::cerr << "[Client] Server disconnected or error receiving data." << std::endl;
        throw std::runtime_error("SSL_read failed for data.");
    }
    buffer[ret] = '\0'; // Null-terminate the string

    std::string res_str(buffer);
    std::cout << "[Client] Received response: " << res_str << std::endl;

    try {
        return json::parse(res_str);
    } catch (const json::parse_error& e) {
        std::cerr << "[Client] JSON parse error on response: " << e.what() << std::endl;
        throw std::runtime_error("JSON parse error on response.");
    }
}

// --- Main Client Function ---

int main() {
    // Initialize SSL Context
    // Client does not need its own certificate for simple client-server
    SSL_CTX* ssl_ctx = SSL_Connection::create_client_context();
    if (!ssl_ctx) {
        std::cerr << "Failed to create SSL client context." << std::endl;
        return 1;
    }

    int client_sockfd;
    sockaddr_in server_addr;

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd < 0) {
        perror("Error creating socket");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP.c_str());

    if (connect(client_sockfd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        close(client_sockfd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    std::cout << "Connected to server " << SERVER_IP << ":" << SERVER_PORT << std::endl;

    // Perform SSL handshake
    SSL* ssl_handle = SSL_new(ssl_ctx);
    SSL_set_fd(ssl_handle, client_sockfd);
    if (SSL_connect(ssl_handle) <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL error
        std::cerr << "[Client] SSL handshake failed." << std::endl;
        SSL_free(ssl_handle);
        close(client_sockfd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }
    std::cout << "[Client] SSL handshake successful." << std::endl;

    std::string command;
    std::string username, password;

    try {
        while (true) {
            std::cout << "\nEnter command (register / login / exit): ";
            std::cin >> command;

            if (command == "register") {
                std::cout << "Enter username: ";
                std::cin >> username;
                std::cout << "Enter password: ";
                std::cin >> password;

                json request;
                request["type"] = "register";
                request["request_id"] = generate_uuid();
                request["timestamp"] = current_timestamp();
                request["payload"]["username"] = username;
                request["payload"]["password"] = password;

                json response = send_receive_json_ssl(ssl_handle, request);
                std::cout << "Registration Result: " << response["status"] << " - " << response["message"] << std::endl;
            } else if (command == "login") {
                std::cout << "Enter username: ";
                std::cin >> username;
                std::cout << "Enter password: ";
                std::cin >> password;

                json request;
                request["type"] = "login";
                request["request_id"] = generate_uuid();
                request["timestamp"] = current_timestamp();
                request["payload"]["username"] = username;
                request["payload"]["password"] = password;

                json response = send_receive_json_ssl(ssl_handle, request);
                std::cout << "Login Result: " << response["status"] << " - " << response["message"] << std::endl;
                if (response["status"] == "success" && response["payload"].contains("session_token")) {
                    std::cout << "Session Token: " << response["payload"]["session_token"] << std::endl;
                }
            } else if (command == "exit") {
                break;
            } else {
                std::cout << "Unknown command. Please use 'register', 'login', or 'exit'." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal client error: " << e.what() << std::endl;
    }

    SSL_shutdown(ssl_handle);
    SSL_free(ssl_handle);
    close(client_sockfd);
    SSL_CTX_free(ssl_ctx);
    std::cout << "Disconnected from server." << std::endl;

    return 0;
}