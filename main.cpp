#include <iostream>
#include <regex>
#include <netinet/in.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>

#define BUFFER_SIZE         1024
#define QUEUE_LENGTH        10

#define CONTENT_TYPE        "Content-Type: application/octet-stream"
#define CONTENT_LENGTH      "Content-Length: "
#define HTTP_VERSION        "HTTP/1.1"
#define CONNECTION_CLOSED   "Connection: close"
#define LOCATION_INFO       "Location: "

using servers_map = std::map<std::string, std::string>;

enum message_type {
    STANDARD,
    CLOSE,
    LOCATION
};

enum message_part {
    START_LINE,
    HEADER_FILE
};

enum header_t {
    CONNECTION,
    TYPE,
    LENGTH,
    SERVER
};

struct parse_results {
    std::string method;
    std::string directory;
    bool close;
    bool header_appeared[4];
};

const std::regex port_num_regex(R"([0-9]+)");
const std::regex correlated_line_regex(R"(([^\t\n]*)\t([^\t\n]*)\t([^\t\n]*)\n?)");

const std::regex start_line_regex(R"(([a-zA-Z]+) ((?:/[^ \r\n]*)+) HTTP/1\.1\r\n)");
const std::regex header_file_regex(R"(([^\s:]+): *([^\s:]+) *\r\n)");
const std::regex directory_regex(R"((?:/[a-zA-Z0-9.-]*)+)");

const std::regex connection_regex(R"(connection)", std::regex_constants::icase);
const std::regex content_type_regex(R"(content-type)", std::regex_constants::icase);
const std::regex content_length_regex(R"(content-length)", std::regex_constants::icase);
const std::regex server_regex(R"(server)", std::regex_constants::icase);

/*
 * Sends appropriate header and file [file_path] from directory [base_diractory] to currently
 * connected client if the file exists. Otherwise another header is sent to the client depending
 * on content of correlated servers. If [get] is [false] only the appropriate header is sent
 * without the content of the file.
 */
void send_file(int sock, std::string &base_directory, std::string &file_path,
               servers_map &correlated_servers, bool get);

/*
 * Sends header to currently connected client with given [status_code], [reason_phrase] and
 * [content_length]. Optionally it gets [msg_type] depending on which various header-fields
 * are added.
 */
void send_header(int sock, const std::string &status_code, const std::string &reason_phrase,
                 const std::string &content_length, message_type msg_type = STANDARD,
                 const std::string &location = "");

/*
 * Parses header field given as match result [m]. Returns [false] if the header field is invalid
 * and [true] otherwise.
 */
bool parse_header_field(parse_results &results, std::cmatch &m);

void reset_parse_results(parse_results &results);

/*
 * Gets results of parsing of vailid request and answers it depending on requested method.
 */
void answer_client_request(struct parse_results &results, int sock, std::string &base_directory,
                           servers_map &correlated_servers);

/*
 * Receives all the messages from one connection phase, parses them and sends appropriate answer.
 */
void get_client_request(int sock, std::string &base_directory, servers_map &correlated_servers);

void create_collection_of_correlated_servers(servers_map &correlated_servers, char *path);


int main(int argc, char *argv[]) {
    int sock, msg_sock;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    socklen_t client_address_len;
    servers_map correlated_servers;
    long port_number = 8080;
    struct stat base_dir_stat;

    if (argc == 4) {
        if (!regex_match(argv[3], port_num_regex))
            exit(EXIT_FAILURE);

        port_number = std::stol(argv[3], nullptr, 10);
    }
    else if (argc != 3) {
        exit(EXIT_FAILURE);
    }

    create_collection_of_correlated_servers(correlated_servers, argv[2]);

    if (stat(argv[1], &base_dir_stat) == -1 || !S_ISDIR(base_dir_stat.st_mode))
        exit(EXIT_FAILURE);

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        exit(EXIT_FAILURE);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port_number);

    if (bind(sock, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
        exit(EXIT_FAILURE);

    if (listen(sock, QUEUE_LENGTH) < 0)
        exit(EXIT_FAILURE);

    signal(SIGPIPE, SIG_IGN);
    std::string base_directory = argv[1];
    while (true) {
        client_address_len = sizeof(client_address);
        msg_sock = accept(sock, (struct sockaddr *)&client_address, &client_address_len);
        if (msg_sock < 0)
            exit(EXIT_FAILURE);

        get_client_request(msg_sock, base_directory, correlated_servers);
    }

    return 0;
}

void send_file(int sock, std::string &base_directory, std::string &file_path,
               servers_map &correlated_servers, bool get) {
    ssize_t read_len;
    char buffer[BUFFER_SIZE];
    struct stat stat_buf;

    FILE *file = fopen((base_directory + file_path).c_str(), "rb");
    if (file != nullptr && stat((base_directory + file_path).c_str(), &stat_buf) != 0) {
        send_header(sock, "500", "Server error", "0", CLOSE);
    }
    else if (file == nullptr || !S_ISREG(stat_buf.st_mode)) {
        auto it = correlated_servers.find(file_path);
        if (it == correlated_servers.end())
            send_header(sock, "404", "Not found", "0");
        else
            send_header(sock, "302", "Requested file is on another server", "0", LOCATION,
                        "http://" + it->second + it->first);
    }
    else {
        // Checks if requested file is in base directory.
        char *full_path = nullptr, *base_path = nullptr;
        full_path = realpath((base_directory + file_path).c_str(), full_path);
        base_path = realpath(base_directory.c_str(), base_path);
        if (full_path == nullptr || base_path == nullptr) {
            free(full_path);
            free(base_path);
            send_header(sock, "500", "Server error", "0", CLOSE);
            return;
        }
        std::string full(full_path), base(base_path);
        if (full.find(base, 0) == std::string::npos) {
            if (fclose(file) == -1)
                exit(EXIT_FAILURE);
            send_header(sock, "404", "Not found", "0");
            return;
        }

        struct stat file_stats;
        if (stat((base_directory + file_path).c_str(), &file_stats) != 0)
            send_header(sock, "500", "Server error", "0", CLOSE);

        send_header(sock, "200", "Success!",
                    std::to_string(file_stats.st_size));

        if (get) {
            if ((read_len = fread(buffer, 1, BUFFER_SIZE, file)) == -1)
                return;

            while (read_len != 0) {
                if (write(sock, buffer, read_len) < 0)
                    return;

                if ((read_len = fread(buffer, 1, BUFFER_SIZE, file)) == -1)
                    return;
            }
        }

        if (fclose(file) == -1)
            exit(EXIT_FAILURE);
    }
}

void send_header(int sock, const std::string &status_code, const std::string &reason_phrase,
                 const std::string &content_length, message_type msg_type, const std::string &location) {
    std::string start_line = HTTP_VERSION " " + status_code + " " + reason_phrase + "\r\n";
    std::string len_header = CONTENT_LENGTH + content_length + "\r\n";
    std::string type_header = CONTENT_TYPE "\r\n\r\n";

    ssize_t msg_len = start_line.length() + len_header.length() + type_header.length();

    if (msg_type == CLOSE) {
        std::string con_close = CONNECTION_CLOSED "\r\n";
        msg_len += con_close.length();
        msg_len = write(sock, (start_line + len_header + con_close + type_header).c_str(), msg_len);
    }
    else if (msg_type == LOCATION) {
        std::string loc = LOCATION_INFO + location + "\r\n";
        msg_len += loc.length();
        msg_len = write(sock, (start_line + len_header + loc + type_header).c_str(), msg_len);
    }
    else {
        msg_len = write(sock, (start_line + len_header + type_header).c_str(), msg_len);
    }
}

bool parse_header_field(parse_results &results, std::cmatch &m) {
    if (regex_match(m[1].first, m[1].second, connection_regex)) {
        if (results.header_appeared[CONNECTION])
            return false;

        results.header_appeared[CONNECTION] = true;
        if (m[2].str() == "close")
            results.close = true;
    }
    else if (regex_match(m[1].first, m[1].second, content_type_regex)) {
        if (results.header_appeared[TYPE])
            return false;

        results.header_appeared[TYPE] = true;
    }
    else if (regex_match(m[1].first, m[1].second, content_length_regex)) {
        if (results.header_appeared[LENGTH])
            return false;

        results.header_appeared[LENGTH] = true;
        try {
            if (stol(m[2].str()) != 0)
                return false;
        }
        catch (...) {
            return false;
        }
    }
    else if (regex_match(m[1].first, m[1].second, server_regex)) {
        if (results.header_appeared[SERVER])
            return false;

        results.header_appeared[SERVER] = true;
    }

    return true;
}

void reset_parse_results(parse_results &results) {
    for (int i = 0; i < 4; ++i)
        results.header_appeared[i] = false;
    results.close = false;
}

void answer_client_request(struct parse_results &results, int sock, std::string &base_directory,
                           servers_map &correlated_servers) {
    if (!regex_match(results.directory, directory_regex)) {
        send_header(sock, "404", "Not found", "0");
    }
    else if (results.method == "GET") {
        send_file(sock, base_directory, results.directory, correlated_servers, true);
    }
    else if (results.method == "HEAD") {
        send_file(sock, base_directory, results.directory, correlated_servers, false);
    }
    else {
        send_header(sock, "501", "Unknown request", "0");
    }
}

void get_client_request(int sock, std::string &base_directory, servers_map &correlated_servers) {
    ssize_t len = 0;
    size_t buf_size = BUFFER_SIZE;
    message_part msg_part = START_LINE;
    char *buffer = (char *)malloc(buf_size * sizeof(char));
    std::cmatch m;
    FILE *stream = fdopen(sock, "r");
    if (stream == nullptr)
        exit(EXIT_FAILURE);
    struct parse_results results;

    reset_parse_results(results);
    while ((len = getline(&buffer, &buf_size, stream)) > 0) {
        if (msg_part == START_LINE) {
            if (regex_match(buffer, m, start_line_regex)) {
                results.method = m[1].str();
                results.directory = m[2].str();
                msg_part = HEADER_FILE;
            }
            else {
                send_header(sock, "400", "Invalid request format", "0", CLOSE);
                break;
            }
        }
        else {
            if (regex_match(buffer, m, header_file_regex)) {
                if (!parse_header_field(results, m)) {
                    send_header(sock, "400", "Invalid request format", "0", CLOSE);
                    break;
                }
            }
            else {
                if (len == 2) {     // Line with only "\r\n".
                    answer_client_request(results, sock, base_directory, correlated_servers);
                    msg_part = START_LINE;
                    if (results.close)
                        break;
                    reset_parse_results(results);
                }
                else {
                    send_header(sock, "400", "Invalid request format", "0", CLOSE);
                    break;
                }
            }
        }
    }

    free(buffer);
    if (errno == ENOMEM)
        send_header(sock, "500", "Server error", "0", CLOSE);
    if (fclose(stream) != 0)
        exit(EXIT_FAILURE);
}

void create_collection_of_correlated_servers(servers_map &correlated_servers, char *path) {
    struct stat stat_buf;
    char *buffer = nullptr;
    size_t buf_size = 0;
    std::cmatch m;

    stat(path, &stat_buf);
    if (!S_ISREG(stat_buf.st_mode))
        exit(EXIT_FAILURE);

    FILE *file = fopen(path, "r");
    if (file == nullptr)
        exit(EXIT_FAILURE);

    while (getline(&buffer, &buf_size, file) >= 0) {
        if (regex_match(buffer, m, correlated_line_regex))
            correlated_servers.emplace(m[1].str(), m[2].str() + ":" + m[3].str());
    }

    free(buffer);
    if (errno == EINVAL || errno == ENOMEM)
        exit(EXIT_FAILURE);
}