#include <fstream>
#include <windows.h>
#include <thread>
#include <shlwapi.h>
#include <string>
#include <iostream>
#include <sstream>

#include "httplib.h"
#include "json.hpp"
#include "helper.h"

#include <idp.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#pragma comment(lib, "Advapi32.lib")

std::string CleanModelResponse(const std::string& raw_response) {
    std::string text = raw_response;
    TrimStr(text);

    // 1. Check if the response contains JSON
    try {
        size_t json_start = text.find('{');
        size_t json_end = text.rfind('}');
        if (json_start != std::string::npos && json_end != std::string::npos && json_end > json_start) {
            std::string json_str = text.substr(json_start, json_end - json_start + 1);
            auto j = nlohmann::json::parse(json_str);

            std::string ini_out;
            std::string summary = "Decompiled code analyzed by BinaryLens";
            if (j.contains("summary") && j["summary"].is_string()) {
                summary = j["summary"].get<std::string>();
            }
            else if (j.contains("BinaryInfo") && j["BinaryInfo"].is_object() && j["BinaryInfo"].contains("summary")) {
                summary = j["BinaryInfo"]["summary"].get<std::string>();
            }
            else if (j.contains("FunctionInfo") && j["FunctionInfo"].is_object() && j["FunctionInfo"].contains("summary")) {
                summary = j["FunctionInfo"]["summary"].get<std::string>();
            }

            // Check for function renames
            nlohmann::json funcs;
            if (j.contains("RenamedFunctions") && j["RenamedFunctions"].is_object()) {
                funcs = j["RenamedFunctions"];
            }
            else if (j.contains("renamed_functions") && j["renamed_functions"].is_object()) {
                funcs = j["renamed_functions"];
            }
            else if (j.contains("functions") && j["functions"].is_object()) {
                funcs = j["functions"];
            }

            if (!funcs.empty()) {
                ini_out += "[BinaryInfo]\nsummary=" + summary + "\n\n[RenamedFunctions]\n";
                for (auto& el : funcs.items()) {
                    if (el.value().is_string()) {
                        ini_out += el.key() + "=" + el.value().get<std::string>() + "\n";
                    }
                }
                return ini_out;
            }

            // Check for local variable renames
            nlohmann::json locals;
            if (j.contains("RenamedLocals") && j["RenamedLocals"].is_object()) {
                locals = j["RenamedLocals"];
            }
            else if (j.contains("renamed_locals") && j["renamed_locals"].is_object()) {
                locals = j["renamed_locals"];
            }
            else if (j.contains("variables") && j["variables"].is_object()) {
                locals = j["variables"];
            }

            if (!locals.empty()) {
                ini_out += "[FunctionInfo]\nsummary=" + summary + "\n\n[RenamedLocals]\n";
                for (auto& el : locals.items()) {
                    if (el.value().is_string()) {
                        ini_out += el.key() + "=" + el.value().get<std::string>() + "\n";
                    }
                }
                return ini_out;
            }
        }
    }
    catch (...) {
        // Not JSON or parse failed, continue with INI cleaning
    }

    // 2. Strip markdown fences and conversational noise around INI
    std::string cleaned;
    std::istringstream stream(text);
    std::string line;
    bool in_section = false;

    while (std::getline(stream, line)) {
        TrimStr(line);
        // Skip markdown code block markers
        if (line.rfind("```", 0) == 0) {
            continue;
        }
        if (line.rfind("[BinaryInfo]", 0) == 0 || line.rfind("[FunctionInfo]", 0) == 0 ||
            line.rfind("[RenamedFunctions]", 0) == 0 || line.rfind("[RenamedLocals]", 0) == 0) {
            in_section = true;
        }
        if (in_section) {
            // Filter out comments starting with // or #
            if (line.rfind("//", 0) == 0 || line.rfind("#", 0) == 0) {
                continue;
            }
            cleaned += line + "\n";
        }
    }

    if (!cleaned.empty()) {
        return cleaned;
    }

    return text;
}

std::string GetResponseFromModel(
    std::string model,
    std::string api_key,
    std::string system_prompt,
    std::string user_prompt,
    std::string custom_base_url
) {
    std::string scheme_host_port;
    std::string chat_endpoint;
    int max_token_len = 128000;

    nlohmann::json body = {
        {"model", model},
        {"messages", {
            {{"role", "system"}, {"content", system_prompt}},
            {{"role", "user"}, {"content", user_prompt}}
        }}
    };

    if (!custom_base_url.empty()) {
        std::string url = custom_base_url;
        TrimStr(url);
        if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) {
            url = "https://" + url;
        }
        while (!url.empty() && url.back() == '/') {
            url.pop_back();
        }
        size_t scheme_pos = url.find("://");
        size_t path_pos = url.find('/', scheme_pos + 3);
        if (path_pos == std::string::npos) {
            scheme_host_port = url;
            chat_endpoint = "/v1/chat/completions";
        }
        else {
            scheme_host_port = url.substr(0, path_pos);
            chat_endpoint = url.substr(path_pos);
            if (chat_endpoint.rfind("/chat/completions") == std::string::npos) {
                chat_endpoint += "/chat/completions";
            }
        }
        max_token_len = 128000;
    }
    else if (ContainsSubstring(model, "gemini")) {
        scheme_host_port = "https://generativelanguage.googleapis.com";
        chat_endpoint = "/v1beta/openai/chat/completions";
        max_token_len = 1000000;
    }
    else if (ContainsSubstring(model, "deepseek")) {
        scheme_host_port = "https://api.deepseek.com";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 128000;

        // Set the deepseek output token to max, as the default is 4k
        body["max_tokens"] = 8192;
    }
    else if (ContainsSubstring(model, "gpt") || ContainsSubstring(model, "o1") || ContainsSubstring(model, "o3")) {
        scheme_host_port = "https://api.openai.com";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 128000;
    }
    else {
        // Default to local Ollama if unspecified
        scheme_host_port = "http://localhost:11434";
        chat_endpoint = "/v1/chat/completions";
        max_token_len = 128000;
    }

    int estimated_token_len = static_cast<int>(user_prompt.length() / 2.31);
    ThreadLogMessage(LOG_PATH, 0, "Estimated token length of the request: %d\n", estimated_token_len);

    if (estimated_token_len > max_token_len) {
        ThreadLogMessage(LOG_PATH, 3, "The given request is too large for the selected model (%s). "
            "Please choose a smaller binary or function.\n", model.c_str()
        );
        return std::string();
    }

    httplib::Client cli(scheme_host_port);
    cli.set_read_timeout(1200, 0);
    cli.set_write_timeout(600, 0);

    ThreadLogMessage(LOG_PATH, 0, "Client created for host: %s\n", scheme_host_port.c_str());

    httplib::Headers headers = {
        {"Content-Type", "application/json"},
        {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) BinaryLens/2.0"}
    };
    if (chat_endpoint.find("opencode") != std::string::npos || scheme_host_port.find("opencode") != std::string::npos) {
        headers.emplace("x-opencode-session", "bl_ida_session");
        headers.emplace("x-opencode-client", "binarylens");
    }
    if (!api_key.empty()) {
        headers.emplace("Authorization", "Bearer " + api_key);
    }
    cli.set_default_headers(headers);

    ThreadLogMessage(LOG_PATH, 0, "Headers set\n");

    auto dumpped_body = body.dump();

    ThreadLogMessage(LOG_PATH, 0, "Body dumped successfully\n");

    auto res = cli.Post(chat_endpoint, dumpped_body, "application/json");

    ThreadLogMessage(LOG_PATH, 0, "Request sent to endpoint: %s\n", chat_endpoint.c_str());

    if (!res) {
        ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
            "Please check your internet connection and try again later.\n"
        );
        return std::string();
    }

    if (res->status != 200) {
        // Try to parse the error message from the response
        nlohmann::json error_data;
        try {
            error_data = nlohmann::json::parse(res->body);

            std::string error_message;
            if (error_data.is_array())
                error_message = error_data[0]["error"]["message"];
            else
                error_message = error_data["error"]["message"];

            ThreadLogMessage(LOG_PATH, 3, "Request to (%s) rejected, with error:"
                "\n\n%s\n", model.c_str(), error_message.c_str()
            );
        }
        catch (const std::exception& e) {
            // If parsing fails, just print the status code
            ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
                "Please try again later. Failed with status (%d).\n", res->status
            );
            ThreadLogMessage(LOG_PATH, 0, "Response JSON:\n%s\n", error_data.dump(4).c_str());
        }
        return std::string();
    }

    nlohmann::json data;
    std::string model_response;

    try {
        data = nlohmann::json::parse(res->body);
        model_response = data["choices"][0]["message"]["content"];
    }
    catch (const std::exception& e) {
        ThreadLogMessage(LOG_PATH, 3, "Failed to get a response from the model. "
            "Model request was rejected unexpectedly. Please try again later.\n"
        );
        ThreadLogMessage(LOG_PATH, 0, "Response JSON:\n%s\n", data.dump(4).c_str());
        return std::string();
    }

    model_response = CleanModelResponse(model_response);
    return model_response;
}

bool LogMessage(const char* path, int display_type, const char* format, ...) {
    va_list args;
    va_start(args, format);

    va_list args_copy;
    va_copy(args_copy, args);
    int len = qvsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) {
        msg("[BinaryLens] WARNING: Failed to format log string\n");
        va_end(args);
        return false;
    }

    char* buf = (char*)malloc(len + 1);
    if (!buf) {
        msg("[BinaryLens] WARNING: Memory allocation failed for log string\n");
        va_end(args);
        return false;
    }

    qvsnprintf(buf, len + 1, format, args);
    va_end(args);

    FILE* logfile = qfopen(path, "a");
    if (!logfile) {
        msg("[BinaryLens] WARNING: Failed to open log file\n");
        free(buf);
        return false;
    }

    qfprintf(logfile, "%s", buf);

    if (display_type == 1)
        msg("%s", buf);
    if (display_type == 2)
        info("%s", buf);
    if (display_type == 3)
        warning("%s", buf);

    qfclose(logfile);
    free(buf);

    return true;
}

class LogMsgInMain : public exec_request_t {
public:
    int display_type;
    char* msg;

    ssize_t execute() override {
        LogMessage(LOG_PATH, display_type, "%s", msg);
        free(msg);
        return 0;
    }
};

bool ThreadLogMessage(const char* path, int display_type, const char* format, ...) {
    va_list args;
    va_start(args, format);

    va_list args_copy;
    va_copy(args_copy, args);
    int len = qvsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (len < 0) {
        msg("[BinaryLens] WARNING: Failed to format log string\n");
        va_end(args);
        return false;
    }

    char* buf = (char*)malloc(len + 1);
    if (!buf) {
        msg("[BinaryLens] WARNING: Memory allocation failed for log string\n");
        va_end(args);
        return false;
    }

    qvsnprintf(buf, len + 1, format, args);
    va_end(args);

    LogMsgInMain LogMsgInMain;
    LogMsgInMain.display_type = display_type;
    LogMsgInMain.msg = buf;

    execute_sync(LogMsgInMain, MFF_WRITE);

    return true;
}

bool WriteRegistryData(const char* sub_key, const char* value_name, const char* data_to_write) {
    HKEY hKey;

    if (RegCreateKeyExA(
        HKEY_CURRENT_USER,
        sub_key,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        nullptr,
        &hKey,
        nullptr
    ) != ERROR_SUCCESS) {
        LogMessage(LOG_PATH, 3, "Failed to create or open registry key. Error code: %ld\n", GetLastError());
        return false;
    }

    if (RegSetValueExA(
        hKey,
        value_name,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(data_to_write),
        strlen(data_to_write) + 1
    ) != ERROR_SUCCESS) {
        LogMessage(LOG_PATH, 3, "Failed to write data to registry. Error code: %ld\n", GetLastError());
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

bool ReadRegistryData(const char* sub_key, const char* value_name, std::string& read_data) {
    HKEY hKey;

    if (RegCreateKeyExA(
        HKEY_CURRENT_USER,
        sub_key,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        nullptr,
        &hKey,
        nullptr
    ) != ERROR_SUCCESS) {
        ThreadLogMessage(LOG_PATH, 3, "ERROR: Failed to create or open registry key. Error code: %ld\n", GetLastError());
        return false;
    }

    char buffer[4096];
    DWORD buffer_size = sizeof(buffer);
    if (RegGetValueA(hKey, nullptr, value_name, RRF_RT_REG_SZ, nullptr, buffer, &buffer_size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    read_data = std::string(buffer);
    RegCloseKey(hKey);
    return true;
}

std::string WrapText(const std::string& text, size_t max_line_length) {
    std::istringstream input(text);
    std::ostringstream output;
    std::string line;

    while (std::getline(input, line)) {
        std::istringstream words(line);
        std::string word;
        std::string currentLine;

        while (words >> word) {
            if (currentLine.empty()) {
                currentLine = word;
            }
            else if (currentLine.size() + 1 + word.size() <= max_line_length) {
                currentLine += " " + word;
            }
            else {
                output << currentLine << "\n";
                currentLine = word;
            }
        }
        output << currentLine << "\n";
    }

    return output.str();
}

bool SaveFileContent(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        LogMessage(LOG_PATH, 3, "Failed to open file for writing: %s\n", filepath.c_str());
        return false;
    }

    file.write(content.data(), content.size());
    if (!file) {
        LogMessage(LOG_PATH, 3, "Failed to write to file: %s\n", filepath.c_str());
        return false;
    }

    return true;
}

std::string GetFileContent(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        LogMessage(LOG_PATH, 3, "Failed to open file: %s\n", filepath.c_str());
        return std::string();
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string file_content = buffer.str();

    if (file_content.empty()) {
        LogMessage(LOG_PATH, 3, "File is empty: %s\n", filepath.c_str());
        return std::string();
    }

    return file_content;
}

void ltrim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
        }));
}

void rtrim(std::string& s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
        }).base(), s.end());
}

void TrimStr(std::string& s) {
    ltrim(s);
    rtrim(s);
}

void RemoveSubstring(std::string& str, const std::string& target) {
    size_t pos;
    while ((pos = str.find(target)) != std::string::npos) {
        str.erase(pos, target.length());
    }
}

bool ContainsSubstring(const std::string& str, const std::string& target) {
    return str.find(target) != std::string::npos;
}