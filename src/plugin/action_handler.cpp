#include <fstream>
#include <windows.h>
#include <thread>
#include <shlwapi.h>
#include <string>
#include <iostream>
#include <sstream>

#include "../helper/httplib.h"
#include "../helper/helper.h"
#include "action_handler.h"
#include "plugin.h"

#include <idp.hpp>
#include <ida.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <hexrays.hpp>

TWidget* widget;

bool HandleAnalysisActions(const char* action_name) {
    if (strcmp(action_name, "rename_subs") == 0) {
        if (sub_rename_end) {
            RenameAllSubs();
        }
    }

    if (strcmp(action_name, "rename_vars") == 0) {
        if (var_rename_end) {
            RenameVariables(widget);
        }
    }

    if (strcmp(action_name, "about") == 0) {
        info("BinaryLens - an IDA plugin that uses language models to speed up binary analysis."
            "\n\nFind more info at github.com/Berk000x/BinaryLens.\n\nv1.0.1\n"
        );
    }

    return true;
}

bool HandleModelActions(const char* action_name) {
    const char* sub_key = "SOFTWARE\\BinaryLensPlugin";
    if (strcmp(action_name, "custom_model_input") == 0) {
        qstring cur_val;
        std::string existing;
        if (ReadRegistryData(sub_key, "model_to_use", existing)) {
            cur_val = existing.c_str();
        }
        bool ok = ask_str(&cur_val, 0, "Enter Model Name (e.g. qwen2.5-coder:32b, deepseek-coder-v2, claude-3-7-sonnet):");
        if (ok && !cur_val.empty()) {
            std::string s = cur_val.c_str();
            TrimStr(s);
            WriteRegistryData(sub_key, "model_to_use", s.c_str());
            info("BinaryLens: Model set to '%s'\n", s.c_str());
        }
        return true;
    }
    if (strcmp(action_name, "custom_base_url_input") == 0) {
        qstring cur_val;
        std::string existing;
        if (ReadRegistryData(sub_key, "custom_base_url", existing)) {
            cur_val = existing.c_str();
        }
        else {
            cur_val = "http://localhost:11434/v1";
        }
        bool ok = ask_str(&cur_val, 0, "Enter API Base URL (e.g. http://localhost:11434/v1, https://openrouter.ai/api/v1):");
        if (ok) {
            std::string s = cur_val.c_str();
            TrimStr(s);
            WriteRegistryData(sub_key, "custom_base_url", s.c_str());
            info("BinaryLens: Base URL set to '%s'\n", s.c_str());
        }
        return true;
    }
    WriteRegistryData(sub_key, "model_to_use", action_name);
    info("BinaryLens: Active model set to '%s'\n", action_name);
    return true;
}

bool HandleApiKeyActions(const char* action_name) {
    qstring key;
    std::string existing;
    const char* sub_key = "SOFTWARE\\BinaryLensPlugin";
    if (ReadRegistryData(sub_key, action_name, existing)) {
        key = existing.c_str();
    }
    bool input = ask_str(&key, 0, "Enter your API key:");

    std::string key_str = key.c_str();

    if (!input)
        return true;

    TrimStr(key_str);
    WriteRegistryData(sub_key, action_name, key_str.c_str());
    info("BinaryLens: API key saved for '%s'\n", action_name);

    return true;
}

class FunctionActionHandler : public action_handler_t {
public:
    bool (*func)(const char*);

    FunctionActionHandler(bool (*f)(const char*)) {
        func = f;
    }

    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        if (func) {
            std::string action_name = ctx->action;
            RemoveSubstring(action_name, "BinaryLens:");
            return func(action_name.c_str()) ? 1 : 0;
        }
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

FunctionActionHandler analysis_handler(HandleAnalysisActions);
FunctionActionHandler model_handler(HandleModelActions);
FunctionActionHandler api_key_handler(HandleApiKeyActions);

// Action descriptors
const action_desc_t rename_subs_action = ACTION_DESC_LITERAL(
    "BinaryLens:rename_subs",
    "Rename all subroutines",
    &analysis_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t rename_vars_action = ACTION_DESC_LITERAL(
    "BinaryLens:rename_vars",
    "Rename variables",
    &analysis_handler,
    nullptr,
    nullptr,
    -1
);

// Gemini
const action_desc_t gemini_25_pro_action = ACTION_DESC_LITERAL(
    "BinaryLens:gemini-2.5-pro",
    "Gemini-2.5-Pro",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gemini_25_flash_action = ACTION_DESC_LITERAL(
    "BinaryLens:gemini-2.5-flash",
    "Gemini-2.5-Flash (Faster)",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gemini_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:gemini_api_key",
    "Set Gemini API key",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

// DeepSeek
const action_desc_t deepseek_chat_action = ACTION_DESC_LITERAL(
    "BinaryLens:deepseek-chat",
    "DeepSeek-Chat (V3)",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t deepseek_reasoner_action = ACTION_DESC_LITERAL(
    "BinaryLens:deepseek-reasoner",
    "DeepSeek-Reasoner (R1)",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t deepseek_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:deepseek_api_key",
    "Set DeepSeek API key",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

// OpenAI
const action_desc_t gpt_4o_action = ACTION_DESC_LITERAL(
    "BinaryLens:gpt-4o",
    "GPT-4o",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gpt_4o_mini_action = ACTION_DESC_LITERAL(
    "BinaryLens:gpt-4o-mini",
    "GPT-4o-mini",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t o3_mini_action = ACTION_DESC_LITERAL(
    "BinaryLens:o3-mini",
    "o3-mini",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t gpt_5_action = ACTION_DESC_LITERAL(
    "BinaryLens:gpt-5",
    "GPT-5",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t openai_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:openai_api_key",
    "Set OpenAI API key",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

// Custom & Local (Ollama / vLLM / OpenRouter)
const action_desc_t ollama_qwen_action = ACTION_DESC_LITERAL(
    "BinaryLens:qwen2.5-coder:32b",
    "Ollama: qwen2.5-coder:32b",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t custom_model_action = ACTION_DESC_LITERAL(
    "BinaryLens:custom_model_input",
    "Set Custom Model Name...",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t custom_url_action = ACTION_DESC_LITERAL(
    "BinaryLens:custom_base_url_input",
    "Set API Base URL (Ollama / OpenRouter)...",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t custom_api_action = ACTION_DESC_LITERAL(
    "BinaryLens:custom_api_key",
    "Set Custom API Key (Optional for Local)...",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t about_action = ACTION_DESC_LITERAL(
    "BinaryLens:about",
    "About",
    &analysis_handler,
    nullptr,
    nullptr,
    -1
);

ssize_t idaapi WidgetPopupCallback(void* user_data, int notification_code, va_list va) {
    if (notification_code == ui_populating_widget_popup) {
        TWidget* t_widget = va_arg(va, TWidget*);
        TPopupMenu* popup = va_arg(va, TPopupMenu*);
        if (get_widget_type(t_widget) == BWN_PSEUDOCODE) {
            ea_t current_ea = get_widget_vdui(t_widget)->cfunc->entry_ea;

            widget = t_widget;

            attach_action_to_popup(t_widget, popup, "BinaryLens:rename_vars", "BinaryLens/", SETMENU_APP);
        }
    }
    return 0;
}

plugmod_t* idaapi init() {
    SetConsoleOutputCP(CP_UTF8);
    DeleteFileA("BinaryLensLog.txt");

    if (!register_action(rename_subs_action)         ||
        !register_action(rename_vars_action)         ||
        !register_action(about_action)               ||
        !register_action(gemini_25_pro_action)       ||
        !register_action(gemini_25_flash_action)     ||
        !register_action(gemini_api_action)          ||
        !register_action(deepseek_chat_action)       ||
        !register_action(deepseek_reasoner_action)   ||
        !register_action(deepseek_api_action)        ||
        !register_action(gpt_4o_action)              ||
        !register_action(gpt_4o_mini_action)         ||
        !register_action(o3_mini_action)             ||
        !register_action(gpt_5_action)               ||
        !register_action(openai_api_action)          ||
        !register_action(ollama_qwen_action)         ||
        !register_action(custom_model_action)        ||
        !register_action(custom_url_action)          ||
        !register_action(custom_api_action)) {

        LogMessage(LOG_PATH, true, "[BinaryLens] ERROR: Failed to register actions.\n");
        return PLUGIN_SKIP;
    }

    // Create submenu in Edit menu
    if (!create_menu(ACTION_NAME, "BinaryLens", "Edit/")) {
        LogMessage(LOG_PATH, true, "[BinaryLens] ERROR: Failed to create Edit menu container\n");
        return PLUGIN_SKIP;
    }

    // Attach options to edit menu
    attach_action_to_menu("Edit/" ACTION_NAME "/", "BinaryLens:rename_subs", SETMENU_APP);

    // Gemini
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Gemini/", "BinaryLens:gemini-2.5-pro", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Gemini/", "BinaryLens:gemini-2.5-flash", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Gemini/", "BinaryLens:gemini_api_key", SETMENU_APP);

    // DeepSeek
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Deepseek/", "BinaryLens:deepseek-chat", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Deepseek/", "BinaryLens:deepseek-reasoner", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Deepseek/", "BinaryLens:deepseek_api_key", SETMENU_APP);

    // OpenAI
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:gpt-4o", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:gpt-4o-mini", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:o3-mini", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:gpt-5", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/OpenAI/", "BinaryLens:openai_api_key", SETMENU_APP);

    // Custom / Local
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Custom or Local (Ollama)/", "BinaryLens:qwen2.5-coder:32b", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Custom or Local (Ollama)/", "BinaryLens:custom_model_input", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Custom or Local (Ollama)/", "BinaryLens:custom_base_url_input", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Select model/Custom or Local (Ollama)/", "BinaryLens:custom_api_key", SETMENU_APP);

    attach_action_to_menu("Edit/" ACTION_NAME "/", "BinaryLens:about", SETMENU_APP);

    // Hook for popup menus
    hook_to_notification_point(HT_UI, WidgetPopupCallback, nullptr);

    return PLUGIN_KEEP;
}

void idaapi term() {
    unhook_from_notification_point(HT_UI, WidgetPopupCallback, nullptr);

    unregister_action("BinaryLens:rename_subs");
    unregister_action("BinaryLens:rename_vars");
    unregister_action("BinaryLens:gemini-2.5-pro");
    unregister_action("BinaryLens:gemini-2.5-flash");
    unregister_action("BinaryLens:gemini_api_key");
    unregister_action("BinaryLens:deepseek-chat");
    unregister_action("BinaryLens:deepseek-reasoner");
    unregister_action("BinaryLens:deepseek_api_key");
    unregister_action("BinaryLens:gpt-4o");
    unregister_action("BinaryLens:gpt-4o-mini");
    unregister_action("BinaryLens:o3-mini");
    unregister_action("BinaryLens:gpt-5");
    unregister_action("BinaryLens:openai_api_key");
    unregister_action("BinaryLens:qwen2.5-coder:32b");
    unregister_action("BinaryLens:custom_model_input");
    unregister_action("BinaryLens:custom_base_url_input");
    unregister_action("BinaryLens:custom_api_key");
    unregister_action("BinaryLens:about");
}

bool idaapi run(size_t) {
    return true;
}