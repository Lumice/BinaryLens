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
    if (strcmp(action_name, "set_model") == 0) {
        qstring cur_val;
        std::string existing;
        if (ReadRegistryData(sub_key, "model_to_use", existing)) {
            cur_val = existing.c_str();
        }
        bool ok = ask_str(&cur_val, 0, "Enter Model Identifier (any model supported by your OpenAI-compatible endpoint):");
        if (ok && !cur_val.empty()) {
            std::string s = cur_val.c_str();
            TrimStr(s);
            WriteRegistryData(sub_key, "model_to_use", s.c_str());
            info("BinaryLens: Active model set to '%s'\n", s.c_str());
        }
        return true;
    }
    if (strcmp(action_name, "set_base_url") == 0) {
        qstring cur_val;
        std::string existing;
        if (ReadRegistryData(sub_key, "custom_base_url", existing)) {
            cur_val = existing.c_str();
        }
        else {
            cur_val = "http://localhost:11434/v1";
        }
        bool ok = ask_str(&cur_val, 0, "Enter API Base URL (e.g. http://localhost:11434/v1, https://api.openai.com/v1):");
        if (ok) {
            std::string s = cur_val.c_str();
            TrimStr(s);
            WriteRegistryData(sub_key, "custom_base_url", s.c_str());
            info("BinaryLens: Base URL set to '%s'\n", s.c_str());
        }
        return true;
    }
    // Presets
    if (strcmp(action_name, "preset_ollama") == 0) {
        WriteRegistryData(sub_key, "custom_base_url", "http://localhost:11434/v1");
        info("BinaryLens: Base URL set to Ollama (http://localhost:11434/v1)\n");
        return true;
    }
    if (strcmp(action_name, "preset_lmstudio") == 0) {
        WriteRegistryData(sub_key, "custom_base_url", "http://localhost:1234/v1");
        info("BinaryLens: Base URL set to LM Studio (http://localhost:1234/v1)\n");
        return true;
    }
    if (strcmp(action_name, "preset_openai") == 0) {
        WriteRegistryData(sub_key, "custom_base_url", "https://api.openai.com/v1");
        info("BinaryLens: Base URL set to OpenAI (https://api.openai.com/v1)\n");
        return true;
    }
    if (strcmp(action_name, "preset_gemini") == 0) {
        WriteRegistryData(sub_key, "custom_base_url", "https://generativelanguage.googleapis.com/v1beta/openai");
        info("BinaryLens: Base URL set to Google Gemini\n");
        return true;
    }
    if (strcmp(action_name, "preset_deepseek") == 0) {
        WriteRegistryData(sub_key, "custom_base_url", "https://api.deepseek.com/v1");
        info("BinaryLens: Base URL set to DeepSeek\n");
        return true;
    }
    if (strcmp(action_name, "preset_openrouter") == 0) {
        WriteRegistryData(sub_key, "custom_base_url", "https://openrouter.ai/api/v1");
        info("BinaryLens: Base URL set to OpenRouter\n");
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
    if (ReadRegistryData(sub_key, "api_key", existing) ||
        ReadRegistryData(sub_key, "openai_api_key", existing)) {
        key = existing.c_str();
    }
    bool input = ask_str(&key, 0, "Enter API Key (optional for local Ollama/LM Studio):");

    std::string key_str = key.c_str();
    if (!input)
        return true;

    TrimStr(key_str);
    WriteRegistryData(sub_key, "api_key", key_str.c_str());
    WriteRegistryData(sub_key, "openai_api_key", key_str.c_str());
    WriteRegistryData(sub_key, "gemini_api_key", key_str.c_str());
    WriteRegistryData(sub_key, "deepseek_api_key", key_str.c_str());
    WriteRegistryData(sub_key, "custom_api_key", key_str.c_str());
    info("BinaryLens: API key saved.\n");

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

const action_desc_t set_model_action = ACTION_DESC_LITERAL(
    "BinaryLens:set_model",
    "Set Model Name...",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t set_base_url_action = ACTION_DESC_LITERAL(
    "BinaryLens:set_base_url",
    "Set API Base URL...",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t set_api_key_action = ACTION_DESC_LITERAL(
    "BinaryLens:set_api_key",
    "Set API Key...",
    &api_key_handler,
    nullptr,
    nullptr,
    -1
);

// Presets
const action_desc_t preset_ollama_action = ACTION_DESC_LITERAL(
    "BinaryLens:preset_ollama",
    "Ollama (http://localhost:11434/v1)",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t preset_lmstudio_action = ACTION_DESC_LITERAL(
    "BinaryLens:preset_lmstudio",
    "LM Studio (http://localhost:1234/v1)",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t preset_openai_action = ACTION_DESC_LITERAL(
    "BinaryLens:preset_openai",
    "OpenAI (https://api.openai.com/v1)",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t preset_gemini_action = ACTION_DESC_LITERAL(
    "BinaryLens:preset_gemini",
    "Google Gemini",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t preset_deepseek_action = ACTION_DESC_LITERAL(
    "BinaryLens:preset_deepseek",
    "DeepSeek",
    &model_handler,
    nullptr,
    nullptr,
    -1
);

const action_desc_t preset_openrouter_action = ACTION_DESC_LITERAL(
    "BinaryLens:preset_openrouter",
    "OpenRouter",
    &model_handler,
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

    if (!register_action(rename_subs_action)       ||
        !register_action(rename_vars_action)       ||
        !register_action(about_action)             ||
        !register_action(set_model_action)         ||
        !register_action(set_base_url_action)      ||
        !register_action(set_api_key_action)       ||
        !register_action(preset_ollama_action)     ||
        !register_action(preset_lmstudio_action)   ||
        !register_action(preset_openai_action)     ||
        !register_action(preset_gemini_action)     ||
        !register_action(preset_deepseek_action)   ||
        !register_action(preset_openrouter_action)) {

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

    // Configuration
    attach_action_to_menu("Edit/" ACTION_NAME "/Configuration/", "BinaryLens:set_model", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Configuration/", "BinaryLens:set_base_url", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Configuration/", "BinaryLens:set_api_key", SETMENU_APP);

    // Presets
    attach_action_to_menu("Edit/" ACTION_NAME "/Base URL Presets/", "BinaryLens:preset_ollama", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Base URL Presets/", "BinaryLens:preset_lmstudio", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Base URL Presets/", "BinaryLens:preset_openai", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Base URL Presets/", "BinaryLens:preset_gemini", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Base URL Presets/", "BinaryLens:preset_deepseek", SETMENU_APP);
    attach_action_to_menu("Edit/" ACTION_NAME "/Base URL Presets/", "BinaryLens:preset_openrouter", SETMENU_APP);

    attach_action_to_menu("Edit/" ACTION_NAME "/", "BinaryLens:about", SETMENU_APP);

    // Hook for popup menus
    hook_to_notification_point(HT_UI, WidgetPopupCallback, nullptr);

    return PLUGIN_KEEP;
}

void idaapi term() {
    unhook_from_notification_point(HT_UI, WidgetPopupCallback, nullptr);

    unregister_action("BinaryLens:rename_subs");
    unregister_action("BinaryLens:rename_vars");
    unregister_action("BinaryLens:set_model");
    unregister_action("BinaryLens:set_base_url");
    unregister_action("BinaryLens:set_api_key");
    unregister_action("BinaryLens:preset_ollama");
    unregister_action("BinaryLens:preset_lmstudio");
    unregister_action("BinaryLens:preset_openai");
    unregister_action("BinaryLens:preset_gemini");
    unregister_action("BinaryLens:preset_deepseek");
    unregister_action("BinaryLens:preset_openrouter");
    unregister_action("BinaryLens:about");
}

bool idaapi run(size_t) {
    return true;
}