#include "../include/rule_loader.hpp"
#include "../include/Logger.hpp"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

RuleLoader::RuleLoader(const std::string& rulesDir) 
    : compiler(nullptr), rules(nullptr), rulesDirectory(rulesDir) {
    yr_initialize();
}

RuleLoader::~RuleLoader() {
    if (rules) yr_rules_destroy(rules);
    if (compiler) yr_compiler_destroy(compiler);
    yr_finalize();
}

bool RuleLoader::loadRuleFile(const std::string& filepath) {
    FILE* file = fopen(filepath.c_str(), "r");
    if (!file) {
        Logger::getInstance()->error("Failed to open rule file: " + filepath);
        return false;
    }
    
    int errors = yr_compiler_add_file(compiler, file, nullptr, filepath.c_str());
    fclose(file);
    
    if (errors > 0) {
        Logger::getInstance()->error("Errors compiling rules in: " + filepath);
        return false;
    }
    
    Logger::getInstance()->info("Loaded YARA rules from: " + filepath);
    return true;
}

bool RuleLoader::loadRules() {
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        Logger::getInstance()->error("Failed to create YARA compiler");
        return false;
    }
    
    ruleFiles.clear();
    
    try {
        for (const auto& entry : fs::directory_iterator(rulesDirectory)) {
            if (entry.path().extension() == ".yar") {
                std::string filepath = entry.path().string();
                if (loadRuleFile(filepath)) {
                    ruleFiles.push_back(filepath);
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::getInstance()->error("Error scanning rules directory: " + std::string(e.what()));
        return false;
    }
    
    if (ruleFiles.empty()) {
        Logger::getInstance()->warning("No YARA rules loaded");
        return false;
    }
    
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        Logger::getInstance()->error("Failed to compile YARA rules");
        return false;
    }
    
    Logger::getInstance()->info("Successfully loaded " + std::to_string(ruleFiles.size()) + " rule files");
    return true;
}

bool RuleLoader::reloadRules() {
    if (rules) {
        yr_rules_destroy(rules);
        rules = nullptr;
    }
    if (compiler) {
        yr_compiler_destroy(compiler);
        compiler = nullptr;
    }
    
    Logger::getInstance()->info("Reloading YARA rules...");
    return loadRules();
}

YR_RULES* RuleLoader::getRules() {
    return rules;
}

std::vector<std::string> RuleLoader::listLoadedRules() {
    return ruleFiles;
}

int RuleLoader::getRuleCount() {
    return ruleFiles.size();
}