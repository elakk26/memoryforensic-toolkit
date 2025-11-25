#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <string>
#include <vector>
#include <yara.h>

class RuleLoader {
private:
    YR_COMPILER* compiler;
    YR_RULES* rules;
    std::vector<std::string> ruleFiles;
    std::string rulesDirectory;
    
public:
    RuleLoader(const std::string& rulesDir = "rules/");
    ~RuleLoader();
    
    bool loadRules();
    bool loadRuleFile(const std::string& filepath);
    bool reloadRules();
    YR_RULES* getRules();
    std::vector<std::string> listLoadedRules();
    int getRuleCount();
};

#endif