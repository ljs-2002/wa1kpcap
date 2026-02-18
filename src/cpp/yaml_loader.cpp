#include "yaml_loader.h"
#include "expression_eval.h"

#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <stdexcept>
#include <algorithm>

namespace fs = std::filesystem;

static PrimitiveType parse_primitive_type(const std::string& s) {
    if (s == "fixed")           return PrimitiveType::FIXED;
    if (s == "bitfield")        return PrimitiveType::BITFIELD;
    if (s == "length_prefixed") return PrimitiveType::LENGTH_PREFIXED;
    if (s == "computed")        return PrimitiveType::COMPUTED;
    if (s == "tlv")             return PrimitiveType::TLV;
    if (s == "counted_list")    return PrimitiveType::COUNTED_LIST;
    if (s == "rest")            return PrimitiveType::REST;
    if (s == "hardcoded")       return PrimitiveType::HARDCODED;
    if (s == "prefixed_list")   return PrimitiveType::PREFIXED_LIST;
    if (s == "repeat")          return PrimitiveType::REPEAT;
    throw std::runtime_error("Unknown primitive type: " + s);
}

static FieldDef parse_field(const YAML::Node& node) {
    FieldDef f;
    f.name = node["name"].as<std::string>();
    f.type = parse_primitive_type(node["type"].as<std::string>());

    switch (f.type) {
    case PrimitiveType::FIXED:
        f.size = node["size"].as<int>();
        if (node["endian"]) f.endian = node["endian"].as<std::string>();
        if (node["format"]) f.format = node["format"].as<std::string>();
        else f.format = "uint";
        break;

    case PrimitiveType::BITFIELD:
        f.group_size = node["group_size"].as<int>();
        for (auto& bf : node["fields"]) {
            FieldDef::BitFieldEntry e;
            e.name = bf["name"].as<std::string>();
            e.bits = bf["bits"].as<int>();
            f.bit_fields.push_back(std::move(e));
        }
        break;

    case PrimitiveType::LENGTH_PREFIXED:
        f.length_size = node["length_size"].as<int>();
        if (node["sub_protocol"]) f.sub_protocol = node["sub_protocol"].as<std::string>();
        if (node["format"]) f.format = node["format"].as<std::string>();
        break;

    case PrimitiveType::COMPUTED:
        f.expression = node["expression"].as<std::string>();
        f.compiled_expr = std::make_shared<CompiledExpression>(
            CompiledExpression::compile(f.expression));
        break;

    case PrimitiveType::TLV:
        f.type_size = node["type_size"].as<int>();
        f.tlv_length_size = node["length_size"].as<int>();
        if (node["type_mapping"]) {
            for (auto it = node["type_mapping"].begin(); it != node["type_mapping"].end(); ++it) {
                f.type_mapping[it->first.as<int>()] = it->second.as<std::string>();
            }
        }
        break;

    case PrimitiveType::COUNTED_LIST:
        f.count_field = node["count_field"].as<std::string>();
        if (node["item_protocol"]) f.item_protocol = node["item_protocol"].as<std::string>();
        if (node["size"]) f.size = node["size"].as<int>();
        if (node["format"]) f.format = node["format"].as<std::string>();
        break;

    case PrimitiveType::REST:
        if (node["format"]) f.format = node["format"].as<std::string>();
        else f.format = "bytes";
        break;

    case PrimitiveType::HARDCODED:
        f.parser_name = node["parser"].as<std::string>();
        break;

    case PrimitiveType::PREFIXED_LIST:
        f.list_length_size = node["list_length_size"].as<int>();
        if (node["item_length_size"]) f.item_length_size = node["item_length_size"].as<int>();
        if (node["item_format"]) f.item_format = node["item_format"].as<std::string>();
        else f.item_format = "string";
        // TLV mode: optional type_size + type_mapping for sub-protocol dispatch
        if (node["type_size"]) f.type_size = node["type_size"].as<int>();
        if (node["type_mapping"]) {
            for (auto it = node["type_mapping"].begin(); it != node["type_mapping"].end(); ++it) {
                f.type_mapping[it->first.as<int>()] = it->second.as<std::string>();
            }
        }
        break;

    case PrimitiveType::REPEAT:
        f.sub_protocol = node["sub_protocol"].as<std::string>();
        if (node["merge"]) f.merge_mode = node["merge"].as<std::string>();
        break;
    }

    return f;
}

static ProtocolDefinition parse_protocol(const YAML::Node& root) {
    ProtocolDefinition proto;
    proto.name = root["name"].as<std::string>();

    if (root["fields"]) {
        for (auto& fnode : root["fields"]) {
            proto.fields.push_back(parse_field(fnode));
        }
    }

    if (root["header_size_field"]) {
        proto.header_size_field = root["header_size_field"].as<std::string>();
    }

    if (root["total_length_field"]) {
        proto.total_length_field = root["total_length_field"].as<std::string>();
    }

    if (root["next_protocol"]) {
        NextProtocol np;
        auto& npn = root["next_protocol"];
        // field is optional (pure heuristic protocols may not have it)
        if (npn["field"]) {
            if (npn["field"].IsSequence()) {
                for (const auto& f : npn["field"]) {
                    np.fields.push_back(f.as<std::string>());
                }
            } else {
                np.fields.push_back(npn["field"].as<std::string>());
            }
        }
        if (npn["mapping"]) {
            for (auto it = npn["mapping"].begin(); it != npn["mapping"].end(); ++it) {
                np.mapping[it->first.as<int>()] = it->second.as<std::string>();
            }
        }
        if (npn["default"]) np.default_protocol = npn["default"].as<std::string>();

        // Parse heuristics rules
        if (npn["heuristics"]) {
            for (const auto& rule_node : npn["heuristics"]) {
                HeuristicRule rule;
                rule.protocol = rule_node["protocol"].as<std::string>();
                if (rule_node["min_length"]) {
                    rule.min_length = rule_node["min_length"].as<size_t>();
                }
                if (rule_node["conditions"]) {
                    for (const auto& cond_node : rule_node["conditions"]) {
                        HeuristicCondition cond;
                        if (cond_node["offset"]) {
                            cond.offset = cond_node["offset"].as<size_t>();
                        }
                        if (cond_node["byte_eq"]) {
                            cond.type = HeuristicCondition::Type::BYTE_EQ;
                            cond.byte_eq_value = cond_node["byte_eq"].as<int>();
                        } else if (cond_node["byte_le"]) {
                            cond.type = HeuristicCondition::Type::BYTE_LE;
                            cond.byte_le_value = cond_node["byte_le"].as<int>();
                        } else if (cond_node["byte_in"]) {
                            cond.type = HeuristicCondition::Type::BYTE_IN;
                            for (const auto& v : cond_node["byte_in"]) {
                                cond.byte_in_set.push_back(static_cast<uint8_t>(v.as<int>()));
                            }
                        } else if (cond_node["prefix_in"]) {
                            cond.type = HeuristicCondition::Type::PREFIX_IN;
                            for (const auto& v : cond_node["prefix_in"]) {
                                cond.prefix_in.push_back(v.as<std::string>());
                            }
                        }
                        rule.conditions.push_back(std::move(cond));
                    }
                }
                np.heuristics.push_back(std::move(rule));
            }
        }

        proto.next_protocol = std::move(np);
    }

    return proto;
}

static LinkTypeConfig parse_link_types(const YAML::Node& root) {
    LinkTypeConfig cfg;
    if (root["link_types"]) {
        for (auto it = root["link_types"].begin(); it != root["link_types"].end(); ++it) {
            cfg.dlt_to_protocol[it->first.as<int>()] = it->second.as<std::string>();
        }
    }
    return cfg;
}

void YamlLoader::load_file(const std::string& file_path) {
    YAML::Node root = YAML::LoadFile(file_path);

    std::string filename = fs::path(file_path).stem().string();

    if (filename == "link_types") {
        link_types_ = parse_link_types(root);
    } else {
        auto proto = parse_protocol(root);
        protocols_[proto.name] = std::move(proto);
    }
}

void YamlLoader::load_directory(const std::string& dir_path) {
    if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
        throw std::runtime_error("Protocol directory not found: " + dir_path);
    }

    // Collect and sort files for deterministic load order
    std::vector<std::string> files;
    for (auto& entry : fs::directory_iterator(dir_path)) {
        if (entry.path().extension() == ".yaml" || entry.path().extension() == ".yml") {
            files.push_back(entry.path().string());
        }
    }
    std::sort(files.begin(), files.end());

    // Load link_types first if present
    for (auto& f : files) {
        if (fs::path(f).stem().string() == "link_types") {
            load_file(f);
            break;
        }
    }

    // Load all protocol files
    for (auto& f : files) {
        if (fs::path(f).stem().string() != "link_types") {
            load_file(f);
        }
    }
}

const ProtocolDefinition* YamlLoader::get_protocol(const std::string& name) const {
    auto it = protocols_.find(name);
    return (it != protocols_.end()) ? &it->second : nullptr;
}
