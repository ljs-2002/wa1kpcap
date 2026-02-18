#pragma once

#include "field_value.h"
#include <string>
#include <memory>
#include <vector>

// ── Compiled expression AST ──
// Built once at YAML load time, evaluated many times at parse time.

struct ExprNode {
    enum class Kind { LITERAL, FIELD_REF, ADD, SUB, MUL, DIV, NEG };
    Kind kind;
    int64_t literal_val = 0;       // LITERAL
    std::string field_name;         // FIELD_REF
    std::unique_ptr<ExprNode> left;  // binary ops, NEG
    std::unique_ptr<ExprNode> right; // binary ops
};

// Precompiled expression: compile once, evaluate many times.
class CompiledExpression {
public:
    // Compile expression string into AST
    static CompiledExpression compile(const std::string& expr);

    // Evaluate compiled AST against parsed fields — no string parsing at runtime
    int64_t evaluate(const FieldMap& fields) const;

    // Check if this expression is valid (has a root node)
    bool valid() const { return root_ != nullptr; }

private:
    std::unique_ptr<ExprNode> root_;

    static int64_t eval_node(const ExprNode& node, const FieldMap& fields);
};

// Legacy API: parse + evaluate in one shot (for backward compat)
class ExpressionEval {
public:
    static int64_t evaluate(const std::string& expr, const FieldMap& fields);

private:
    ExpressionEval(const std::string& expr, const FieldMap& fields);

    int64_t parse_expr();
    int64_t parse_term();
    int64_t parse_unary();
    int64_t parse_primary();

    char peek() const;
    char consume();
    void skip_ws();
    bool at_end() const;

    const std::string& expr_;
    const FieldMap& fields_;
    size_t pos_ = 0;
};
