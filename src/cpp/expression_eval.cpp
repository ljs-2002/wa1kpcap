#include "expression_eval.h"
#include <stdexcept>
#include <cctype>

// ═══════════════════════════════════════════════════════════
// CompiledExpression: compile once at YAML load, evaluate many times
// ═══════════════════════════════════════════════════════════

namespace {

// Compile-time parser: builds AST from expression string
class ExprCompiler {
public:
    ExprCompiler(const std::string& expr) : expr_(expr), pos_(0) {}

    std::unique_ptr<ExprNode> compile() {
        skip_ws();
        auto node = parse_expr();
        skip_ws();
        if (!at_end()) {
            throw std::runtime_error("Unexpected character in expression: " + expr_);
        }
        return node;
    }

private:
    std::unique_ptr<ExprNode> parse_expr() {
        auto left = parse_term();
        skip_ws();
        while (!at_end() && (peek() == '+' || peek() == '-')) {
            char op = consume();
            skip_ws();
            auto right = parse_term();
            skip_ws();
            auto node = std::make_unique<ExprNode>();
            node->kind = (op == '+') ? ExprNode::Kind::ADD : ExprNode::Kind::SUB;
            node->left = std::move(left);
            node->right = std::move(right);
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<ExprNode> parse_term() {
        auto left = parse_unary();
        skip_ws();
        while (!at_end() && (peek() == '*' || peek() == '/')) {
            char op = consume();
            skip_ws();
            auto right = parse_unary();
            skip_ws();
            auto node = std::make_unique<ExprNode>();
            node->kind = (op == '*') ? ExprNode::Kind::MUL : ExprNode::Kind::DIV;
            node->left = std::move(left);
            node->right = std::move(right);
            left = std::move(node);
        }
        return left;
    }

    std::unique_ptr<ExprNode> parse_unary() {
        skip_ws();
        if (!at_end() && peek() == '-') {
            consume();
            skip_ws();
            auto node = std::make_unique<ExprNode>();
            node->kind = ExprNode::Kind::NEG;
            node->left = parse_unary();
            return node;
        }
        return parse_primary();
    }

    std::unique_ptr<ExprNode> parse_primary() {
        skip_ws();
        if (at_end()) throw std::runtime_error("Unexpected end of expression");

        char c = peek();

        if (c == '(') {
            consume();
            skip_ws();
            auto node = parse_expr();
            skip_ws();
            if (at_end() || peek() != ')') {
                throw std::runtime_error("Missing closing parenthesis");
            }
            consume();
            return node;
        }

        if (std::isdigit(c)) {
            size_t start = pos_;
            while (!at_end() && std::isdigit(peek())) consume();
            auto node = std::make_unique<ExprNode>();
            node->kind = ExprNode::Kind::LITERAL;
            node->literal_val = std::stoll(expr_.substr(start, pos_ - start));
            return node;
        }

        if (std::isalpha(c) || c == '_') {
            size_t start = pos_;
            while (!at_end() && (std::isalnum(peek()) || peek() == '_')) consume();
            auto node = std::make_unique<ExprNode>();
            node->kind = ExprNode::Kind::FIELD_REF;
            node->field_name = expr_.substr(start, pos_ - start);
            return node;
        }

        throw std::runtime_error(std::string("Unexpected character in expression: ") + c);
    }

    char peek() const { return expr_[pos_]; }
    char consume() { return expr_[pos_++]; }
    void skip_ws() { while (pos_ < expr_.size() && std::isspace(expr_[pos_])) ++pos_; }
    bool at_end() const { return pos_ >= expr_.size(); }

    const std::string& expr_;
    size_t pos_;
};

} // anonymous namespace

CompiledExpression CompiledExpression::compile(const std::string& expr) {
    CompiledExpression ce;
    ExprCompiler compiler(expr);
    ce.root_ = compiler.compile();
    return ce;
}

int64_t CompiledExpression::evaluate(const FieldMap& fields) const {
    if (!root_) return 0;
    return eval_node(*root_, fields);
}

int64_t CompiledExpression::eval_node(const ExprNode& node, const FieldMap& fields) {
    switch (node.kind) {
    case ExprNode::Kind::LITERAL:
        return node.literal_val;
    case ExprNode::Kind::FIELD_REF: {
        auto it = fields.find(node.field_name);
        if (it == fields.end()) return 0;
        return field_to_int(it->second);
    }
    case ExprNode::Kind::ADD:
        return eval_node(*node.left, fields) + eval_node(*node.right, fields);
    case ExprNode::Kind::SUB:
        return eval_node(*node.left, fields) - eval_node(*node.right, fields);
    case ExprNode::Kind::MUL:
        return eval_node(*node.left, fields) * eval_node(*node.right, fields);
    case ExprNode::Kind::DIV: {
        int64_t r = eval_node(*node.right, fields);
        if (r == 0) return 0;
        return eval_node(*node.left, fields) / r;
    }
    case ExprNode::Kind::NEG:
        return -eval_node(*node.left, fields);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════
// Legacy ExpressionEval (kept for backward compat)
// ═══════════════════════════════════════════════════════════

ExpressionEval::ExpressionEval(const std::string& expr, const FieldMap& fields)
    : expr_(expr), fields_(fields) {}

int64_t ExpressionEval::evaluate(const std::string& expr, const FieldMap& fields) {
    ExpressionEval ev(expr, fields);
    ev.skip_ws();
    int64_t result = ev.parse_expr();
    ev.skip_ws();
    if (!ev.at_end()) {
        throw std::runtime_error("Unexpected character in expression: " + expr);
    }
    return result;
}

int64_t ExpressionEval::parse_expr() {
    int64_t left = parse_term();
    skip_ws();
    while (!at_end() && (peek() == '+' || peek() == '-')) {
        char op = consume();
        skip_ws();
        int64_t right = parse_term();
        skip_ws();
        if (op == '+') left += right;
        else left -= right;
    }
    return left;
}

int64_t ExpressionEval::parse_term() {
    int64_t left = parse_unary();
    skip_ws();
    while (!at_end() && (peek() == '*' || peek() == '/')) {
        char op = consume();
        skip_ws();
        int64_t right = parse_unary();
        skip_ws();
        if (op == '*') left *= right;
        else {
            if (right == 0) throw std::runtime_error("Division by zero in expression");
            left /= right;
        }
    }
    return left;
}

int64_t ExpressionEval::parse_unary() {
    skip_ws();
    if (!at_end() && peek() == '-') {
        consume();
        skip_ws();
        return -parse_unary();
    }
    return parse_primary();
}

int64_t ExpressionEval::parse_primary() {
    skip_ws();
    if (at_end()) throw std::runtime_error("Unexpected end of expression");

    char c = peek();

    if (c == '(') {
        consume();
        skip_ws();
        int64_t val = parse_expr();
        skip_ws();
        if (at_end() || peek() != ')') {
            throw std::runtime_error("Missing closing parenthesis");
        }
        consume();
        return val;
    }

    if (std::isdigit(c)) {
        size_t start = pos_;
        while (!at_end() && std::isdigit(peek())) consume();
        return std::stoll(expr_.substr(start, pos_ - start));
    }

    if (std::isalpha(c) || c == '_') {
        size_t start = pos_;
        while (!at_end() && (std::isalnum(peek()) || peek() == '_')) consume();
        std::string field_name = expr_.substr(start, pos_ - start);

        auto it = fields_.find(field_name);
        if (it == fields_.end()) {
            throw std::runtime_error("Unknown field in expression: " + field_name);
        }
        return field_to_int(it->second);
    }

    throw std::runtime_error(std::string("Unexpected character in expression: ") + c);
}

char ExpressionEval::peek() const {
    return expr_[pos_];
}

char ExpressionEval::consume() {
    return expr_[pos_++];
}

void ExpressionEval::skip_ws() {
    while (pos_ < expr_.size() && std::isspace(expr_[pos_])) ++pos_;
}

bool ExpressionEval::at_end() const {
    return pos_ >= expr_.size();
}
