
#ifndef PARSER_H
#define PARSER_H

#include <memory>

enum Token
{
    TOK_TOP = 0,
    
    TOK_COMMENT = 0x100,
    TOK_IF,
    TOK_AND,
    TOK_OR,
    TOK_ELSE,
    TOK_ENDIF,
    TOK_ACCEPT,
    TOK_REJECT,
    TOK_ADDPUBKEY,
    TOK_SAY,
    TOK_YELL,
    TOK_SETENV,

    TOK_ENV = 0x200,
    TOK_DATE,
    TOK_NPROC,
    TOK_MAC,
    TOK_HOSTID,
    TOK_MACHINEID,
    TOK_HOSTNAME,
    TOK_AWS,
    TOK_SCALEWAY,
    TOK_GITHUB_REPO,
    TOK_GITHUB_OWNER,
    TOK_NOT,
    TOK_VERSION,

    TOK_NZ = 0x400,
    TOK_BEFORE,
    TOK_MAX,

    TOK_PARAMETER = 0x800
};

enum ParameterType
{
    PARAM_STRING = 0,
    PARAM_UNSIGNED_INT,
    PARAM_DATE,
    PARAM_MAC_ADDRESS,
    PARAM_HEX_STRING
};

enum SyntaxError
{
    SERR_PARAMETER_MISSING = 0,
    SERR_EXPECTING_PARAMETER,
    SERR_EXTRA_KEYWORDS,
    SERR_TEST_MISSING,
    SERR_AND_WITHOUT_IF,
    SERR_OR_WITHOUT_IF,
    SERR_ELSE_WITHOUT_IF,
    SERR_ENDIF_WITHOUT_IF,
    SERR_IF_WITHOUT_ENDIF,
    SERR_AND_AFTER_OR_OR_ELSE,
    SERR_OR_AFTER_AND_OR_ELSE,
    SERR_CONDITION_MISSING,
    SERR_INVALID_CONDITION,
    SERR_NOT_UNSIGNED_INTEGER,
    SERR_NOT_DATE,
    SERR_NOT_MAC_ADDRESS,
    SERR_NOT_HEX_STRING
};

class Statement {
protected:
    Statement(Token token, int lineno);
public:
    virtual ~Statement();

    virtual bool isCommand() { return false; }
    virtual bool isTest() { return false; }
    virtual bool isParameter() { return false; }
    virtual bool isCondition() { return false; }

    Token getToken() { return _token; }
    int getLineNo() { return _lineno; }

    std::vector<std::unique_ptr<Statement>>& getStatements() { return statements; }
protected:
    Token _token;
    int _lineno;
    std::vector<std::unique_ptr<Statement>> statements;
};

std::unique_ptr<Statement> parse_rules(std::istream &in, bool isSigned, int &lineno, Statement *appendtop = nullptr);
std::vector<std::pair<std::string,bool>> split_content(std::istream &in);
std::unique_ptr<Statement> parse_rules(std::istream &in);
void syntax_check(Statement *top);
bool execute_script(Statement *top, bool verbose = false);
void display_info_and_check(std::istream &in);
void check_rules(std::istream &in, bool verbose);

class exception_closing_quotes : public std::exception {
public:
    exception_closing_quotes( int lineno ) { msg = "Line " + std::to_string(lineno) + " : Closing quotes missing";};
private:
	const char * what () const throw () { return msg.c_str(); }
    std::string msg;
};

class exception_unknown_condition : public std::exception {
public:
    exception_unknown_condition( std::string what_arg, int lineno ) { msg = "Line " + std::to_string(lineno) + " : Unknown condition '" + what_arg + "'";};
private:
	const char * what () const throw () { return msg.c_str(); }
    std::string msg;
};

class exception_unknown_command : public std::exception {
public:
    exception_unknown_command( std::string what_arg, int lineno ) { msg = "Line " + std::to_string(lineno) + " : Unknown command '" + what_arg + "'";};
private:
	const char * what () const throw () { return msg.c_str(); }
    std::string msg;
};

class exception_command_notallowed : public std::exception {
public:
    exception_command_notallowed( std::string what_arg, int lineno ) { msg = "Line " + std::to_string(lineno) + " : Command '" + what_arg + "' not allowed in unsigned block";};
private:
	const char * what () const throw () { return msg.c_str(); }
    std::string msg;
};


class exception_syntax_error : public std::exception {
public:    
    exception_syntax_error(SyntaxError err, int lineno);
	const char * what () const throw () { return msg.c_str(); }
    SyntaxError code() const { return _err; }
    static const char * translate(SyntaxError err);
private:
    SyntaxError _err;
    int lineno;
    std::string msg;
};

#endif
