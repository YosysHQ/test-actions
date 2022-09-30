#include <thread>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <stack>
#include <string>
#include <fstream>
#include <regex>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "parser.h"
#include "checks.h"
#include "OpenPGP.h"

#if __MINGW32__
#include <time.h>
#include <iomanip>

char* strptime(const char* s,const char* f,struct tm* tm)
{
	std::istringstream input(s);
	input.imbue(std::locale(setlocale(LC_ALL, nullptr)));
	input >> std::get_time(tm, f);
	if (input.fail()) {
		return nullptr;
	}
	return (char*)(s + input.tellg());
}
#endif

Statement::Statement(Token token, int lineno) :
    _token(token),
    _lineno(lineno)
{
};

Statement::~Statement()
{
};

class TopStatement : public Statement {
public:
    TopStatement() : Statement(TOK_TOP, 0) {};
};

class Command : public Statement {
public:
    Command(Token token, int lineno, std::string line) : Statement(token, lineno), text(line) {};
    bool isCommand() override { return true; }
    std::string getLineText() { return text; }
private:
    std::string text;
};

class Test : public Statement {
public:
    Test(Token token, int lineno) : Statement(token, lineno) {};
    bool isTest() override { return true; }
};

class Parameter : public Statement {
public:
    Parameter(std::string value, int lineno) : Statement(TOK_PARAMETER, lineno), param(value) {};
    bool isParameter() override { return true; }
    std::string& getParam() { return param; }
private:
    std::string param;
};

class Condition : public Statement {
public:
    Condition(Token token, int lineno) : Statement(token, lineno) {};
    bool isCondition() override { return true; }
    Token getConditionType() { return _token; }
    std::string& getConditionValue() { return value; }
private:
    std::string value;
};

const char* err_messages[] {
    "Parameter is missing", //SERR_PARAMETER_MISSING = 0,
    "Expecting parameter but found test", // SERR_EXPECTING_PARAMETER,
    "Extra keywords found in line", // SERR_EXTRA_KEYWORDS,
    "Test is missing", //SERR_TEST_MISSING,
    "Keyword 'and' without 'if'", //SERR_AND_WITHOUT_IF,
    "Keyword 'or' without 'if'", //SERR_OR_WITHOUT_IF,
    "Keyword 'else' without 'if'", //SERR_ELSE_WITHOUT_IF,
    "Keyword 'endif' without 'if'", //SERR_ENDIF_WITHOUT_IF,
    "If condition not closed", //SERR_IF_WITHOUT_ENDIF,
    "Keyword 'and' used after 'or' or 'else", //SERR_AND_AFTER_OR_OR_ELSE,
    "Keyword 'or' used after 'and' or 'else",  //SERR_OR_AFTER_AND_OR_ELSE,
    "Condition is missing", // SERR_CONDITION_MISSING,
    "Invalid condition used for test", // SERR_INVALID_CONDITION,
    "Unisgned integer expected", // SERR_NOT_UNSIGNED_INTEGER,
    "Date expected in YYYY-MM-DD format", // SERR_NOT_DATE
    "MAC address expected", // SERR_NOT_MAC_ADDRESS
    "Provided parameter is not hex string" // SERR_NOT_HEX_STRING
};

const char * exception_syntax_error::translate(SyntaxError err)
{
    return err_messages[err];
}

exception_syntax_error::exception_syntax_error(SyntaxError err, int lineno):
     _err(err),
     std::exception()
{
    msg = "Line ";
    msg += std::to_string(lineno);
    msg += " : ";
    msg += err_messages[_err];
}

/*

    License File Format Definition
    ==============================
    
    Sequence of PGP signed messages (RFC 4880)
    Payload is line based
    Whitespaces at begin/end of line ignored
    Lines starting with “#” are comments

    The license file may also contain commands before the first signed message. 
    But the commands "accept" and "addpubkey" are only allowed in signed blocks.

    Commands
    ========
    With the exception of if-...-endif all commands are single line

    if-[and../or..]-[else]-endif
    ----------------------------
    Executes one or more tests and runs the commands before else/endif if all tests succeed, 
    and the (optional) commands after else otherwise.

        if <test>
        [and/or <test>]
            <commands>
        [else]
            <commands>
        [endif]

    It’s not possible to mix and and or in an if-statement.

    accept
    ------
    Stop interpreting the license and accept the license. Can have an optional test as argument, 
    in which case we only stop and accept if the test succeeds.

        accept <test>

    reject
    ------
    Stop interpreting the license and reject the license with the given message.

        reject "<message>"

    There’s an implicit reject and the end of the input.

    addpubkey
    ---------
    Add the given public key to the list of accepted public keys.

        addpubkey "<keydata>"

    say
    ---
    Print the arguments to the log/console.

        say "<message>"

    yell
    ----
    Print the arguments to stderr.

        yell "<message>"

    setenv
    ------
    Set the given environment variable to the given value.

        setenv <name> <value>

    Run unsetenv() if value is omitted.

    Tests
    =====

    env
    ---
    Tests environment variables.

        env -nz <name>

    Passes if the given variable is set and has a value different from "" and "0".

    date
    ----
    Tests the current date against a given date.

        date -before <YYYY-MM-DD>

    nproc
    -----
    Test the number of processes against a given threshold.

        nproc -max 32

    mac
    ---
    Test if the given MAC address is found on any of the network devices in the system.

        mac <MAC-Address>

    hostid
    ------
    Test if the given host id (in hex) matches the host id returned by ghethostid().

        hostid <hostid>

    machine-id
    ----------
    Test if the given machine id (in hex) matches the machine id in /etc/machine-id.

        machine-id <machine-id>

    hostname
    --------
    Test if the given hostname matches the string returned by gethostname().

        hostname <hostname>

    aws-instance
    ------------
    Test if the given aws instance ID matches the one returned via http://169.254.169.254/2018-09-24/meta-data/instance-id.

        aws-instance <instance-id>

    scaleway-instance
    -----------------
    Test if the given scaleway instance ID matches the one returned via http://169.254.42.42/conf.

        scaleway-instance <instance-id>

    not
    ---
    Run the given test and pass if it fails and fail if the test passes.

        not <test>

    version
    -------
    Tests the current product release date against a given date.

        version -before <YYYY-MM-DD>

*/

const std::unordered_map<std::string, Token> g_commands =
{
    { "if", TOK_IF },
    { "and", TOK_AND },
    { "or", TOK_OR },
    { "else", TOK_ELSE },
    { "endif", TOK_ENDIF },
    { "accept", TOK_ACCEPT },
    { "reject", TOK_REJECT },
    { "addpubkey", TOK_ADDPUBKEY },
    { "say", TOK_SAY },
    { "yell", TOK_YELL },
    { "setenv", TOK_SETENV }
};

const std::unordered_map<std::string, Token> g_conditions =
{
    { "-nz",     TOK_NZ },
    { "-before", TOK_BEFORE },
    { "-max",    TOK_MAX }
};

const std::unordered_map<std::string, Token> g_tests =
{
    { "env", TOK_ENV },
    { "date", TOK_DATE },
    { "nproc", TOK_NPROC },
    { "mac", TOK_MAC },
    { "hostid", TOK_HOSTID },
    { "machine-id", TOK_MACHINEID },
    { "hostname", TOK_HOSTNAME },
    { "aws-instance", TOK_AWS },
    { "scaleway-instance", TOK_SCALEWAY },
    { "github-repo", TOK_GITHUB_REPO },
    { "github-owner", TOK_GITHUB_OWNER },
    { "not",TOK_NOT },
    { "version",TOK_VERSION }
};

void parseParams(Statement *current, char **ptr, int lineno)
{
    while (*ptr)
    {
        while ((**ptr) && (**ptr == ' ')) {
            (*ptr)++;
        }
        if (*ptr[0] == '"') {
            std::string str;
            (*ptr)++;
            while (**ptr) {
                char c = **ptr;
                if (c == '"') {
                    (*ptr)++;
                    break;
                }
                str += c;
                (*ptr)++;
                if (!**ptr) {
                    throw exception_closing_quotes(lineno);
                }
		    }            
            current->getStatements().push_back(std::make_unique<Parameter>(str, lineno));
            continue;
        }
        
        char *tok = strtok_r(*ptr, " \t\r\n", ptr);

        if (tok==nullptr) return;

        if (tok[0] == '-') {
            auto search = g_conditions.find(tok);
            if (search != g_conditions.end()) {
                current->getStatements().push_back(std::make_unique<Condition>(search->second, lineno));
                continue;
            }
            else {
                throw exception_unknown_condition(tok, lineno);
            }
        }
        auto search = g_tests.find(tok);
        if (search != g_tests.end()) {
            current->getStatements().push_back(std::make_unique<Test>(search->second, lineno));
        } else {
            current->getStatements().push_back(std::make_unique<Parameter>(tok, lineno));
        }
    }
}

void parse(Statement *current, char **ptr, bool isSigned, int lineno)
{
    if (ptr==nullptr) return;
    std::string line(*ptr);
    if (*ptr[0] == '#') {
        current->getStatements().push_back(std::make_unique<Command>(TOK_COMMENT, lineno, line));
        return;
    }

    char *tok = strtok_r(*ptr, " \t\r\n", ptr);
    
    if (tok==nullptr) return;

    auto search = g_commands.find(tok);
    if (search != g_commands.end()) {
        if (!isSigned) {
            if (search->second==TOK_ACCEPT || search->second==TOK_ADDPUBKEY) {
                throw exception_command_notallowed(tok, lineno);
            }
        }
        current->getStatements().push_back(std::make_unique<Command>(search->second, lineno, line));
    } else {
        throw exception_unknown_command(tok, lineno);
    }
    parseParams(current->getStatements().back().get(), ptr, lineno);   
}

std::unique_ptr<Statement> parse_rules(std::istream &in, bool isSigned, int &lineno, Statement *appendtop)
{
    constexpr size_t line_buf_size = 65536;
    char buffer[line_buf_size];
    const char *tok;

    std::unique_ptr<Statement> top = std::make_unique<TopStatement>();
    Statement *current = top.get();
    if (appendtop!=nullptr)
        current = appendtop;
    while (1) {
        lineno++;
        in.getline(buffer, line_buf_size);
        // Trim right
        char *ptr = buffer + strlen(buffer) - 1;
        while ((ptr >= buffer) && (*ptr == ' ')) {
            *ptr = 0;
            ptr--;
        }
        // Trim left
        ptr = buffer;
        while ((*ptr != 0) && (*ptr == ' ')) {
            ptr++;
        }

        parse(current, &ptr, isSigned, lineno);

        if (in.eof())
            break;
    }
    return top;
}

void expectCondition(Statement *stm, std::vector<Token> tok)
{
    if (!stm->isCondition())
        throw exception_syntax_error(SERR_CONDITION_MISSING, stm->getLineNo());
    for(Token t : tok) {
        if (stm->getToken()==t) return;
    }
    throw exception_syntax_error(SERR_INVALID_CONDITION, stm->getLineNo());
}

void expectParameter(Statement *stm, ParameterType pt, int index = 0, int num = 1)
{
    if (stm->getStatements().size()<(index + num))
        throw exception_syntax_error(SERR_PARAMETER_MISSING, stm->getLineNo());
    else if (stm->getStatements().size()==(index + num)) {
        bool ok = true;
        for (int i = index; i<index + num; i++) {
            Statement *s = stm->getStatements().at(i).get();
            ok &= s->isParameter();
            if (s->isParameter()) {
                Parameter *p = static_cast<Parameter*>(s);
                switch(pt) {
                    case PARAM_STRING:
                        break;
                    case PARAM_UNSIGNED_INT: 
                        {
                            std::regex pattern("[[:digit:]]+");
                            if (!regex_match(p->getParam(),pattern))
                                throw exception_syntax_error(SERR_NOT_UNSIGNED_INTEGER, stm->getLineNo());
                        }
                        break;
                    case PARAM_DATE: 
                        {
                            std::regex pattern("\\b\\d{4}[-]\\d{2}[-]\\d{2}\\b");
                            if (!regex_match(p->getParam(),pattern))
                                throw exception_syntax_error(SERR_NOT_DATE, stm->getLineNo());
                        }
                        break;
                    case PARAM_MAC_ADDRESS:
                        {
                            std::regex pattern("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
                            if (!regex_match(p->getParam(),pattern))
                                throw exception_syntax_error(SERR_NOT_MAC_ADDRESS, stm->getLineNo());
                        }
                        break;
                    case PARAM_HEX_STRING:
                        {
                            std::regex pattern("^[A-Fa-f0-9]+$");
                            if (!regex_match(p->getParam(),pattern))
                                throw exception_syntax_error(SERR_NOT_HEX_STRING, stm->getLineNo());
                            if ((p->getParam().size() % 2) != 0)
                                throw exception_syntax_error(SERR_NOT_HEX_STRING, stm->getLineNo());
                        }
                        break;
                }
            }
        }
        if (ok)
            return;
        throw exception_syntax_error(SERR_EXPECTING_PARAMETER, stm->getLineNo());
    } else
        throw exception_syntax_error(SERR_EXTRA_KEYWORDS, stm->getLineNo());
}

void expectTest(Statement *stm, int index = 0, bool fail = true)
{
    if (stm->getStatements().size() > index) {
        if (stm->getStatements().at(index + 0)->isTest()) {
            switch(stm->getStatements().at(index + 0)->getToken()) {
                case TOK_ENV:
                    expectCondition(stm->getStatements().at(index + 1).get(), { TOK_NZ });
                    expectParameter(stm, PARAM_STRING, index + 2, 1);
                    return;
                case TOK_DATE:
                case TOK_VERSION:
                    expectCondition(stm->getStatements().at(index + 1).get(), { TOK_BEFORE });
                    expectParameter(stm, PARAM_DATE, index + 2, 1);
                    return;
                case TOK_NPROC:
                    expectCondition(stm->getStatements().at(index + 1).get(), { TOK_MAX });
                    expectParameter(stm, PARAM_UNSIGNED_INT, index + 2, 1);
                    return;

                case TOK_MAC:
                    expectParameter(stm, PARAM_MAC_ADDRESS, index + 1, 1);
                    return;
                case TOK_HOSTID:
                case TOK_MACHINEID:
                case TOK_HOSTNAME:
                case TOK_AWS:
                case TOK_SCALEWAY:
                case TOK_GITHUB_REPO:
                case TOK_GITHUB_OWNER:
                    expectParameter(stm, PARAM_STRING, index + 1, 1);
                    return;
                case TOK_NOT:
                    expectTest(stm, index+1);
                    return;
                default:
                    throw std::runtime_error("Unhandled test");
            }
        }
        throw exception_syntax_error(SERR_TEST_MISSING, stm->getLineNo());
    }
    if (fail)
        throw exception_syntax_error(SERR_TEST_MISSING, stm->getLineNo());
}

struct ifstate {
    ifstate() : is_and(false), is_or(false), is_else(false), value(false) { };
    bool is_and;
    bool is_or;
    bool is_else;
    bool value;
};

void expectCommand(Statement *stm, std::stack<ifstate> &state)
{
    switch(stm->getToken()) {
        case TOK_COMMENT:
            break;
        case TOK_IF:
            state.push(ifstate()); 
            expectTest(stm);
            break;
        case TOK_AND:
            if (state.size()==0) throw exception_syntax_error(SERR_AND_WITHOUT_IF, stm->getLineNo());
            if (state.top().is_or || state.top().is_else) throw exception_syntax_error(SERR_AND_AFTER_OR_OR_ELSE, stm->getLineNo());
            state.top().is_and = true;            
            expectTest(stm);
            break;
        case TOK_OR :
            if (state.size()==0) throw exception_syntax_error(SERR_OR_WITHOUT_IF, stm->getLineNo());
            if (state.top().is_and || state.top().is_else) throw exception_syntax_error(SERR_OR_AFTER_AND_OR_ELSE, stm->getLineNo());
            state.top().is_or = true;            
            expectTest(stm);
            break;
        case TOK_ELSE :
            if (state.size()==0) throw exception_syntax_error(SERR_ELSE_WITHOUT_IF, stm->getLineNo());
            state.top().is_else = true;            
            break;
        case TOK_ENDIF :
            if (state.size()==0) throw exception_syntax_error(SERR_ENDIF_WITHOUT_IF, stm->getLineNo());
            state.pop();
            break;
        case TOK_ACCEPT : expectTest(stm, 0, false);
                          break;

        case TOK_REJECT :
        case TOK_SAY :
        case TOK_YELL : 
                        expectParameter(stm, PARAM_STRING);
                        break;
        case TOK_ADDPUBKEY :
                        expectParameter(stm, PARAM_HEX_STRING);
                        break;
        case TOK_SETENV :
                        expectParameter(stm, PARAM_STRING, 0, 2);
                        break;
        default: 
            throw std::runtime_error("Unhandled command");
    }
}


void syntax_check(Statement *top)
{
    Statement *current = top;
    std::stack<ifstate> state;
    for (auto &s : current->getStatements()) {
        Statement *stm = s.get();
        expectCommand(stm, state);
    }
    if (state.size()>0) throw exception_syntax_error(SERR_IF_WITHOUT_ENDIF, top->getLineNo());
}

static const char *getParamString(Statement *stm, int index)
{
    Parameter *p = static_cast<Parameter*>(stm->getStatements().at(index).get());
    return p->getParam().c_str();
}

/*
static Token getCondition(Statement *stm, int index)
{
    return stm->getStatements().at(index).get()->getToken();
}
*/

static int nproc_check(int cores)
{
    return std::thread::hardware_concurrency() <= cores;
}

static bool evaluateTest(Statement *stm, int index = 0)
{
    if (stm->getStatements().size()==0)
        return true;
    switch(stm->getStatements().at(index + 0)->getToken()) {
        case TOK_ENV:
            {
                const char *env = getenv(getParamString(stm, index+2));
                if ((env!=NULL) && (strlen(env)>0)) // TOK_NZ
                    return true;
            }
            return false;
        case TOK_DATE:
            {
                struct tm tm;
                memset(&tm, 0, sizeof(tm));
                if (strptime(getParamString(stm, index+2), "%Y-%m-%d", &tm))
                {
                    time_t conditon_date = mktime(&tm);
                    time_t t = time(NULL);
                    struct tm now = *localtime(&t);
                    return t < conditon_date; // TOK_BEFORE
                }
            }
            return false;
        case TOK_VERSION:
            {
                struct tm *ver_tm;
                struct tm tm;
                memset(&tm, 0, sizeof(tm));
                time_t epoch = YOSYSHQ_RELEASE;
                ver_tm = localtime(&epoch);
                if (strptime(getParamString(stm, index+2), "%Y-%m-%d", &tm))
                {
                    time_t conditon_date = mktime(&tm);
                    time_t t = mktime(ver_tm);
                    return t < conditon_date; // TOK_VERSION
                }
            }
            return false;
        case TOK_NPROC:
            {
                long cores = atol(getParamString(stm, index+2));
                return nproc_check(cores); // TOK_MAX
            }
        case TOK_MAC:
            return execute_check(CHECK_MAC_ADDRESS,getParamString(stm, index+1));
        case TOK_HOSTID:
            return execute_check(CHECK_HOSTID,getParamString(stm, index+1));
        case TOK_MACHINEID:
            return execute_check(CHECK_MACHINEID,getParamString(stm, index+1));
        case TOK_HOSTNAME:
            return execute_check(CHECK_HOSTNAME,getParamString(stm, index+1));
        case TOK_AWS:
            return execute_check(CHECK_AWS_INSTANCE,getParamString(stm, index+1));
        case TOK_SCALEWAY:                
            return execute_check(CHECK_SCALEWAY_INSTANCE,getParamString(stm, index+1));
        case TOK_GITHUB_REPO:                
            return execute_check(CHECK_GITHUB_REPO,getParamString(stm, index+1));
        case TOK_GITHUB_OWNER:                
            return execute_check(CHECK_GITHUB_OWNER,getParamString(stm, index+1));
        case TOK_NOT:
            return !evaluateTest(stm, index+1);
        default: 
            throw std::runtime_error("Unhandled test");
    }
    return false;
}

class reject_rule : public std::exception {
public:
    explicit reject_rule(const std::string& what_arg) : what_msg(what_arg) {};
	const char * what () const throw () { return what_msg.c_str(); }
private:
    std::string what_msg;
};

extern "C" int tabby_silence;
int tabby_silence = 0;

static bool executeCommand(Statement *stm)
{
    switch(stm->getToken()) {
        case TOK_COMMENT:
            break;
        case TOK_ACCEPT: 
            return evaluateTest(stm, 0);
        case TOK_REJECT:
            throw reject_rule(getParamString(stm,0));
        case TOK_ADDPUBKEY:
            break;
        case TOK_SAY:
            if (!tabby_silence) fprintf(stdout, "%s\n", getParamString(stm,0));
            break;
        case TOK_YELL: 
            if (!tabby_silence) fprintf(stderr, "%s\n", getParamString(stm,0));
            break;
        case TOK_SETENV:
            {
                #if _WIN32
                    throw std::runtime_error("Unimplemented");
                #else
                    const char *val = getParamString(stm,1);
                    if (val)
                        setenv(getParamString(stm,0),val,1);
                    else
                        unsetenv(getParamString(stm,0));
                #endif
            }
            break;
        default: 
            throw std::runtime_error("Unhandled command");
    }
    // Implicit reject
    return false;
}

bool execute_script(Statement *top, bool verbose)
{
    Statement *current = top;
    syntax_check(top);
    std::stack<ifstate> state;
    try {
        for (auto &s : current->getStatements()) {
            Statement *stm = s.get();
            if (verbose && stm->isCommand()) {
                Command *c = static_cast<Command*>(stm);
                printf("[license] [Line %d] : %s\n",c->getLineNo(),c->getLineText().c_str());
            }
            switch(stm->getToken()) {
                case TOK_IF:
                    state.push(ifstate());
                    state.top().value = evaluateTest(stm, 0);
                    break;
                case TOK_AND:
                    state.top().is_and = true;
                    state.top().value &= evaluateTest(stm, 0);
                    break;
                case TOK_OR:
                    state.top().is_or = true;
                    state.top().value |= evaluateTest(stm, 0);
                    break;
                case TOK_ELSE:
                    state.top().is_else = true;
                    break;
                case TOK_ENDIF:
                    state.pop();
                    break;
                default:
                    if ((state.size()==0) || (state.top().value && !state.top().is_else)  || (!state.top().value && state.top().is_else))
                        if (executeCommand(stm)) return true;                 
            }
        }
    } catch(reject_rule ex) {
        fprintf(stdout, "%s\n", ex.what());
    }
    return false;
}

std::vector<std::tuple<std::string, bool, OpenPGP::Key::Ptr>> public_keys;

static std::string hex_to_bytes(const std::string& hex)
{
  std::string bytes;
  for (size_t i = 0; i < hex.length(); i += 2) {
    char byte = (char) strtol(hex.substr(i, 2).c_str(), NULL, 16);
    bytes += byte;
  }

  return bytes;
}

static int execute_add_pubkey(Statement *top)
{
    Statement *current = top;
    syntax_check(top);
    std::stack<ifstate> state;
    for (auto &s : current->getStatements()) {
        Statement *stm = s.get();
        switch(stm->getToken()) {
            case TOK_IF:
                state.push(ifstate());
                state.top().value = evaluateTest(stm, 0);
                break;
            case TOK_AND:
                state.top().is_and = true;
                state.top().value &= evaluateTest(stm, 0);
                break;
            case TOK_OR:
                state.top().is_or = true;
                state.top().value |= evaluateTest(stm, 0);
                break;
            case TOK_ELSE:
                state.top().is_else = true;
                break;
            case TOK_ENDIF:
                state.pop();
                break;
            default:
                if ((state.size()==0) || (state.top().value && !state.top().is_else)  || (!state.top().value && state.top().is_else)) {
                    if (stm->getToken() == TOK_ADDPUBKEY) {
                        std::string key = hex_to_bytes(getParamString(stm,0)).c_str();
                        public_keys.push_back(std::make_tuple("Customer", false, std::move(OpenPGP::Key::Ptr(new OpenPGP::Key(key)))));
                        return public_keys.size() - 1;
                    }
                }
        }
    }
    return 0;
}

std::vector<std::pair<std::string,bool>> split_content(std::istream &in)
{
    std::vector<std::pair<std::string,bool>> retVal;
    
    std::string line;
    std::stringstream ss;
    bool pgp = false;
    in.clear();
    in.seekg(0);
    while (std::getline(in, line))
    {
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        if (line == "-----BEGIN PGP SIGNED MESSAGE-----") {
            if (ss.str().size()>0) {
                retVal.push_back(std::make_pair<std::string,bool>(ss.str(),false));
            }
            ss.str("");
            pgp = true;
        }
        ss << line << std::endl;
        if (line == "-----END PGP SIGNATURE-----") {
            if (ss.str().size()>0) {
                retVal.push_back(std::make_pair<std::string,bool>(ss.str(),true));
            }
            ss.str("");
            pgp = false;
        }
    }
    if (ss.str().size()>0) {
        retVal.push_back(std::make_pair<std::string,bool>(ss.str(),false));
    }
    return retVal;
}

extern unsigned char yosyshq_public_key[2012];
extern unsigned char yosyshq_public_key_old[2012];

static std::string decrypt(std::string msg, int key_index)
{
    auto const& key = public_keys.at(key_index);
    OpenPGP::Key::Ptr ptr = std::get<2>(key);
    OpenPGP::Key *signer = ptr.get();

	const OpenPGP::CleartextSignature signature(msg);
	const int verified = OpenPGP::Verify::cleartext_signature(*signer, signature);
	if (verified == -1) {
        throw std::runtime_error("License file is damaged");
	} else if (verified != 1) {
        if (key_index < public_keys.size()-1 && std::get<0>(public_keys.at(key_index+1)) == "YosysHQ") {
            return decrypt(msg, key_index+1);
        }
        throw std::runtime_error("License not signed by " + std::get<0>(key));
	} else {
        /*if (std::get<1>(key)) {
            throw std::runtime_error("Using deprecated license, contact support@yosyshq.com for new license");
        }*/
        /*
        OpenPGP::Packet::Tag2::Ptr sig = std::static_pointer_cast <OpenPGP::Packet::Tag2> (signature.get_sig().get_packets()[0]);
        if (sig && (sig->get_hash() < OpenPGP::Hash::ID::SHA256 || sig->get_hash() > OpenPGP::Hash::ID::SHA224)) {
            throw std::runtime_error("Using insecure hash algorithm, contact support@yosyshq.com for new license");
        }
        */
		return signature.get_message();
	}        
    return std::string();
}

static std::vector<std::string> split_string_by_newline(const std::string& str)
{
    auto result = std::vector<std::string>{};
    auto ss = std::stringstream(str);

    for (std::string line; std::getline(ss, line, '\n');)
        result.push_back(line);

    return result;
}

std::unique_ptr<Statement> parse_rules(std::istream &in)
{  
    std::unique_ptr<Statement> top = std::make_unique<TopStatement>();
    if (public_keys.size()==0) {
        static int done = false;
        if (!done) {
            unsigned char val = 0;
            for(int i=0;i<2012;i++)
                yosyshq_public_key[i] ^= val++;
            public_keys.push_back(std::make_tuple("YosysHQ", false, std::move(OpenPGP::Key::Ptr(new OpenPGP::Key(std::string((const char*)yosyshq_public_key))))));
            val = 0;
            for(int i=0;i<2012;i++)
                yosyshq_public_key_old[i] ^= val++;
            public_keys.push_back(std::make_tuple("YosysHQ", true, std::move(OpenPGP::Key::Ptr(new OpenPGP::Key(std::string((const char*)yosyshq_public_key_old))))));
            done = true;
        }
    }
    auto res = split_content(in);
    int key_index = 0;
    int lineno = 0;
    for(auto &p : res) {
        std::vector<std::string> orig_lines = split_string_by_newline(p.first);
        int before = lineno;
        if (p.second) {
            std::istringstream in(decrypt(p.first, key_index));
            lineno += 2; // skip header
            parse_rules(in, p.second, lineno, top.get());
            syntax_check(top.get());
            key_index = execute_add_pubkey(top.get());
        } else {
            std::istringstream in(p.first);
            parse_rules(in, p.second, lineno, top.get());
            syntax_check(top.get());
        }
        lineno = before + orig_lines.size();
    }
    return top;
}

static void check_all_keys(std::string msg, bool display)
{
    for(int key_index=0; key_index < public_keys.size(); key_index++) {
        auto const& key = public_keys.at(key_index);
        OpenPGP::Key::Ptr ptr = std::get<2>(key);
        OpenPGP::Key *signer = ptr.get();

        const OpenPGP::CleartextSignature signature(msg);
        const int verified = OpenPGP::Verify::cleartext_signature(*signer, signature);

        if (signature.meaningful()) {
            if (verified != 0) {
                OpenPGP::Packet::Tag2::Ptr sig = std::static_pointer_cast <OpenPGP::Packet::Tag2> (signature.get_sig().get_packets()[0]);
                if (sig && (sig->get_hash() < OpenPGP::Hash::ID::SHA256 || sig->get_hash() > OpenPGP::Hash::ID::SHA224)) {
                    printf("[license] WARNING: Insecure hash algorithm: %s\n", get_mapped(OpenPGP::Hash::NAME, sig->get_hash()).c_str());
                }
            }
        }

        if (verified == 1) {
            if (std::get<1>(key)) {
                printf("[license] WARNING: Licensed signed with deprecated key.\n");
            }
            if (display) {
                printf("[license] Signed block is valid and signed by key '%s'.\n", std::get<0>(key).c_str());
                printf("\n%s\n", signature.get_sig().show().c_str());
            }
            return;
        }
        if (verified == -1) {
            printf("[license] ERROR: Signed block is signed by key '%s' but DAMAGED.\n", std::get<0>(key).c_str());
            if (display) {
                printf("\n%s\n", signature.get_sig().show().c_str());
            }
            return;
        }
    }
    printf("[license] ERROR: Signed block not signed with any of provided keys.\n");
}

void display_info_and_check(std::istream &in)
{
    auto res = split_content(in);
    int block = 0;
    for(auto &p : res) {
        block++;
        printf("[license] Checking block %d ...\n", block);
        printf("[license] ==========================\n");
        if (p.second) {
            check_all_keys(p.first, true);
        } else {
            printf("[license] Block contains unsigned information.\n");
        }
        printf("\n");
    }
}

void check_rules(std::istream &in, bool verbose)
{  
    std::unique_ptr<Statement> top = std::make_unique<TopStatement>();
    auto res = split_content(in);
    int lineno = 0;
    try {
        for(auto &p : res) {
            std::vector<std::string> orig_lines = split_string_by_newline(p.first);
            int before = lineno;
            if (p.second) {
                const OpenPGP::CleartextSignature signature(p.first);
                check_all_keys(p.first, false);        

                lineno += 3; // skip header
                std::string msg = signature.get_message();
                std::istringstream in(msg);
                std::vector<std::string> lines = split_string_by_newline(msg);

                parse_rules(in, true, lineno, top.get());
                syntax_check(top.get());
                execute_add_pubkey(top.get());
            } else {
                std::istringstream in(p.first);
                parse_rules(in, true, lineno, top.get());
                syntax_check(top.get());
            }
            lineno = before + orig_lines.size();
        }
    } catch(std::exception& ex) {
        printf("[license] <Syntax ERROR> %s\n", ex.what());
        return;
    }
    printf("[license] Syntax OK\n");
    
    printf("[license] Executing...\n");
    if (!execute_script(top.get(), verbose)) {
        printf("[license] License Check FAILED\n");
        return;
    }
    printf("[license] License Check OK\n");
}