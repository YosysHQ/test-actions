#include "catch2/catch.hpp"
#include <sstream>
#include "parser.h"

TEST_CASE( "Empty input", "[parser]" ) {
    std::istringstream in("");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 0 );

    in = std::istringstream("\n\r   \t \r \n   \t  \n  \r \n\n");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 0 );
}

TEST_CASE( "Comment parsing", "[parser]" ) {
    std::istringstream in("       #  Test   \n  #");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 2 );
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_COMMENT );
    REQUIRE( top->getStatements().at(1)->isCommand());
    REQUIRE( top->getStatements().at(1)->getToken() == TOK_COMMENT );
}

TEST_CASE( "Unknown command", "[parser]" ) {
    std::istringstream in("unk");
    int lineno = 0;
    REQUIRE_THROWS_AS(parse_rules(in, true, lineno), exception_unknown_command);

    lineno = 0;
    in = std::istringstream("unk");
    REQUIRE_THROWS_WITH(parse_rules(in, true, lineno), "Line 1 : Unknown command 'unk'");
}

TEST_CASE( "Unknown condition", "[parser]" ) {
    int lineno = 0;
    std::istringstream in("accept nproc -unk");
    REQUIRE_THROWS_AS(parse_rules(in, true, lineno), exception_unknown_condition);
    lineno = 0;
    in = std::istringstream("accept nproc -unk");
    REQUIRE_THROWS_WITH(parse_rules(in, true, lineno), "Line 1 : Unknown condition '-unk'");
}

TEST_CASE( "Quotes not closed", "[parser]" ) {
    int lineno = 0;
    std::istringstream in("say \"test");
    REQUIRE_THROWS_AS(parse_rules(in, true, lineno), exception_closing_quotes);
    
    lineno = 0;
    in = std::istringstream("say \"test");
    REQUIRE_THROWS_WITH(parse_rules(in, true, lineno), "Line 1 : Closing quotes missing");
}

TEST_CASE( "Command not allowed", "[parser]" ) {
    int lineno = 0;
    std::istringstream in("accept nproc -max 32");
    REQUIRE_THROWS_AS(parse_rules(in, false, lineno), exception_command_notallowed);

    lineno = 0;
    in = std::istringstream("addpubkey key");
    REQUIRE_THROWS_AS(parse_rules(in, false, lineno), exception_command_notallowed);

    lineno = 0;
    in = std::istringstream("accept nproc -max 32");
    REQUIRE_THROWS_WITH(parse_rules(in, false, lineno), "Line 1 : Command 'accept' not allowed in unsigned block");
}

TEST_CASE( "Say command parsing", "[parser]" ) {
    std::istringstream in("say \"test text display\"");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 1 );
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_SAY );
    REQUIRE( top->getStatements().at(0)->getStatements().size() == 1 );
    REQUIRE( top->getStatements().at(0)->getStatements().at(0)->isParameter());    
    REQUIRE( !top->getStatements().at(0)->getStatements().at(0)->isCommand());

    in = std::istringstream("say \"test text display\" \"add\"");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 1 );
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_SAY );
    REQUIRE( top->getStatements().at(0)->getStatements().size() == 2 );
    REQUIRE( top->getStatements().at(0)->getStatements().at(0)->isParameter());
    REQUIRE( top->getStatements().at(0)->getStatements().at(1)->isParameter());
}

TEST_CASE( "Accept command parsing", "[parser]" ) {
    std::istringstream in("accept mac 11:11:11:11:11:11");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 1 );
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_ACCEPT );
    REQUIRE( top->getStatements().at(0)->getStatements().size() == 2 );
    REQUIRE( top->getStatements().at(0)->getStatements().at(0)->isTest());
    REQUIRE( top->getStatements().at(0)->getStatements().at(1)->isParameter());
}

TEST_CASE( "Accept with no test", "[parser]" ) {
    std::istringstream in("accept");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 1 );
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_ACCEPT );
    REQUIRE( top->getStatements().at(0)->getStatements().size() == 0 );

    in = std::istringstream ("accept 11:11:11:11:11:11");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 1);
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_ACCEPT );
    REQUIRE( top->getStatements().at(0)->getStatements().size() == 1 );
}

TEST_CASE( "Big test", "[parser]" ) {
    std::istringstream in(
        "if date -before 2022-01-01\n" \
        "and nproc -max 32\n" \
        "  accept mac 00:11:22:33:44:55\n" \
        "  accept mac 11:22:33:55:66:77\n" \
        "  accept mac 22:33:44:66:77:88\n" \
        "  reject \"No matching MAC address found for this license!\"\n" \
        "else\n"
        "  reject \"License Expired or max processors exceeded!\"\n" \
        "endif\n"
    );
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE( top->getStatements().size() == 9 );
    REQUIRE( top->getStatements().at(0)->isCommand());
    REQUIRE( top->getStatements().at(0)->getToken() == TOK_IF );
    REQUIRE( top->getStatements().at(0)->getStatements().size() == 3 );
    REQUIRE( top->getStatements().at(0)->getStatements().at(0)->isTest());
    REQUIRE( top->getStatements().at(0)->getStatements().at(1)->isCondition());
    REQUIRE( top->getStatements().at(0)->getStatements().at(2)->isParameter());
    REQUIRE_NOTHROW(syntax_check(top.get()));
}


class SyntaxErrorExceptionMatcher : public Catch::MatcherBase<exception_syntax_error> {
public:
    SyntaxErrorExceptionMatcher(SyntaxError expected) : _expected(expected) {}

    bool match(exception_syntax_error const &e) const override {
        return e.code() == _expected;
    }

    std::string describe() const override {
        std::string desc = exception_syntax_error::translate(_expected);
        return "expecting '"+desc+ "'";
    }
private:
    SyntaxError _expected;
};

TEST_CASE( "Syntax error exceptions", "[exceptions]" ) {
    REQUIRE(std::string(exception_syntax_error::translate(SERR_PARAMETER_MISSING)) == "Parameter is missing");
    
    std::istringstream in("say");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_WITH(syntax_check(top.get()), "Line 1 : Parameter is missing");
}

TEST_CASE( "Accept command", "[syntax]" ) {
    std::istringstream in("accept mac 11:11:11:11:11:11");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept 11:11:11:11:11:11");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_TEST_MISSING});

    in = std::istringstream ("accept unk 11:11:11:11:11:11");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_TEST_MISSING});

    in = std::istringstream ("accept not mac 11:11:11:11:11:11");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept mac 11:11:11:11:11:1v");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_NOT_MAC_ADDRESS});

    in = std::istringstream ("accept hostid 1231232");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept hostname test1231232");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept machine-id 12abcdef31232");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept aws-instance 12abcdef31232");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept scaleway-instance 12abcdef31232");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("accept");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));
}

TEST_CASE( "If command", "[syntax]" ) {
    std::istringstream in("if date -before 2022-01-01");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_IF_WITHOUT_ENDIF});
    
    in = std::istringstream(
        "if date -before 2022-01-01\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream(
        "if date -before 2022-01-01\n" \
        "and nproc -max 32\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream(
        "if date -before 2022-01-01\n" \
        "and nproc -max 32\n" \
        "or nproc -max 32\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_OR_AFTER_AND_OR_ELSE});

    in = std::istringstream(
        "if date -before 2022-01-01\n" \
        "or nproc -max 32\n" \
        "and nproc -max 32\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_AND_AFTER_OR_OR_ELSE});

    in = std::istringstream(
        "if date -before 2022-01-01\n" \
        "else\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));
    
    in = std::istringstream(
        "if date 2022-01-01\n" \
        "else\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_CONDITION_MISSING});
        
    in = std::istringstream(
        "if date -max 2022-01-01\n" \
        "else\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_INVALID_CONDITION});

    in = std::istringstream(
        "if nproc -max aaa\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_NOT_UNSIGNED_INTEGER});
    
    in = std::istringstream(
        "if nproc -max 12\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);

    REQUIRE_NOTHROW(syntax_check(top.get()));
    in = std::istringstream(
        "if date -before 2022-01-121\n" \
        "else\n" \
        "endif"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_NOT_DATE});

}

TEST_CASE( "Output commands", "[syntax]" ) {
    std::istringstream in("reject \"License Expired or max processors exceeded!\"");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("say \"Testing output\"");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("say \"Testing output\" \"test\"");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_EXTRA_KEYWORDS});

    in = std::istringstream ("say");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_PARAMETER_MISSING});

    in = std::istringstream ("say env");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_EXPECTING_PARAMETER});

    in = std::istringstream ("yell \"Testing stderr output\"");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));
}

TEST_CASE( "Environment commands", "[syntax]" ) {
    std::istringstream in("setenv test value");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));

    in = std::istringstream ("if env -nz test\nendif");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_NOTHROW(syntax_check(top.get()));
}

TEST_CASE( "Multiple parts", "[parser]" ) {
    std::istringstream in(
        "# First comment line\n" \
        "# 2nd comment line\n" \
        "setenv testvar value\n" \
        "say \"This is customer commands section\"\n"
    );
    int lineno = 0;
    auto top = parse_rules(in, false, lineno);
    in = std::istringstream(
        "if date -before 2022-01-01\n" \
        "and nproc -max 32\n" \
        "  accept mac 00:11:22:33:44:55\n" \
        "  accept mac 11:22:33:55:66:77\n" \
        "  accept mac 22:33:44:66:77:88\n" \
        "  reject \"No matching MAC address found for this license!\"\n" \
        "else\n"
        "  reject \"License Expired or max processors exceeded!\"\n" \
        "endif\n"
    );

    parse_rules(in, true, lineno, top.get());

    REQUIRE_NOTHROW(syntax_check(top.get()));
    REQUIRE_NOTHROW(execute_script(top.get()));
}

TEST_CASE( "Implicit reject", "[executor]" ) {
    std::istringstream in("");
    int lineno = 0;
    auto top = parse_rules(in, false, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check date", "[executor]" ) {
    std::istringstream in("accept date -before 2099-01-01");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);
}

TEST_CASE( "Check mac", "[executor]" ) {
    std::istringstream in("accept mac 11:22:33:44:55:66");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check hostid", "[executor]" ) {
    std::istringstream in("accept hostid 11223344");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check machine-id", "[executor]" ) {
    std::istringstream in("accept machine-id 11223344556677889900");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check hostname", "[executor]" ) {
    std::istringstream in("accept hostname unknown");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

/*
TEST_CASE( "Check aws-instance", "[executor]" ) {
    std::istringstream in("accept aws-instance unknown");
    auto top = parse_rules(in, true);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check scaleway-instance", "[executor]" ) {
    std::istringstream in("accept scaleway-instance unknown");
    auto top = parse_rules(in, true);
    REQUIRE(execute_script(top.get()) == false);
}
*/

TEST_CASE( "Check empty", "[executor]" ) {
    std::istringstream in("accept");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);
}

TEST_CASE( "Check NOT", "[executor]" ) {
    std::istringstream in("accept not date -before 2000-01-01");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);
}

TEST_CASE( "Check env", "[executor]" ) {
    std::istringstream in("accept env -nz PWD");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);

    in = std::istringstream("accept env -nz UNKNOWN");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);

    in = std::istringstream("setenv UNKNOWN val\naccept env -nz UNKNOWN");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);

    in = std::istringstream("setenv UNKNOWN \"\"\naccept env -nz UNKNOWN");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check if", "[executor]" ) {
    std::istringstream in(
        "setenv UNKNOWN value\n" \
        "if date -before 2099-01-01\n" \
        "   setenv UNKNOWN \"\"\n" \
        "endif\n" \
        "accept not env -nz UNKNOWN\n"
    );
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);

    in = std::istringstream(
        "setenv UNKNOWN value\n" \
        "if date -before 2099-01-01\n" \
        "and date -before 2000-01-01\n" \
        "   setenv UNKNOWN \"\"\n" \
        "endif\n" \
        "accept not env -nz UNKNOWN\n"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);

    in = std::istringstream(
        "setenv UNKNOWN value\n" \
        "if date -before 2099-01-01\n" \
        "or date -before 2000-01-01\n" \
        "   setenv UNKNOWN \"\"\n" \
        "endif\n" \
        "accept not env -nz UNKNOWN\n"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);

    in = std::istringstream(
        "yell \"Checking\"\n" \
        "setenv UNKNOWN value\n" \
        "if date -before 2000-01-01\n" \
        "   say \"Wrong\"\n" \
        "else\n" \
        "   setenv UNKNOWN \"\"\n" \
        "endif\n" \
        "accept not env -nz UNKNOWN\n"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);

    in = std::istringstream(
        "setenv UNKNOWN value\n" \
        "if date -before 2000-01-01\n" \
        "   if date -before 1900-01-01\n" \
        "     say \"Wrong 1900\"\n" \
        "   endif\n" \
        "   say \"Wrong 2000\"\n" \
        "else\n" \
        "   if date -before 2050-01-01\n" \
        "     setenv UNKNOWN \"\"\n" \
        "   else\n" \
        "     say \"Wrong 1900\"\n" \
        "   endif\n" \
        "endif\n" \
        "accept not env -nz UNKNOWN\n"
    );
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == true);
}

TEST_CASE( "Two rejects", "[exceptions]" ) {
    std::istringstream in(
        "reject \"First reject\"\n" \
        "reject \"2nd reject\"\n"
    );
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check addpubkey", "[executor]" ) {
    std::istringstream in("addpubkey test");
    int lineno = 0;
    auto top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_NOT_HEX_STRING});

    in = std::istringstream("addpubkey 11223");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE_THROWS_MATCHES(syntax_check(top.get()), exception_syntax_error, SyntaxErrorExceptionMatcher{SERR_NOT_HEX_STRING});

    in = std::istringstream("addpubkey 2d2d2d2d2d424547494e20504750205055424c4943204b455920424c4f434b2d2d2d2d2d0a56657273696f6e3a2063630a0a7873444b42474239592f49424341437738353935376b4c494130562b4b4e6c4a3447414e6a796749522b4257466747594641577744376d6d69636d73354744760a646b4452584a6b713139434e75586a564c74536161514a4565512f2f4d66624e65356f32525647426e35695a42444151396b6a336944752f746a394a4e656c2f0a746370686939506e30506858636568696741334f4a4d4e5133784f78794759712b65524b684b506b713655376c7469723251446c70776969625930486368466f0a562b6357506e4d316a5573524355652f48336e70756b6430572b744f5535476d61666355625253444b3245642f4d565871526247426d4e3569646454334b76730a6c754c4d59794e2b71716955617a6375584e5555744d7277496135546a4d474430354845482f626c3672474d67376f5376455a33643755502b7a502f683456330a6250666178526d4a2b54306c54525047773668676f497039706b2b427477783364486754412f774e42786e457a454d55367963667547577a626f7773634c312f0a724b3266537442666e6b2b537a6a6468374a615549616c2b42664a716c356970376b48364c325166534f6d3369426c38495874485669694a3478576e3755394f0a6943683057745364385742372f6c644671434e4a4c4b34304e454d50786f69434c4a764b6a4d6759487237534648316e2f2b3034337377734743626367734f680a772f2f43777048474664567a5156706f506330765757397a65584e495553416f5757397a65584e495553424d61574e6c626e4e6c4b53413863335677634739790a6445423562334e35633268784c6d4e7662543743774677454577454341415946416d4239592f494143676b51346544346875764b79727435766766384347724d0a6e703353676c2f75416c5a4b4148474951744a446a71544c72337675574c6a596454706242655437556f754541484358566a31444c6f433775612f31657968630a5438537a7073423865786e2f786a50636845566d2f5942725a684d654358737a73374c37376e5068456e477849414f334c774b6259736d2b42396144364655310a7a33594436484f444953395158626943753735782f4b4d365834317547694946646757396c78424b377845736f7964715a58444f4d3832787a4a596633734c6f0a4144392f44716c33646945527667336f7947456e344b6e594d645963392b4f69416a6d6e696c5579524253533954454f67367472306962693652754b497a314d0a44576868594934306c457739624857726a2f415a6865382b7533506f45782f2b6a784b762b354b7a7744327939326b4145664233652b385932346956657137620a57373370314c6e6278544c786e6851335263374179675267665750794151674172644e356b6269796e326f776c616d4f3679537a7a477856336e3143773457590a486a6e36564677456b50305376585a5078506c3775444d2b376a596b4f552b5961457a475a784e6d69632b70785a5970694a6f6965536133596e497246354f4a0a665364543648416847476f7a5a754f4c5a4f2f6471453576454e72704757396a4d656e663654374f526b564a78442b6d724154373767525961465634663743590a457a717a66664a68784f313168506432414a6c32506946544168714c613749536f4d676865546b5a62456739553544694b35746c537a6e586d357a74674c59760a483466656c7538594c686169704b477a4374374537445156374f745173682f72506d636955364d374b7031584538777163525431626753696f65676f684d65760a6e714558756b355067786f4247786b316b76686c69317a5a355062365773664654356b616d396b764d794a45424f504a316235617051502f6138336e726f596f0a762b56467830334c6452543539337a4e444830476d736273554b4c5338556368506e7268574f39647834756f63364976674a496d74363966624d70666d5252370a44317241754c574f366d476b357a395a3234454f4a704c656f4c7635656b324d4659797454336b3275583373317843764a72303464492f4f3756684b2b6f4c6d0a42677a6548326e574e7135645752502b65625339474d52386d62756e536a5a4a37495043774677454741454341415946416d4239592f494143676b51346544340a6875764b79727471787767416f626a6d6a39366b716a69636251576943773270735a6e464d4f4f2b38394b3749384e3449522f546534736b41775a6d504b6c700a7672503152334144476d3741367a6b44447a755455456c684c317a61704c6e376566465179756c7364326c6b546d35374c7061684f42424375422b754377394e0a70795777456357696b43505847757767654e655a4e6b3667775a65734f4a453274304c31475076706f717068467632396d5566305137645763335661326f47380a357062416e6f7151754f434a37567851636a6d2b35354232486d6a56744d3448744c49304544314b354956554a7a445863656672625557316b6e355a7a5a51320a2f35446f7878584e38657634796b5a4a715755556f794a374670564634396f344a6e312f584470376467767779583958414f555343457633616236634b3931760a6347736f43414d6f62726246464c6373414466376654364c796655387265773576673d3d0a3d616443730a2d2d2d2d2d454e4420504750205055424c4943204b455920424c4f434b2d2d2d2d2d");
    lineno = 0;
    top = parse_rules(in, true, lineno);
    REQUIRE(execute_script(top.get()) == false);
}

TEST_CASE( "Check license", "[executor]" ) {
    std::istringstream in(
        "yell \"111\"\n" \
        "-----BEGIN PGP SIGNED MESSAGE-----\n" \
        "Hash: SHA1\n" \
        "\n" \
        "yell \"academic license - for non-commercial use only\"\n" \
        "accept date -before 2021-06-06\n" \
        "reject \"license expired\"\n" \
        "-----BEGIN PGP SIGNATURE-----\n" \
        "Version: cc\n" \
        "\n" \
        "wsBcBAEBAgAGBQJgkmkvAAoJEG2H+iE1UX26dYgH/AxzIPkb3ZhhacEnwaKOeVdJ\n" \
        "AlAYJrCkVUZwZyK+Tww6ssd6S//wga3loW2gbeh3CyAGqEHKqLg9ZVFb4MUvhEI9\n" \
        "Q5bczetU+qOCiMOclmS28P6o6BMIMF6p0EOVmUQ0kkyu7Xe7K3Hv8aPi8kKZ0Kss\n" \
        "Q8r/abUOoURk6y71/CNHI+1j3LzxQ0j/qIK72JKFtE9/pxw+VC73dZuPypHKoUvb\n" \
        "00mPxsUYEUBgVdSkyV+ofha3JFVqXOyRw9di9LWAyNMB95bF0/4cTJVn7lDuqsl8\n" \
        "ie6im1lc8LdEL8UjcI7lPH+mIvVu19z2N/ULW5MUJeHFW0RRfy8jNtiju7GOqmg=\n" \
        "=YnyP\n" \
        "-----END PGP SIGNATURE-----\n" \
        "\n" \
        "yell \"22\"\n" \
        "\n" \
        "-----BEGIN PGP SIGNED MESSAGE-----\n" \
        "Hash: SHA1\n" \
        "\n" \
        "yell \"academic license - for non-commercial use only\"\n" \
        "accept date -before 2021-06-06\n" \
        "reject \"license expired\"\n" \
        "-----BEGIN PGP SIGNATURE-----\n" \
        "Version: cc\n" \
        "\n" \
        "wsBcBAEBAgAGBQJgkmkvAAoJEG2H+iE1UX26dYgH/AxzIPkb3ZhhacEnwaKOeVdJ\n" \
        "AlAYJrCkVUZwZyK+Tww6ssd6S//wga3loW2gbeh3CyAGqEHKqLg9ZVFb4MUvhEI9\n" \
        "Q5bczetU+qOCiMOclmS28P6o6BMIMF6p0EOVmUQ0kkyu7Xe7K3Hv8aPi8kKZ0Kss\n" \
        "Q8r/abUOoURk6y71/CNHI+1j3LzxQ0j/qIK72JKFtE9/pxw+VC73dZuPypHKoUvb\n" \
        "00mPxsUYEUBgVdSkyV+ofha3JFVqXOyRw9di9LWAyNMB95bF0/4cTJVn7lDuqsl8\n" \
        "ie6im1lc8LdEL8UjcI7lPH+mIvVu19z2N/ULW5MUJeHFW0RRfy8jNtiju7GOqmg=\n" \
        "=YnyP\n" \
        "-----END PGP SIGNATURE-----\n" \
        "\n" \
        "yell \"333\"\n" 
    );
    auto res = split_content(in);
    REQUIRE(res.size()==5);
    REQUIRE(res.at(0).second==false);
    REQUIRE(res.at(1).second==true);
    REQUIRE(res.at(2).second==false);
    REQUIRE(res.at(3).second==true);
    REQUIRE(res.at(4).second==false);
    REQUIRE_NOTHROW(parse_rules(in));
    auto top = parse_rules(in);
    REQUIRE(top->getStatements().size() == 9 );
}

TEST_CASE( "Check dual level license", "[executor]" ) {
    std::istringstream in(
        "-----BEGIN PGP SIGNED MESSAGE-----\n" \
        "Hash: SHA1\n" \
        "\n" \
        "yell \"Trustfull client\"\n" \
        "addpubkey 2d2d2d2d2d424547494e20504750205055424c4943204b455920424c4f434b2d2d2d2d2d0a56657273696f6e3a2063630a0a7873444b42474239592f49424341437738353935376b4c494130562b4b4e6c4a3447414e6a796749522b4257466747594641577744376d6d69636d73354744760a646b4452584a6b713139434e75586a564c74536161514a4565512f2f4d66624e65356f32525647426e35695a42444151396b6a336944752f746a394a4e656c2f0a746370686939506e30506858636568696741334f4a4d4e5133784f78794759712b65524b684b506b713655376c7469723251446c70776969625930486368466f0a562b6357506e4d316a5573524355652f48336e70756b6430572b744f5535476d61666355625253444b3245642f4d565871526247426d4e3569646454334b76730a6c754c4d59794e2b71716955617a6375584e5555744d7277496135546a4d474430354845482f626c3672474d67376f5376455a33643755502b7a502f683456330a6250666178526d4a2b54306c54525047773668676f497039706b2b427477783364486754412f774e42786e457a454d55367963667547577a626f7773634c312f0a724b3266537442666e6b2b537a6a6468374a615549616c2b42664a716c356970376b48364c325166534f6d3369426c38495874485669694a3478576e3755394f0a6943683057745364385742372f6c644671434e4a4c4b34304e454d50786f69434c4a764b6a4d6759487237534648316e2f2b3034337377734743626367734f680a772f2f43777048474664567a5156706f506330765757397a65584e495553416f5757397a65584e495553424d61574e6c626e4e6c4b53413863335677634739790a6445423562334e35633268784c6d4e7662543743774677454577454341415946416d4239592f494143676b51346544346875764b79727435766766384347724d0a6e703353676c2f75416c5a4b4148474951744a446a71544c72337675574c6a596454706242655437556f754541484358566a31444c6f433775612f31657968630a5438537a7073423865786e2f786a50636845566d2f5942725a684d654358737a73374c37376e5068456e477849414f334c774b6259736d2b42396144364655310a7a33594436484f444953395158626943753735782f4b4d365834317547694946646757396c78424b377845736f7964715a58444f4d3832787a4a596633734c6f0a4144392f44716c33646945527667336f7947456e344b6e594d645963392b4f69416a6d6e696c5579524253533954454f67367472306962693652754b497a314d0a44576868594934306c457739624857726a2f415a6865382b7533506f45782f2b6a784b762b354b7a7744327939326b4145664233652b385932346956657137620a57373370314c6e6278544c786e6851335263374179675267665750794151674172644e356b6269796e326f776c616d4f3679537a7a477856336e3143773457590a486a6e36564677456b50305376585a5078506c3775444d2b376a596b4f552b5961457a475a784e6d69632b70785a5970694a6f6965536133596e497246354f4a0a665364543648416847476f7a5a754f4c5a4f2f6471453576454e72704757396a4d656e663654374f526b564a78442b6d724154373767525961465634663743590a457a717a66664a68784f313168506432414a6c32506946544168714c613749536f4d676865546b5a62456739553544694b35746c537a6e586d357a74674c59760a483466656c7538594c686169704b477a4374374537445156374f745173682f72506d636955364d374b7031584538777163525431626753696f65676f684d65760a6e714558756b355067786f4247786b316b76686c69317a5a355062365773664654356b616d396b764d794a45424f504a316235617051502f6138336e726f596f0a762b56467830334c6452543539337a4e444830476d736273554b4c5338556368506e7268574f39647834756f63364976674a496d74363966624d70666d5252370a44317241754c574f366d476b357a395a3234454f4a704c656f4c7635656b324d4659797454336b3275583373317843764a72303464492f4f3756684b2b6f4c6d0a42677a6548326e574e7135645752502b65625339474d52386d62756e536a5a4a37495043774677454741454341415946416d4239592f494143676b51346544340a6875764b79727471787767416f626a6d6a39366b716a69636251576943773270735a6e464d4f4f2b38394b3749384e3449522f546534736b41775a6d504b6c700a7672503152334144476d3741367a6b44447a755455456c684c317a61704c6e376566465179756c7364326c6b546d35374c7061684f42424375422b754377394e0a70795777456357696b43505847757767654e655a4e6b3667775a65734f4a453274304c31475076706f717068467632396d5566305137645763335661326f47380a357062416e6f7151754f434a37567851636a6d2b35354232486d6a56744d3448744c49304544314b354956554a7a445863656672625557316b6e355a7a5a51320a2f35446f7878584e38657634796b5a4a715755556f794a374670564634396f344a6e312f584470376467767779583958414f555343457633616236634b3931760a6347736f43414d6f62726246464c6373414466376654364c796655387265773576673d3d0a3d616443730a2d2d2d2d2d454e4420504750205055424c4943204b455920424c4f434b2d2d2d2d2d\n" \
        "-----BEGIN PGP SIGNATURE-----\n" \
        "Version: cc\n" \
        "\n" \
        "wsBcBAEBAgAGBQJgmQaXAAoJEG2H+iE1UX26pLoIAJs2Z9LyVmkTStac76Ws2wHE\n" \
        "98N+ai3kHLjTU68fTIHgHBOfedGUXQkpNGKv8jWOerP9M1WzwdW3Cl9HpgLo/bAi\n" \
        "TLILoL9kCspJ6eXBBdlw58MQ73/l0a53QsKtH+a2v0N4BH0jz/gOsJJOncba57Wy\n" \
        "UDlPbbFK9PKgaXgFNnNuycX3hoM4pde1Dp2WRQFxUnQ2zGeQopQZcfxPV0/GADkI\n" \
        "aZ90FG7M7t/2BxZXXu2rE/JeKBerPL54Ncxy56ypbfdQ9eH7DFRRNDXK3jL6AUQH\n" \
        "0PMdIBB87MFDsAKU/wrwg0UNn3c9sBb8jj/OQnb152SsEHruKWzM+b+wRGk/YAg=\n" \
        "=Wlfv\n" \
        "-----END PGP SIGNATURE-----\n" \
        "-----BEGIN PGP SIGNED MESSAGE-----\n" \
        "Hash: SHA1\n" \
        "\n" \
        "accept date -before 2021-06-06\n" \
        "reject \"license expired\"\n" \
        "-----BEGIN PGP SIGNATURE-----\n" \
        "Version: cc\n" \
        "\n" \
        "wsBcBAEBAgAGBQJgmQbEAAoJEOHg+Ibrysq7mwgH/Ro9mcVXMJ6gPqnrDbW7wPrj\n" \
        "7tHoAJuYBu3TM+GnfXPDzFsSaMMyAmOX1zrfonkORaVux8yLrQrHbXZ6BOHIYSlt\n" \
        "PUfCQEf32HB+SD0oL3Vvpdd2GZYbnpf5s46qKFl/g/MafCOJJAZSKAU60H6zLnuf\n" \
        "YXUBL96iZcGBvdm0JpziLjX37Ob3yK7z25ma8hqpGyBc0Zmz3pyiWJluoRtgZex2\n" \
        "zwkUzZuGn1dJfEK0MLpX7FTMAnYK+RHOXfIlTVXoJWuMlofmYaCMohXuC2cH6iGw\n" \
        "CkMMR+gJ77gb1D/Oh32uidFKDKYPmRAvnaBm82dHqwFxC31MLcgmaDDq1YaYjSE=\n" \
        "=IlIa\n" \
        "-----END PGP SIGNATURE-----\n"
    );
    auto res = split_content(in);
    REQUIRE(res.size()==2);
    REQUIRE(res.at(0).second==true);
    REQUIRE(res.at(1).second==true);
    REQUIRE_NOTHROW(parse_rules(in));
    auto top = parse_rules(in);
    REQUIRE(top->getStatements().size() == 4 );
}
