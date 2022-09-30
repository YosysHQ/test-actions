
#include <stdio.h>
#include <stdarg.h>
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include "OpenPGP.h"
#include "parser.h"
#include "checks.h"

extern std::vector<std::tuple<std::string, bool, OpenPGP::Key::Ptr>> public_keys;

extern unsigned char yosyshq_public_key[2012];
extern unsigned char yosyshq_public_key_old[2012];

[[ noreturn ]] void fatal_error(std::string error) {
    std::cerr << "Error: " << error << std::endl;
    exit(-1);
}
 
int generate_keys(std::string pub_name, std::string pri_name)
{       
    OpenPGP::KeyGen::Config config;
    config.passphrase = "";
    config.pka        = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
    config.bits       = 2048;
    config.sym        = OpenPGP::Sym::ID::AES256;
    config.hash       = OpenPGP::Hash::ID::SHA256;

    OpenPGP::KeyGen::Config::UserID uid;
    uid.user          = "YosysHQ";
    uid.comment       = "YosysHQ License";
    uid.email         = "support@yosyshq.com";
    uid.sig           = OpenPGP::Hash::ID::SHA256;
    config.uids.push_back(uid);

    OpenPGP::KeyGen::Config::SubkeyGen subkey;
    subkey.pka        = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;
    subkey.bits       = 2048;
    subkey.sym        = OpenPGP::Sym::ID::AES256;
    subkey.hash       = OpenPGP::Hash::ID::SHA256;
    subkey.sig        = OpenPGP::Hash::ID::SHA256;
    config.subkeys.push_back(subkey);

    const OpenPGP::SecretKey pri = OpenPGP::KeyGen::generate_key(config);

    if (!pri.meaningful())
        fatal_error("Generated bad keypair.");

    const OpenPGP::PublicKey pub = pri.get_public();

    std::ofstream pub_out(pub_name, std::ios::binary);
    if (!pub_out)
        fatal_error("Could not open public key file '" + pub_name + "' for writing.");

    std::ofstream pri_out(pri_name, std::ios::binary);
    if (!pri_out)
        fatal_error("Could not open private key file '" + pri_name + "' for writing.");

    pub_out << pub.write(OpenPGP::PGP::Armored::YES) << std::flush;
    pri_out << pri.write(OpenPGP::PGP::Armored::YES) << std::flush;

    std::cout << "Keys written to '" << pub_name << "' and '" << pri_name << "'." << std::endl;
    return 0;
}

int sign(std::string private_key, std::string plain, std::string license)
{
    std::ifstream key(private_key, std::ios::binary);
    if (!key)
        fatal_error("File \"" + private_key + "\" not opened.");

    std::ifstream file(plain, std::ios::binary);
    if (!file)
        fatal_error("File \"" + plain + "\" not opened.");
    
    std::ofstream lic_out(license, std::ios::binary);
    if (!lic_out)
        fatal_error("Could not open license file '" + license + "' for writing.");

    const OpenPGP::Sign::Args signargs(OpenPGP::SecretKey(key), "", 4, OpenPGP::Hash::ID::SHA256);
    const OpenPGP::CleartextSignature signature = OpenPGP::Sign::cleartext_signature(signargs, std::string(std::istreambuf_iterator<char>(file), {}));

    if (!signature.meaningful())
        fatal_error("Generated bad cleartext signature.");

    lic_out << signature.write() << std::endl;
    return 0;
}

void display_info(std::string license)
{
    std::ifstream sig(license, std::ios::binary);
    if (!sig)
        fatal_error("File \"" + license + "\" not opened.");
    
    display_info_and_check(sig);
}

void verify(std::string license, bool verbose)
{
    std::ifstream sig(license, std::ios::binary);
    if (!sig)
        fatal_error("File \"" + license + "\" not opened.");
    check_rules(sig, verbose);
}

void verify_tabby(std::string license, bool verbose)
{
    try {
        std::ifstream sig(license, std::ios::binary);
        if (!sig)
            fatal_error("File \"" + license + "\" not opened.");
        auto top = parse_rules(sig);
        if (!execute_script(top.get(), false)) {
            printf("License check failed.\n");
        }
        printf("License OK.\n");
    } catch(std::exception& ex) {
        printf("[license] %s\n", ex.what());
    }
}

void display_identifiers(std::string option)
{
    if (option=="all")      return display_dev_identifiers(CheckType::CHECK_ALL);
    if (option=="local")    return display_dev_identifiers(CheckType::CHECK_LOCAL);
    if (option=="mac")      return display_dev_identifiers(CheckType::CHECK_MAC_ADDRESS);
    if (option=="hostid")   return display_dev_identifiers(CheckType::CHECK_HOSTID);
    if (option=="machine")  return display_dev_identifiers(CheckType::CHECK_MACHINEID);
    if (option=="hostname") return display_dev_identifiers(CheckType::CHECK_HOSTNAME);
    if (option=="aws")      return display_dev_identifiers(CheckType::CHECK_AWS_INSTANCE);
    if (option=="scaleway") return display_dev_identifiers(CheckType::CHECK_SCALEWAY_INSTANCE);
    fatal_error("Unknown option provided.");
}

void usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [options] [files]\n", cmd);
	printf("\n");
	printf("    -g <pubkey.asc> <privkey.asc>\n");
	printf("        Generate License File\n");
	printf("\n");
	printf("    -s <privkey.asc> <plainlic.txt> <license.txt>\n");
	printf("        Sign License File\n");
	printf("\n");
	printf("    [-P] [-p pubkey.asc ...] -d <license.txt>\n");
	printf("        Check Signatures and Display Information\n");
    printf("        options:\n");
    printf("          -P : adds YosysHQ public key to check keychain\n");
    printf("          -p : adds provided public key to check keychain\n");
    printf("          -v : verbose mode\n");
	printf("\n");
	printf("    [-P] [-p pubkey.asc ...] [-v] -c <license.txt>\n");
	printf("        Check License\n");
    printf("        options:\n");
    printf("          -P : adds YosysHQ public key to check keychain\n");
    printf("          -p : adds provided public key to check keychain\n");
	printf("\n");
	printf("    -i <option>\n");
	printf("        Display device identifiers\n");
    printf("        options:\n");
    printf("          local    : (default value) all local machine device identifiers\n");
    printf("          all      : all possible device identifiers, including remote\n");
    printf("          mac      : device mac addresses\n");
    printf("          hostid   : device host id\n");
    printf("          machine  : device machine id\n");
    printf("          hostname : device hostname\n");
    printf("          aws      : aws instance id\n");
    printf("          scaleway : scaleway instance id\n");
	printf("\n");
	printf("    -h\n");
	printf("        Display help message\n");
	printf("\n");
	exit(1);
}

extern unsigned char yosyshq_public_key[2012];
bool verbose = false;

void execute_command(char command, std::vector<std::string> parameters)
{
    if (command== 'g') {
        generate_keys(parameters.at(0), parameters.at(1));
    } else if (command == 's') {
        sign(parameters.at(0), parameters.at(1), parameters.at(2));
    } else if (command == 'd') {
        display_info(parameters.at(0));
    } else if (command == 'v') {
        verbose = true;
    } else if (command == 'c') {
        verify(parameters.at(0), verbose);
    } else if (command == 't') {
        verify_tabby(parameters.at(0), verbose);
    } else if (command == 'i') {
        display_identifiers(parameters.at(0));
    } else if (command== 'P') {
        unsigned char val = 0;
        for(int i=0;i<2012;i++)
            yosyshq_public_key[i] ^= val++;
        public_keys.push_back(std::make_tuple("YosysHQ", false, std::move(OpenPGP::Key::Ptr(new OpenPGP::Key(std::string((const char*)yosyshq_public_key))))));
        val = 0;
        for(int i=0;i<2012;i++)
            yosyshq_public_key_old[i] ^= val++;
        public_keys.push_back(std::make_tuple("YosysHQ", true, std::move(OpenPGP::Key::Ptr(new OpenPGP::Key(std::string((const char*)yosyshq_public_key_old))))));
    } else if (command== 'p') {
        std::string public_key = parameters.at(0);
        std::ifstream key(public_key, std::ios::binary);
        if (!key)
            fatal_error("File \"" + public_key + "\" not opened.");
        try {
            public_keys.push_back(std::make_tuple(public_key, false, std::move(OpenPGP::Key::Ptr(new OpenPGP::Key(key)))));
        } catch(...) {
            fatal_error("Error parsing \"" + public_key + "\" key file.");
        }
    }
}

int main(int argc, char **argv)
{
    std::vector<std::string> parameters;
    
    int expected_param = -1;
    char command;

	for (int i = 1; i < argc; i++)
	{
        if (expected_param == 0) {
            execute_command(command, parameters);
            parameters.clear();
        }

		std::string arg(argv[i]);
		if (arg[0] == '-' && arg.size() > 1) {
            command = arg[1];
            switch(command) {
                case 'g' : expected_param = 2; break;
                case 's' : expected_param = 3; break;
                case 'd' : expected_param = 1; break;
                case 'c' : expected_param = 1; break;
                case 't' : expected_param = 1; break;
                case 'P' : expected_param = 0; break;
                case 'p' : expected_param = 1; break;
                case 'v' : expected_param = 0; break;
                case 'i' : expected_param = 1; break;
                default:
                    usage(argv[0]);
            };
            continue;
		}
        if (expected_param == 0) 
            usage(argv[0]);
		parameters.push_back(arg); 
        expected_param--;
	}
    
    if (expected_param && command=='i') { expected_param = 0; parameters.push_back("local"); } // special case

    if (expected_param) {
        std::cerr << "Error: Command is expected " <<  expected_param << " more parameter(s)!" << std::endl;
        usage(argv[0]);
    } else {
        execute_command(command, parameters);
        parameters.clear();
    }

	return 0;
}
