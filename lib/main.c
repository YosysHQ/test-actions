#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
//#include <sys/types.h>
#include <unistd.h>
//#include <libgen.h>

/*
std::string get_current_process_name()
{
    #if defined(__APPLE__) || defined(__FreeBSD__)
        return getprogname();
    #elif defined(_GNU_SOURCE)
        return basename(program_invocation_name);
    #elif defined(_WIN32)
        return __argv[0];
    #else
        return "?";
    #endif
}
*/
extern int license_check(const char *filename, int (*printlogf)(const char*, ...));

extern int tabby_silence;

extern void tabby_setup(void){
	tabby_silence = 1;
	char *license_file = getenv("YOSYSHQ_LICENSE");
    if (license_file != NULL) {
        if (license_check(license_file, printf) != 0x4237efc9) {
            fprintf(stderr, "License check failed.\n");
            exit(-1);
        }
    } else {
        fprintf(stderr, "No YOSYSHQ_LICENSE environment variable found!\n");
        exit(-1);
    }
}
