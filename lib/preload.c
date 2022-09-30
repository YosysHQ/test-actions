#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

__attribute__((constructor)) static void preload_setup(void){
    void *handle;
    void (*tabby_setup)(void);
#if defined(__APPLE__)
    handle = dlopen("@executable_path/../lib/libtabby.dylib", RTLD_LAZY);
#else
    handle = dlopen("libtabby.so", RTLD_LAZY);
#endif
    if (!handle) {
        /* fail to load the library */
        fprintf(stderr, "Error: %s\n", dlerror());
        exit(-1);
        return;
    }

    *(void**)(&tabby_setup) = dlsym(handle, "tabby_setup");
    if (!tabby_setup) {
        /* no such symbol */
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        exit(-1);
        return;
    }

    tabby_setup();
    dlclose(handle);
}
