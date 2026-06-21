#include <stdint.h>
#include <string.h>

typedef struct apihash_descriptor {
    const char* id;
    const char* display_name;
    const char* description;
    const char* input_mode;
    uint32_t hash_size_bits;
    const char* source;
    const char* license;
    const char* symbol_name;
} apihash_descriptor;

uint64_t native_demo_compute(const char* library_name, const char* symbol_name) {
    if (strcmp(library_name, "demo.dll") == 0 && strcmp(symbol_name, "DemoFunction") == 0) {
        return 0xAABBCCDDu;
    }
    return 0;
}

uint64_t native_demo64_compute(const char* library_name, const char* symbol_name) {
    if (strcmp(library_name, "demo.dll") == 0 && strcmp(symbol_name, "WideFunction") == 0) {
        return 0x1122334455667788ULL;
    }
    return 0;
}

static apihash_descriptor DESCRIPTORS[] = {
    {
        "native_demo",
        "Native Demo",
        "32-bit descriptor-based native hash",
        "library_function",
        32,
        "native fixture",
        "fixture",
        "native_demo_compute"
    },
    {
        "native_demo64",
        "Native Demo 64",
        "64-bit descriptor-based native hash",
        "library_function",
        64,
        "native fixture",
        "fixture",
        "native_demo64_compute"
    }
};

uint32_t apihash_plugin_count(void) {
    return 2;
}

const apihash_descriptor* apihash_plugin_descriptor(uint32_t index) {
    if (index >= 2) {
        return 0;
    }
    return &DESCRIPTORS[index];
}
