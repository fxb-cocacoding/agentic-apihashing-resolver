#include <stdint.h>

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

static uint8_t lower_ascii(uint8_t value) {
    if (value >= 'A' && value <= 'Z') {
        return (uint8_t)(value + 32u);
    }
    return value;
}

uint64_t internal_djb2_compute(const char* library_name, const char* symbol_name) {
    uint32_t hash = 5381u;
    const uint8_t* cursor = (const uint8_t*)symbol_name;
    (void)library_name;
    while (*cursor != 0u) {
        hash = ((hash << 5u) + hash) + lower_ascii(*cursor);
        cursor++;
    }
    return (uint64_t)hash;
}

static apihash_descriptor DESCRIPTORS[] = {
    {
        "internal_djb2_symbol_c",
        "Internal DJB2 Symbol (C)",
        "Lowercase DJB2 over symbol_name (32-bit output).",
        "library_function",
        32,
        "internal example",
        "internal-use",
        "internal_djb2_compute"
    }
};

uint32_t apihash_plugin_count(void) {
    return 1u;
}

const apihash_descriptor* apihash_plugin_descriptor(uint32_t index) {
    if (index >= 1u) {
        return 0;
    }
    return &DESCRIPTORS[index];
}

const char* apihash_plugin_author(uint32_t index) {
    if (index >= 1u) {
        return 0;
    }
    return "Internal Research Team";
}
