#include "signature.h"

#include "../maps/maps.h"

#include <fcntl.h>
#include <inttypes.h>
#include <immintrin.h>
#include <lua.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Error handling macro
#define HANDLE_ERROR(msg) \
    do {                  \
        perror(msg);      \
        return NULL;      \
    } while (0)


// use AVX512 to speed up signature scanning of first byte matches
// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html
__m512i first_byte_m512;
__mmask64 check_bytes_mask64;


/**
 * Error logging function
 *
 * @param[out] format The format string
 */
void log_error(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Error in sig_scan: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/**
 * Matches a pattern with an array of bytes.
 *
 * @param[in] data The data to compare the pattern against.
 * @param[in] pattern The pattern to test for.
 * @param[in] pattern_size The length of the pattern.
 *
 * @return u16 packed values, [found][number of bytes to skip ahead]
 */
uint32_t match_pattern(const uint8_t* data, const uint16_t* pattern, size_t pattern_size)
{
    uint32_t match_len = 0; // match / skip
    uint32_t skip = 0; // match / skip

    __m512i check_bytes_m512 = _mm512_loadu_si512(data);
    check_bytes_mask64 = _mm512_cmpeq_epi8_mask(first_byte_m512, check_bytes_m512);
/////////    if (check_bytes_mask64 == 0) {
/////////        //match_len = pattern_size; // 'correct'
/////////        return 64; // skip = 64; // return skip;
/////////    }
//    printf("                CHK64 MASK = 0x%016llx === 0x%016llx / 0x%016llx / 0x%016llx / 0x%016llx / 0x%016llx / 0x%016llx / 0x%016llx / 0x%016llx ", check_bytes_mask64,
//    first_byte_m512[0],
//    first_byte_m512[1],
//    first_byte_m512[2],
//    first_byte_m512[3],
//    first_byte_m512[4],
//    first_byte_m512[5],
//    first_byte_m512[6],
//    first_byte_m512[7]);
    //printf("                0x%08llx\n", *((unsigned long long*)data));

//    printf("                CHK64 MASK = 0x%016llx\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n"
//           "                    0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x - 0x%02x\n",
//                            check_bytes_mask64,
//                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
//                            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
//                            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
//                            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
//                            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
//                            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
//                            data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
//                            data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63] );

        //printf("                mask stt = 0x%016llx\n", check_bytes_mask64);
    while (check_bytes_mask64 != 0 && match_len < pattern_size) {
        skip = __builtin_ctzll(check_bytes_mask64); // pos/bytes to skip
        // trail zeros from 0x40000...010 means 010 is closer to data[0]
        //__mmask64 nand = ~(1 << ((__mmask64)skip - 1)); // remove last 'match'
        // nand means 0a0bc0 < remove this 'a' bit (first match in check_bytes mask)
        __mmask64 nand = 1; // just do on 3 lines or you have to cast everything
        nand = nand << skip;
        check_bytes_mask64 &= ~nand; // remove last 'match'
        match_len = 0;

        //printf("                mask now = 0x%016llx\n", check_bytes_mask64);
        //printf("                nand ????? 0x%016llx\n", nand);
        //printf("                skip position = %u   (data is %p)\n", skip, data+skip);

        // if there's any pat[0] match, (pat can't start with wildcard) just read from start
        // will re-check some of the same 8 bytes again possibly.
        // only matters for multi hit areas (y-n-n-y-n-n-n)

        //while (data[skip+match_len] == (uint8_t)(pattern[match_len] & 0xFF) && match_len < pattern_size) {
        //    match_len += 1 + ((pattern[match_len+1] >> 8) & 0x1);
        //}
        while (match_len < pattern_size) {
            if (data[skip+match_len] != (uint8_t)(pattern[match_len] & 0xFF)
                && pattern[match_len] < 0xFF) {
                break; // no match
            }
            match_len++;
        }
    }

    if (match_len == pattern_size) {
        skip = skip << 16;
        return skip + match_len;
    }
    return 64; // wasn't in the 512 bit scan
    //if (match_len == pattern_size) {
    //    skip = skip << 16;
    //}
    //return skip + match_len;
    //return match_len == pattern_size ? (skip << 16) & match_len : skip + match_len;
}

/**
 * Converts an IDA-like signature into a pattern to be used in LibreSplit.
 * Supports the '??' string to ignore certain bytes in the comparison.
 *
 * @param[in] signature A string containing the signature to convert.
 * @param[out] pattern_size A pointer onto where to save the size of the pattern.
 *
 * @return A pattern to be used with the LibreSplit signature scan functions.
 */
uint16_t* convert_signature(const char* signature, size_t* pattern_size)
{
    char* signature_copy = strdup(signature);
    if (!signature_copy) {
        return NULL;
    }

    char* token = strtok(signature_copy, " ");
    if (token == NULL) {
        // Signature is all delimiters or empty
        free(signature_copy);
        return NULL;
    }
    size_t size = 0;
    size_t capacity = 10;
    uint16_t* pattern = (uint16_t*)malloc(capacity * sizeof(uint16_t));
    if (!pattern) {
        free(signature_copy);
        return NULL;
    }

    pattern[size] = 0xFF00; // Set the upper byte to 1 to indicate ignoring this byte
    while (token != NULL) {
        if (size >= capacity) {
            capacity *= 2;
            uint16_t* temp = (uint16_t*)realloc(pattern, capacity * sizeof(uint16_t));
            if (!temp) {
                free(pattern);
                free(signature_copy);
                return NULL;
            }
            pattern = temp;
        }

        if (strstr(token, "?") != NULL) {
            // Treats a half-byte mask as a full-byte mask (0? => ?? or ?F=> ??)
            pattern[size] = 0xFF00; // Set the upper byte to 1 to indicate ignoring this byte
        } else {
            pattern[size] = strtol(token, NULL, 16);
        }
        size++;
        token = strtok(NULL, " ");
    }

    // VPBROADCASTB avx512 instruction
    // 0x6a -> 0x6a6a6a6a6a6a6a6a -> 0x6a6a6a6a6a6a6a6a.....6a (512 bits)
    // starting with wildcards wont work. may be able to rework broad avx match
    // if the first 512bits aren't all wilds (why would they be?)
    __m128i expand_first = _mm_set1_epi8((uint8_t)(pattern[0] & 0xFF));
    first_byte_m512 = _mm512_broadcastb_epi8(expand_first);

    free(signature_copy);
    *pattern_size = size;
    return pattern;
}

bool validate_process_memory(pid_t pid, uintptr_t address, void* buffer, size_t size)
{
    struct iovec local_iov = { buffer, size };
    struct iovec remote_iov = { (void*)address, size };
    ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

    return nread == (ssize_t)size;
}

/**
 * Performs the Lua Auto Splitter sig_scan function, pushing onto the Lua stack the result.
 *
 * If a pattern is found, it will be offset by the process base_address, allowing the result to
 * be used directly in readAddress, without any module definition.
 *
 * Using readAddress with a module name and an address coming from sig_scan is not supported and
 * may result in out-of-process reads or other unforeseen consequences.
 *
 * @param L The lua state.
 *
 * @return Always 1 (one parameter is always pushed on the stack, either the address or nil)
 */
int perform_sig_scan(lua_State* L)
{
    if (lua_gettop(L) != 2) {
        log_error("Invalid number of arguments: expected 2 (signature, offset)");
        lua_pushnil(L);
        return 1;
    }

    if (!lua_isstring(L, 1) || !lua_isnumber(L, 2)) {
        log_error("Invalid argument types: expected (string, number)");
        lua_pushnil(L);
        return 1;
    }

    pid_t p_pid = process.pid;
    const char* signature = lua_tostring(L, 1);
    intptr_t offset = lua_tointeger(L, 2);

    // Validate signature string
    if (strlen(signature) == 0) {
        log_error("Signature string cannot be empty");
        lua_pushnil(L);
        return 1;
    }

    size_t pattern_length;
    uint16_t* pattern = convert_signature(signature, &pattern_length);
    if (!pattern) {
        log_error("Failed to convert signature");
        lua_pushnil(L);
        return 1;
    }

    uint8_t* buffer = NULL;
    uint32_t max_size = 0;

    for (uint32_t i = 0; i < maps_cache_size; i++) {
        max_size = maps_cache[i].size > max_size ? maps_cache[i].size : max_size;
    }

    // alloc once and use for every map region
    buffer = malloc(max_size + 100); // lazy 64 align for rare over-search, should never matter
    if (!buffer) {
        free(pattern);
        log_error("Failed to allocate memory for region(s) buffer");
        lua_pushnil(L);
        return 1;
    }

    for (uint32_t i = 0; i < maps_cache_size; i++) {
        ProcessMap region = maps_cache[i];

        if (!validate_process_memory(p_pid, region.start, buffer, region.size)) {
            continue; // Continue to next region
        }

        uint32_t match_len = 0;
        //printf("           REGSZ = %lu\n", region.size);
        for (size_t j = 0; j <= region.size - pattern_length; j += match_len) {
            match_len = match_pattern(buffer + j, pattern, pattern_length);
            //printf("            DOSKIP64\n");
            //if (match_len > pattern_length) {
            if (match_len > 0x0000FFFF) { // treat as u16[2]
                // The resulting address is the start of the region
                // plus the index of the first byte that matches
                // plus the user-set offset, minus the process's base_address
                // or a subsequent memory read will read the wrong address or
                // go out of memory (due to commit 2b4417f offsetting memory reads)
                // So this result might be negative if the main module happens to be after
                // the found signature. This should be corrected by readAddress.
                ssize_t skip = match_len >> 16; // basically what would have been added to j
                intptr_t result = (region.start + skip + j + offset) - process.base_address;
                printf("           FINOFFSET = %lu\n", skip+j);

                free(buffer);
                free(pattern);

                lua_pushnumber(L, result);
                return 1;
            }
        }
    }

    free(buffer); // not found :(
    free(pattern);

    // No match found
    log_error("No match found for the given signature");
    lua_pushnil(L);
    return 1;
}
