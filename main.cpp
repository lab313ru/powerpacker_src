#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PX20 "PX20"
#define PP20 "PP20"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static inline unsigned int rol(unsigned int n, int c)
{
    const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);  // assumes width is a power of 2.
    c &= mask;
    return (n << c) | (n >> ((-c) & mask));
}

static inline unsigned short ror(unsigned short n, int c)
{
    const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
    c &= mask;
    return (n >> c) | (n << ((-c) & mask));
}

unsigned int ppCalcPasskey(const char* passwd) {
    unsigned int result = 0;

    while (*passwd) {
        result = rol(result, 1);
        result += passwd[0];
        result = ((result & 0xFFFF0000) >> 16) | ((result & 0x0000FFFF) << 16);
        passwd++;
    }

    return result;
}

unsigned short ppCalcChecksum(const char* passwd) {
    unsigned short result = 0;

    while (*passwd) {
        result = ror(result, passwd[0]);
        result += passwd[0];
        passwd++;
    }

    return result;
}

static void encrypt(unsigned int* tmp, int size, unsigned int passwd) {
    for (int i = 0; i < size; ++i) {
        *tmp++ ^= passwd;
    }
}

static size_t write_word(FILE* f, unsigned short v) {
    unsigned char b1 = (v >> 8) & 0xFF;
    unsigned char b2 = (v >> 0) & 0xFF;
    size_t result = fwrite(&b1, 1, sizeof(b1), f);
    return result + fwrite(&b2, 1, sizeof(b2), f);
}

static size_t write_dwords(FILE* f, unsigned int* buf, int count) {
    size_t result = 0;
    
    for (int i = 0; i < count / 4; ++i) {
        result += write_word(f, (buf[i] >> 16) & 0xFFFF);
        result += write_word(f, (buf[i] >> 0) & 0xFFFF);
    }

    return result;
}

typedef struct {
    unsigned int token;
    unsigned int* ptr;
    unsigned int* ptr_max;
} write_res_t;

typedef struct {
    unsigned short w00[4];
    unsigned short w08[4];
    unsigned short w10[4];
    unsigned char b2C[4];
    unsigned char* start;
    unsigned int len;
    unsigned char* src_end;

    unsigned char** addrs;
    unsigned int addrs_count;
    unsigned char* dst;
    unsigned int tmp[0x80];
    unsigned char* print_pos;

    unsigned short value;
    unsigned short bits;

    unsigned short* wnd1;
    unsigned short* wnd2;
    unsigned short wnd_max;
    unsigned short wnd_off;
    unsigned short wnd_left;
} CrunchInfo;

long get_file_size(const char* path) {
    FILE* f = fopen(path, "rb");

    if (f == NULL) {
        return 0;
    }

    fseek(f, 0, SEEK_END);

    long size = ftell(f);

    fclose(f);

    return size;
}

static unsigned char* updateSpeedupLarge(unsigned char* curr, unsigned char* next, int count, CrunchInfo* info) {
    unsigned char* src = &curr[info->wnd_max];

    for (int i = 0; i < count; ++i) {
        if (&src[i] >= (info->src_end - 1)) {
            continue;
        }

        unsigned short val = (src[i + 0] << 8) | src[i + 1];
        unsigned char* back = info->addrs[val];

        if (back != NULL) {
            int new_val = &src[i] - back;
            int diff = back - next;

            //printf("%d %d\n", new_val, diff);

            if (diff >= 0 && new_val < info->wnd_max / sizeof(unsigned short)) {
                if (diff >= info->wnd_left) {
                    diff -= info->wnd_max;
                }

                info->wnd1[info->wnd_off + diff] = new_val;
                info->wnd2[info->wnd_off + diff] = new_val;
            }
        }

        info->addrs[val] = &src[i];
    }

    return &src[count] - info->wnd_max;
}

static void writeBits(unsigned short count, unsigned int value, write_res_t* dst, CrunchInfo* info) {
    for (int i = 0; i < count; ++i) {
        int bit = value & 1;
        value >>= 1;

        unsigned int c = dst->token & 0x80000000;
        dst->token = (dst->token << 1) | bit;

        if (c != 0) {
            //printf("%08X\n", dst->token);
            dst->ptr[0] = dst->token;
            dst->ptr++;
            dst->token = 1;

            if (dst->ptr >= dst->ptr_max) {
                memcpy(info->dst, info->tmp, 0x200);
                info->dst = &info->dst[0x200];
                dst->ptr = info->tmp;
            }
        }
    }
}

static void writeMoreBits(unsigned int count, write_res_t* dst, CrunchInfo* info) {
    if (count < 4) {
        writeBits(2, count - 1, dst, info);
    }
    else {
        writeBits(2, (count - 4) % 3, dst, info);

        for (int i = 0; i < (count - 4) / 3 + 1; ++i) {
            writeBits(2, 3, dst, info);
        }
    }

    writeBits(1, 0, dst, info);
}

static void prepareDict(int repeats, CrunchInfo* info) {
    for (int i = 0; i < repeats; ++i) {
        info->wnd1[info->wnd_off] = 0;
        info->wnd2[info->wnd_off++] = 0;

        info->wnd_left--;
        if (info->wnd_left == 0) {
            info->wnd_left = info->wnd_max;
            info->wnd_off = 0;
        }
    }
}

typedef void (*progress_cb)(unsigned int src_off, unsigned int dst_off, unsigned int fsize);

static int ppCrunchBuffer_sub(progress_cb cb, CrunchInfo* info) {
    for (int i = 0; i < info->wnd_max; ++i) {
        info->wnd1[i] = 0;
        info->wnd2[i] = 0;
    }

    for (int i = 0; i < info->addrs_count; ++i) {
        info->addrs[i] = 0;
    }

    info->dst = info->start;
    unsigned int fsize = info->src_end - info->start;

    info->wnd_off = 0;
    info->wnd_left = info->wnd_max;
    unsigned int max_size = info->wnd_left;

    if (info->wnd_left >= fsize) {
        max_size = fsize;
    }

    updateSpeedupLarge(&info->start[-info->wnd_max], info->start, max_size, info);

    info->print_pos = info->start;
    unsigned char* src_curr = info->start;

    write_res_t res;
    res.ptr = info->tmp;
    res.ptr_max = &info->tmp[0x80];
    res.token = 1;

    int bits = 0;

    while (src_curr < info->src_end) { // check_end
        int progress = src_curr - info->print_pos;

        if (progress >= 0x200) {
            info->print_pos += progress;

            if (cb != NULL) {
                cb(info->print_pos - info->start, info->dst - info->start + (res.ptr - info->tmp) * sizeof(unsigned int), info->len);
                //printf("%08X\n", res.token);
            }
        }

        unsigned char* src_max = &src_curr[0x7FFF];

        if (src_max >= info->src_end) {
            src_max = info->src_end;
        }

        int repeats = 1;
        unsigned char* next_src = &src_curr[1];
        unsigned char* cmp_src = NULL;
        unsigned short wnd_off_ = info->wnd_off;
        int bits_ = bits;
        unsigned int token_ = res.token;

        while (1) { // main_loop
            next_src = &next_src[repeats - 1];
            cmp_src = &cmp_src[repeats - 1];

            int skip = 0;

            while (info->wnd1[info->wnd_off]) {
                int off = info->wnd1[info->wnd_off];

                next_src = &next_src[off];
                info->wnd_off = (info->wnd_off + off);

                if (&next_src[1 - repeats] < src_max && *next_src == src_curr[repeats] && next_src >= cmp_src) {
                    next_src = &next_src[1 - repeats];

                    cmp_src = &src_curr[2];
                    unsigned char* cmp_from = &next_src[1];

                    while (*cmp_src++ == *cmp_from++);
                    cmp_from--;

                    if (src_max < cmp_from) {
                        cmp_src = cmp_src - cmp_from + src_max;
                        cmp_from = src_max;
                    }

                    int curr_repeats = cmp_src - src_curr - 1;

                    if (repeats < curr_repeats) {
                        int shift = cmp_from - src_curr - curr_repeats;
                        unsigned short curr_bits = 3;

                        if (curr_repeats < 5) {
                            curr_bits = curr_repeats - 2;
                        }

                        if (info->w08[curr_bits] >= shift) {
                            repeats = curr_repeats;
                            res.token = (res.token & 0xFFFF0000) | (shift & 0xFFFF);
                            bits = curr_bits;
                        }
                    }

                    skip = 1;
                    break; // main_loop
                }
            }

            if (skip) {
                continue; // main_loop
            }

            // set_token
            info->value = res.token & 0xFFFF;
            info->bits = bits;
            info->wnd_off = wnd_off_;
            bits = bits_;
            res.token = token_;

            if (repeats == 1) {
                writeBits(8, src_curr[0], &res, info);
                bits++;

                prepareDict(1, info);
                src_curr = updateSpeedupLarge(src_curr, &src_curr[1], 1, info);
            }
            else {
                if (repeats < info->wnd_max) {
                    prepareDict(repeats, info);
                    src_curr = updateSpeedupLarge(src_curr, &src_curr[repeats], repeats, info);
                }
                else {
                    src_curr = &src_curr[repeats];

                    info->wnd_off = 0;
                    info->wnd_left = info->wnd_max;

                    for (int i = 0; i < info->wnd_max; ++i) {
                        info->wnd1[info->wnd_off] = 0;
                        info->wnd2[info->wnd_off++] = 0;
                    }

                    info->wnd_off = 0;
                    info->wnd_left = info->wnd_max;

                    src_curr = updateSpeedupLarge(&src_curr[-info->wnd_left], src_curr, info->wnd_left, info);
                }

                if (bits == 0) {
                    writeBits(1, 1, &res, info);
                }
                else {
                    writeMoreBits(bits, &res, info);
                    bits = 0;
                }

                if (repeats >= 5) {
                    if (repeats < 12) {
                        writeBits(3, repeats - 5, &res, info);
                    }
                    else {
                        writeBits(3, (repeats - 12) % 7, &res, info);

                        for (int i = 0; i < ((repeats - 12) / 7) + 1; ++i) {
                            writeBits(3, 7, &res, info);
                        }
                    }
                }

                unsigned short bits_count = info->bits;
                unsigned short value = info->value - 1;
                int count = 1;

                if (repeats >= 5) {
                    if (value >= 0x80) {
                        writeBits(info->w00[bits_count], value, &res, info);
                        value = 1;
                    }
                    else {
                        writeBits(7, value, &res, info);
                        value = 0;
                    }
                }
                else {
                    count = info->w00[bits_count];
                }

                writeBits(count, value, &res, info);
                writeBits(2, info->w10[bits_count], &res, info);
            }

            break; // check_end
        }
    }

    writeMoreBits(bits, &res, info);

    bits = 0;

    if (res.token != 1) {
        int bit = 0;

        while (!bit) {
            bits++;
            bit = res.token & 0x80000000;
            res.token <<= 1;
        }

        // here the original cruncher uses a pointer to the source data end
        // I decided to use hardcoded dword
        unsigned int address = 0x00000000;
        unsigned int last_token = 0;
        for (int i = 0; i < bits; ++i) {
            bit = address & 1;
            address >>= 1;
            last_token = (last_token << 1) | bit;
        }

        last_token |= res.token;
        res.ptr[0] = last_token;
        res.ptr++;
    }

    int last_size = res.ptr - info->tmp;

    memcpy(info->dst, info->tmp, last_size * sizeof(unsigned int));
    ((unsigned int*)info->dst)[last_size] = (fsize << 8) | (bits & 0xFF);

    return info->dst - info->start + (last_size + 1) * sizeof(unsigned int);
}

static void print_progress(unsigned int src_off, unsigned int dst_off, unsigned int fsize) {
    if (src_off == 0) {
        return;
    }

    unsigned int crunched = (src_off * 100) / fsize;
    unsigned int gain = (dst_off * 100) / src_off;

    printf("\r%u%% crunched. (%u%% gain)   ", crunched, 100 - gain);
}

int ppCrunchBuffer(unsigned int len, unsigned char* buf, CrunchInfo* info) {
    info->start = buf;
    info->len = len;
    info->src_end = &buf[len];

    return ppCrunchBuffer_sub(print_progress, info);
}

void ppFreeCrunchInfo(CrunchInfo* info) {
    if (info == NULL) {
        return;
    }

    if (info->addrs != NULL) {
        free(info->addrs);
    }

    free(info->wnd1);
    free(info);
}

CrunchInfo* ppAllocCrunchInfo(int eff) {
    CrunchInfo* info = (CrunchInfo*)malloc(sizeof(CrunchInfo));

    if (info == NULL) {
        return NULL;
    }

    unsigned short eff_param3 = 10;
    unsigned short eff_param2 = 11;
    unsigned short eff_param1 = 11;

    switch (eff) {
    case 1:
        eff_param2 = 9;
        eff_param1 = 9;
        eff_param3 = 9;
        break;
    case 2:
        eff_param2 = 10;
        eff_param1 = 10;
    case 3:
        break;
    case 4:
        eff_param2 = 12;
        eff_param1 = 12;
        break;
    case 5:
        eff_param1 = 12;
        eff_param2 = 13;
        break;
    }

    info->w00[0] = info->b2C[0] = 9;
    info->w00[1] = info->b2C[1] = eff_param3;
    info->w00[2] = info->b2C[2] = eff_param1;
    info->w00[3] = info->b2C[3] = eff_param2;

    info->w08[0] = (1 << 9);
    info->w08[1] = (1 << eff_param3);
    info->w08[2] = (1 << eff_param1);
    info->w08[3] = (1 << eff_param2);

    info->w10[0] = 0;
    info->w10[1] = 1;
    info->w10[2] = 2;
    info->w10[3] = 3;

    info->addrs_count = 0x10000;

    info->wnd_max = (1 << eff_param2) * sizeof(unsigned short);

    info->wnd1 = (unsigned short*)malloc(info->wnd_max * sizeof(unsigned short) * 2);
    info->wnd2 = &info->wnd1[info->wnd_max];

    info->addrs = NULL;
    if (info->wnd1) {
        memset(info->wnd1, 0, info->wnd_max * sizeof(unsigned short) * 2);

        info->addrs = (unsigned char**)malloc(info->addrs_count * sizeof(unsigned char*));

        if (info->addrs) {
            memset(info->addrs, 0, info->addrs_count * sizeof(unsigned char*));

            return info;
        }
    }

    ppFreeCrunchInfo(info);
    return NULL;
}

int ppWriteDataHeader(int eff, int crypt, unsigned int checksum, unsigned char* table, FILE* dst_h) {
    int error = 0;

    if (crypt) {
        if (fwrite(PX20, 1, 4, dst_h) != 4) {
            error = 1;
        }

        if (!error && write_word(dst_h, checksum) != sizeof(checksum)) {
            error = 1;
        }
    }
    else {
        if (!error && fwrite(PP20, 1, 4, dst_h) != 4) {
            error = 1;
        }
    }

    if (!error && fwrite(table, 1, 4, dst_h) != 4) {
        error = 1;
    }

    return error;
}

int compress(const char* src_path, const char* dst_path, unsigned int fsize, CrunchInfo* info, const char* passwd, int eff) {
    if (fsize == 0) {
        return -1;
    }

    FILE* src_h = fopen(src_path, "rb");

    if (src_h == NULL) {
        printf("Can't open '%s' file!\n", src_path);
        return -1;
    }

    info->start = (unsigned char*)malloc(fsize);

    if (info->start == NULL) {
        printf("No memory to crunch '%s'!\n", src_path);
        fclose(src_h);
        return -1;
    }

    if (fread(info->start, 1, fsize, src_h) < fsize) {
        printf("Error reading '%s'!\n", src_path);
        fclose(src_h);
        free(info->start);
        return -1;
    }

    fclose(src_h);

    unsigned int passkey = 0;
    unsigned short checksum = 0;

    if (passwd) {
        passkey = ppCalcPasskey(passwd);
        checksum = ppCalcChecksum(passwd);
    }

    printf("Crunching '%s'...\n", src_path);

    int crunched_len = ppCrunchBuffer(fsize, info->start, info);

    if (crunched_len == -1) {
        free(info->start);
        remove(dst_path);
        printf("Buffer overflow!\n");
        return -1;
    }

    printf("\n");

    if (passwd) {
        printf("Encrypting...\n");
        encrypt((unsigned int*)info->start, (crunched_len / 4)  - 1, passkey);
    }

    printf("\n");
    printf("  Normal length   : %d bytes.\n", fsize);
    printf("  Crunched length : %d bytes. " ANSI_COLOR_YELLOW "(Gained %d%%)" ANSI_COLOR_RESET "\n", crunched_len, (100 - (crunched_len * 100) / fsize));

    FILE* dst_h = fopen(dst_path, "wb");

    if (dst_h == NULL) {
        printf("Can't open '%s' file!\n", dst_path);
        free(info->start);
        return -1;
    }

    int error = ppWriteDataHeader(eff, passwd != NULL, checksum, info->b2C, dst_h);

    if (error) {
        printf("Error writing to '%s'!\n", dst_path);
        free(dst_h);
        free(info->start);
        return -1;
    }

    if (!error && write_dwords(dst_h, (unsigned int*)info->start, crunched_len) != crunched_len) {
        error = 1;
    }

    fclose(dst_h);
    free(info->start);

    if (error) {
        printf("Error writing to '%s'!\n", dst_path);
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    printf(ANSI_COLOR_GREEN "POWER-PACKER 2.3a" ANSI_COLOR_RESET " Data Cruncher.\n");
    printf(ANSI_COLOR_RED "  Written by Nico François (POWER PEAK)" ANSI_COLOR_RESET "\n");

    if (argc < 2) {
        printf("Usage : Crunch <source> <destination> [-e=EFFICIENCY] [-c]\n"
            "With:\n"
            "  EFFICIENCY: 1 = Fast, 2 = Mediocre, 3 = Good (def), 4 = Very Good, 5 = Best\n"
            "  -c        : Encrypt file.\n\n"
        );
        return -1;
    }

    char passwd[17];
    memset(passwd, 0, sizeof(passwd));

    int eff = 3;
    int i = 3;
    while (i < argc) {
        if (((argv[i][0] == '-') || (argv[i][0] == '/'))) {
            switch (argv[i][1]) {
            case 'e': {
                sscanf(&argv[i][3], "%d", &eff);
            } break;
            case 'c': {
                sscanf(&argv[i][3], "%16s", passwd);
            } break;
            }
        }

        i++;
    }

    CrunchInfo* info = ppAllocCrunchInfo(eff);

    unsigned int fsize = get_file_size(argv[1]);

    int result = compress(argv[1], argv[2], fsize, info, passwd[0] != 0 ? passwd : NULL, eff);
    printf("\n" ANSI_COLOR_BLUE "Done." ANSI_COLOR_RESET "\n");

    ppFreeCrunchInfo(info);

    return result;
}
