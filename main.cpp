#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <climits>

const char PX20[] = "PX20";
const char PP20[] = "PP20";
const char PPMM[] = "PPMM";

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

static unsigned short read_word(FILE* f) {
    unsigned char b1;
    unsigned char b2;
    fread(&b1, 1, sizeof(b1), f);
    fread(&b2, 1, sizeof(b2), f);

    return (b1 << 8) | b2;
}

static unsigned int read_dword(FILE* f) {
    unsigned int result = read_word(f);
    return (result << 16) | read_word(f);
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
    unsigned int fsize;
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

static long get_file_size(const char* path) {
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
            int new_val = (int)(&src[i] - back);
            int diff = (int)(back - next);

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

static void writeBits(int count, unsigned int value, write_res_t* dst, CrunchInfo* info) {
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

static void writeMoreBits(int count, write_res_t* dst, CrunchInfo* info) {
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

    for (int i = 0; i < (USHRT_MAX + 1); ++i) {
        info->addrs[i] = 0;
    }

    info->dst = info->start;

    info->wnd_off = 0;
    info->wnd_left = info->wnd_max;
    unsigned int max_size = info->wnd_left;

    if (info->wnd_left >= info->fsize) {
        max_size = info->fsize;
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
        int progress = (int)(src_curr - info->print_pos);

        if (progress >= 0x200) {
            info->print_pos += progress;

            if (cb != NULL) {
                cb((unsigned int)(info->print_pos - info->start), (unsigned int)(info->dst - info->start + (res.ptr - info->tmp) * sizeof(unsigned int)), info->fsize);
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

                if (next_src < src_max && *next_src == src_curr[repeats] && next_src >= cmp_src) {
                    next_src = &next_src[1 - repeats];

                    cmp_src = &src_curr[2];
                    unsigned char* cmp_from = &next_src[1];

                    while (cmp_src < src_max && *cmp_src++ == *cmp_from++);
                    cmp_from--;

                    if (src_max < cmp_from) {
                        cmp_src = cmp_src - cmp_from + src_max;
                        cmp_from = src_max;
                    }

                    int curr_repeats = (int)(cmp_src - src_curr - 1);

                    if (repeats < curr_repeats) {
                        int shift = (int)(cmp_from - src_curr - curr_repeats);
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

    int last_size = (int)(res.ptr - info->tmp);

    memcpy(info->dst, info->tmp, last_size * sizeof(unsigned int));
    ((unsigned int*)info->dst)[last_size] = (info->fsize << 8) | (bits & 0xFF);

    return (int)(info->dst - info->start + last_size * sizeof(unsigned int) + sizeof(unsigned int));
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
    info->fsize = len;
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

CrunchInfo* ppAllocCrunchInfo(int eff, int old_version) {
    CrunchInfo* info = (CrunchInfo*)malloc(sizeof(CrunchInfo));

    if (info == NULL) {
        return NULL;
    }

    unsigned char eff_param3 = 10;
    unsigned char eff_param2 = 11;
    unsigned char eff_param1 = 11;

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

    int multiply = old_version ? 2 : 1;

    info->wnd_max = (unsigned int)(1 << eff_param2) * (int)sizeof(unsigned short) * multiply;

    info->wnd1 = (unsigned short*)malloc(info->wnd_max * sizeof(unsigned short) * 2 * multiply);
    info->wnd2 = NULL;

    info->addrs = NULL;
    if (info->wnd1) {
        info->wnd2 = &info->wnd1[info->wnd_max];

        memset(info->wnd1, 0, info->wnd_max * sizeof(unsigned short) * 2 * multiply);

        info->addrs = (unsigned char**)malloc(info->addrs_count * sizeof(unsigned char*));

        if (info->addrs) {
            memset(info->addrs, 0, info->addrs_count * sizeof(unsigned char*));

            return info;
        }
    }

    ppFreeCrunchInfo(info);
    return NULL;
}

int ppWriteDataHeader(int eff, int crypt, unsigned short checksum, unsigned char* table, FILE* dst_h) {
    int error = 0;

    if (crypt) {
        if (fwrite(PX20, 1, sizeof(PX20) - 1, dst_h) != sizeof(PX20) - 1) {
            error = 1;
        }

        if (!error && write_word(dst_h, checksum) != sizeof(checksum)) {
            error = 1;
        }
    }
    else {
        if (!error && fwrite(PP20, 1, sizeof(PP20) - 1, dst_h) != sizeof(PP20) - 1) {
            error = 1;
        }
    }

    if (!error && fwrite(table, 1, 4, dst_h) != 4) {
        error = 1;
    }

    return error;
}

static int compress(const char* src_path, const char* dst_path, unsigned int fsize, CrunchInfo* info, const char* passwd, int eff) {
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
        encrypt((unsigned int*)info->start, (crunched_len / 4) - 1, passkey);
    }

    printf("\n");
    printf("  Normal length   : %d bytes.\n", fsize);
    printf("  Crunched length : %d bytes. (Gained %d%%)\n", crunched_len, (100 - (crunched_len * 100) / fsize));

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

void ppDecrypt(unsigned char* buffer, int size, unsigned int key) {
    for (int i = 0; i < size; i += 4) {
        buffer[i + 0] ^= (key >> 24) & 0xFF;
        buffer[i + 1] ^= (key >> 16) & 0xFF;
        buffer[i + 2] ^= (key >> 8) & 0xFF;
        buffer[i + 3] ^= (key >> 0) & 0xFF;
    }
}

/* the decoder presented here is taken from pplib by Stuart Caie. The
 * following statement comes from the original source.
 *
 * pplib 1.0: a simple PowerPacker decompression and decryption library
 * placed in the Public Domain on 2003-09-18 by Stuart Caie.
 */

#define PP_READ_BITS(nbits, var) do {				\
	bit_cnt = (nbits); (var) = 0;				\
	while (bits_left < bit_cnt) {				\
		if (buf < src) return -1;			\
		bit_buffer |= *--buf << bits_left;		\
		bits_left += 8;					\
	}							\
	bits_left -= bit_cnt;					\
	while (bit_cnt--) {					\
		(var) = ((var) << 1) | (bit_buffer & 1);	\
		bit_buffer >>= 1;				\
	}							\
} while (0)

#define PP_BYTE_OUT(byte) do {					\
	if (out <= dest) return -1;				\
	*--out = (byte); written++;				\
} while (0)

int ppDecrunchBuffer(unsigned char* src, unsigned int src_len, unsigned char* dest, unsigned int dest_len) {
    unsigned char* buf, *out, *dest_end, *off_lens, bits_left = 0, bit_cnt;
    unsigned int bit_buffer = 0, x, todo, offbits, offset, written = 0;

    if (!src || !dest) return -1;

    /* set up input and output pointers */
    off_lens = src; src = &src[4];
    buf = &src[src_len];

    out = dest_end = &dest[dest_len];

    /* skip the first few bits */
    PP_READ_BITS(src[src_len + 3], x);

    /* while there are input bits left */
    while (written < dest_len) {
        PP_READ_BITS(1, x);
        if (x == 0) {
            /* bit==0: literal, then match. bit==1: just match */
            todo = 1; do { PP_READ_BITS(2, x); todo += x; } while (x == 3);
            while (todo--) { PP_READ_BITS(8, x); PP_BYTE_OUT(x); }

            /* should we end decoding on a literal, break out of the main loop */
            if (written == dest_len) break;
        }

        /* match: read 2 bits for initial offset bitlength / match length */
        PP_READ_BITS(2, x);
        offbits = off_lens[x];
        todo = x + 2;
        if (x == 3) {
            PP_READ_BITS(1, x);
            if (x == 0) offbits = 7;
            PP_READ_BITS(offbits, offset);
            do { PP_READ_BITS(3, x); todo += x; } while (x == 7);
        }
        else {
            PP_READ_BITS(offbits, offset);
        }
        if (&out[offset] >= dest_end) return -1; /* match_overflow */
        while (todo--) { x = out[offset]; PP_BYTE_OUT(x); }
    }

    /* all output bytes written without error */
    return 0;
}

typedef struct {
    unsigned int tag;
    unsigned char* src;
    unsigned int src_len;
    unsigned char* dst;
    unsigned int dst_len;
} decrunch_t;

int ppLoadData(const char* filename, decrunch_t** bufferptr, const char* passwd) {
    *bufferptr = NULL;

    FILE* f = fopen(filename, "rb");

    if (f == NULL) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    unsigned int buf_len = (unsigned int)ftell(f);
    fseek(f, 0, SEEK_SET);

    if (buf_len == 0) {
        fclose(f);
        return -1;
    }

    char tag[4];

    if (fread(tag, 1, sizeof(tag), f) != sizeof(tag)) {
        fclose(f);
        return -1;
    }

    unsigned int dest_len = 0;
    unsigned int read_len = 0;
    int offset = 4;
    unsigned short checksum = 0;

    if (!memcmp(PP20, tag, sizeof(tag))) {
        fseek(f, -4, SEEK_END);

        dest_len = read_dword(f);

        read_len = buf_len - offset + sizeof(decrunch_t);
        dest_len = (dest_len >> 8);
    }
    else if (!memcmp(PX20, tag, sizeof(tag))) {
        checksum = read_word(f);
        offset += 2;

        fseek(f, -4, SEEK_END);

        dest_len = read_dword(f);

        read_len = buf_len - offset + sizeof(decrunch_t);
        dest_len = (dest_len >> 8);
    }
    else {
        fclose(f);
        return -1;
    }

    unsigned char* buffer = (unsigned char*)malloc(read_len);
    memset(buffer, 0, read_len);

    if (buffer == NULL) {
        fclose(f);
        return -1;
    }

    fseek(f, offset, SEEK_SET);

    if (fread(&buffer[sizeof(decrunch_t)], 1, read_len - sizeof(decrunch_t), f) != read_len - sizeof(decrunch_t)) {
        fclose(f);
        free(buffer);
        return -1;
    }

    fclose(f);

    decrunch_t* info = (decrunch_t*)buffer;
    *bufferptr = info;
    info->src = &buffer[sizeof(decrunch_t)];

    if (offset == 6) {
        if ((passwd == NULL) || (strlen(passwd) > 16)) {
            fclose(f);
            free(buffer);
            return -1;
        }

        if (ppCalcChecksum(passwd) != checksum) {
            fclose(f);
            free(buffer);
            return -1;
        }

        unsigned int key = ppCalcPasskey(passwd);
        ppDecrypt(&info->src[4], read_len - sizeof(decrunch_t) - 8, key);
    }

    memcpy(&info->tag, PPMM, sizeof(PPMM));
    info->src_len = read_len - sizeof(decrunch_t);
    info->dst_len = dest_len;

    info->dst = (unsigned char*)malloc(dest_len);

    if (info->dst == NULL) {
        return -1;
    }

    return ppDecrunchBuffer(info->src, read_len - sizeof(decrunch_t) - 8, info->dst, dest_len);
}

static void print_help() {
    printf(
        "  Crunch: powerpack <source> <destination> <-c> [-e=EFFICIENCY] [-p=PASSWORD] [-o] [-h]\n"
        "Decrunch: powerpack <source> <destination> <-d> [-p=PASSWORD] [-h]\n"
        "With:\n"
        "          -c: Crunch (compress)\n"
        "          -d: Decrunch (decompress)\n"
        "  EFFICIENCY: 1 = Fast, 2 = Mediocre, 3 = Good (def), 4 = Very Good, 5 = Best\n"
        "    PASSWORD: Encrypt/decrypt file. Max 16 characters\n"
        "          -o: Use it to compress with the old PP alorithm.\n"
        "              The difference in the size of a window:\n"
        "              - Old version: 0x4000\n"
        "              - New version: 0x8000\n"
        "          -h: Show this help\n\n"
    );
}

int main(int argc, char* argv[]) {
    printf("POWER-PACKER 36.10 (28.9.93) Data Cruncher.\n");
    printf(u8"  Written by Nico François (POWER PEAK)\n");
    printf("  Decompiled by Dr. MefistO in 2020\n");
    printf("  Version: v1.0\n\n");

    if (argc < 2) {
        print_help();
        return -1;
    }

    char passwd[17];
    memset(passwd, 0, sizeof(passwd));

    int old_version = 0;
    int eff = 3;
    int i = 3;
    int mode = -1;

    while (i < argc) {
        if (((argv[i][0] == '-') || (argv[i][0] == '/'))) {
            switch (argv[i][1]) {
            case 'c': {
                mode = 0;
            } break;
            case 'd': {
                mode = 1;
            } break;
            case 'h':
                print_help();
                return 0;
            case 'e': {
                if (sscanf(&argv[i][3], "%d", &eff) != 1) {
                    return -1;
                }
            } break;
            case 'p': {
                if (sscanf(&argv[i][3], "%16s", passwd) != 1) {
                    return -1;
                }
            } break;
            case 'o': {
                old_version = 1;
                break;
            }
            }
        }

        i++;
    }

    if (mode == -1) {
        printf("Incorrect mode. Please, use '-c' to crunch or '-d' to decrunch\n\n");
        print_help();
        return -1;
    }

    int result = -1;

    if (mode == 0) {
        CrunchInfo* info = ppAllocCrunchInfo(eff, old_version);

        unsigned int fsize = get_file_size(argv[1]);

        result = compress(argv[1], argv[2], fsize, info, passwd[0] != 0 ? passwd : NULL, eff);
        ppFreeCrunchInfo(info);
        printf("\nDone.\n");
    }
    else {
        decrunch_t* info;

        result = ppLoadData(argv[1], &info, passwd[0] != 0 ? passwd : NULL);

        if (info == NULL) {
            printf("Cannot decrunch '%s'!\n", argv[1]);
            return -1;
        }

        FILE* dst_h = fopen(argv[2], "wb");

        if (dst_h == NULL) {
            printf("Cannot open '%s' for write!\n", argv[2]);
            free(info);
            return -1;
        }

        if (fwrite(info->dst, 1, info->dst_len, dst_h) != info->dst_len) {
            printf("Cannot write to '%s'!\n", argv[2]);
            result = -1;
        }

        printf("Successfully decrunched '%s' into '%s'\n", argv[1], argv[2]);
        printf("Result: %d -> %d bytes\n", info->src_len, info->dst_len);

        free(info);
        fclose(dst_h);
    }

    return result;
}
