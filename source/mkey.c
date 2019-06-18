/*
 * mkey - parental controls master key generator for certain video game consoles
 * Copyright (C) 2015-2019, Daz Jones (Dazzozo) <daz@dazzozo.com>
 * Copyright (C) 2015-2019, SALT
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mkey.h"

#include "types.h"
#include "utils.h"

#include "ctr.h"
#include "polarssl/sha2.h"

const char mkey_devices[][4] = {"RVL", "TWL", "CTR", "WUP", "HAC"};
const char* mkey_default_device = "CTR";

int mkey_num_devices(void)
{
    return sizeof(mkey_devices) / sizeof(*mkey_devices);
}

typedef struct {
    u32 poly;
    u32 xorout;
    u32 addout;
} mkey_v0_props;

typedef struct {
    const char* hmac_file;
} mkey_v1_props;

typedef struct {
    bool no_versions;
    const char* mkey_file;
    const char* aes_file;
} mkey_v2_props;

typedef struct {
    const char* hmac_file;
} mkey_v3_props;

typedef struct {
    const char* hmac_file;
} mkey_v4_props;

typedef struct {
    const char* device;
    u32 algorithms;

    bool big_endian;

    mkey_v0_props v0;
    mkey_v1_props v1;
    mkey_v2_props v2;
    mkey_v3_props v3;
    mkey_v4_props v4;
} mkey_props;

typedef struct {
    mkey_ctx* ctx;

    const char* device;
    const mkey_props* props;
    int algorithm;
} mkey_session;

static const mkey_props _props[sizeof(mkey_devices) / sizeof(*mkey_devices)] =
{
    [0] =
    {
        .device = mkey_devices[0],
        .algorithms = 0b00001,
        .big_endian = true,
        .v0 = {
            .poly = 0xEDB88320,
            .xorout = 0xAAAA,
            .addout = 0x14C1,
        },
    },

    [1] =
    {
        .device = mkey_devices[1],
        .algorithms = 0b00001,
        .v0 = {
            .poly = 0xEDB88320,
            .xorout = 0xAAAA,
            .addout = 0x14C1,
        },
    },

    [2] =
    {
        .device = mkey_devices[2],
        .algorithms = 0b00111,
        .v0 = {
            .poly = 0xEDBA6320,
            .xorout = 0xAAAA,
            .addout = 0x1657,
        },
        .v1 = {
            .hmac_file = "ctr_%02"PRIx8".bin",
        },
        .v2 = {
            .mkey_file = "ctr_%02"PRIx8"_%02"PRIx8".bin",
            .aes_file = "ctr_aes_%02"PRIx8".bin",
        },
    },

    [3] =
    {
        .device = mkey_devices[3],
        .algorithms = 0b00101,
        .big_endian = true,
        .v0 = {
            .poly = 0xEDBA6320,
            .xorout = 0xAAAA,
            .addout = 0x1657,
        },
        .v2 = {
            .no_versions = true,
            .mkey_file = "wup_%02"PRIx8".bin",
            .aes_file = "wup_aes_%02"PRIx8".bin",
        },
    },

    [4] =
    {
        .device = mkey_devices[4],
        .algorithms = 0b11000,
        .v3 = {
            .hmac_file = "hac_%02"PRIx8".bin",
        },
        .v4 = {
            .hmac_file = "hac_%02"PRIx8".bin",
        },
    },
};

static const mkey_props* mkey_get_props(const char* device)
{
    for(int i = 0; i < mkey_num_devices(); i++) {
        if(!strcmp(device, _props[i].device))
            return &_props[i];
    }

    return NULL;
}

static int mkey_detect_algorithm(mkey_session* session, const char* inquiry_number)
{
    mkey_ctx* ctx = session->ctx;
    const mkey_props* props = session->props;

    u64 inquiry = strtoull(inquiry_number, 0, 10);

    if(strlen(inquiry_number) == 8) {
        if(props->algorithms & BIT(0))
            return 0;
        else {
            if(ctx->dbg) printf("Error: v0 algorithm not supported by %s.\n", session->device);
            return -1;
        }
    }

    else if(strlen(inquiry_number) == 10) {
        u8 version = (inquiry / 10000000) % 100;
        if(props->algorithms & BIT(1) && version < 10)
            return 1;
        else if (props->algorithms & BIT(2))
            return 2;
        else if (props->algorithms & BIT(3))
            return 3;
        else {
            if(ctx->dbg) printf("Error: v1/v2/v3 algorithms not supported by %s.\n", session->device);
            return -1;
        }
    }

    else if(strlen(inquiry_number) == 6) {
        if(props->algorithms & BIT(4))
            return 4;
        else {
            if(ctx->dbg) printf("Error: v4 algorithm not supported by %s.\n", session->device);
            return -1;
        }
    }

    else {
        if(ctx->dbg) printf("Error: inquiry number must be 6, 8 or 10 digits.\n");
        return -2;
    }
}

static u32 mkey_calculate_crc(u32 poly, u32 xorout, u32 addout, const void* inbuf, size_t size);

static int mkey_generate_v0(mkey_session* session, u64 inquiry, u8 month, u8 day, char* master_key)
{
    mkey_ctx* ctx = session->ctx;
    const mkey_props* props = session->props;

    u32 poly = props->v0.poly;
    u32 xorout = props->v0.xorout;
    u32 addout = props->v0.addout;

    // Create the input buffer.
    char inbuf[9] = {0};
    snprintf(inbuf, sizeof(inbuf), "%02"PRIu8 "%02"PRIu8 "%04"PRIu64, month, day, inquiry % 10000);

    if(ctx->dbg) {
        printf("CRC polynomial: 0x%08"PRIX32".\n", poly);
        printf("CRC xor-out:    0x%"PRIX32".\n", xorout);
        printf("CRC add-out:    0x%"PRIX32".\n", addout);

        printf("\nCRC input:\n");
        hexdump(inbuf, strlen(inbuf));
    }

    u32 output = mkey_calculate_crc(poly, xorout, addout, (u8*)inbuf, strlen(inbuf));

    if(ctx->dbg) printf("\nOutput word: %"PRIu32".\n", output);

    // Truncate to 5 decimal digits to form the final master key.
    snprintf(master_key, 10, "%05d", output % 100000);

    return 0;
}

static int mkey_read_aes_key(mkey_session* session, const char* file_name, void* out);
static int mkey_read_mkey_file(mkey_session* session, const char* file_name, void* out);
static int mkey_read_hmac_key(mkey_session* session, const char* file_name, void* out);

static int mkey_generate_v1_v2(mkey_session* session, u64 inquiry, u8 month, u8 day, char* master_key)
{
    int ret = 0;
    mkey_ctx* ctx = session->ctx;
    const mkey_props* props = session->props;

    struct stat st;
    if(!ctx->data_path_set || stat(ctx->data_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if(ctx->dbg) printf("v1/v2 attempted, but data directory doesn't exist or was not specified.\n");
        return -1;
    }

    mkey_data data = {0};
    u8 aes_key[0x10] = {0};

    /*
     * Extract key ID fields from inquiry number.
     * If this system uses masterkey.bin, there is an AES key for the region which is also required.
     * This key is used to decrypt the encrypted HMAC key stored in masterkey.bin. See below.
     */
    u8 region = (inquiry / 1000000000) % 10;
    u8 version = (inquiry / 10000000) % 100;

    char file_name[MAX_PATH] = {0};

    /*
    * The v2 algorithm uses a masterkey.bin file that can be updated independently of the rest of the system,
    * avoiding the need for recompiling the parental controls application. The format consists of an ID field,
    * used to identify the required key files for the user's inquiry number, a HMAC key encrypted using AES-128-CTR,
    * and the AES counter value for decrypting it.
    * Obviously, what is missing from this list is the AES key itself, unique to each region, which is usually
    * hardcoded within the parental controls application (i.e. .rodata).
    *
    * The 3DS implementation stores the masterkey.bin file in the CVer title, which is updated anyway for every
    * system update (it also contains the user-facing system version number). The AES key is stored in mset
    * (System Settings) .rodata.
    *
    * The Wii U implementation does away with the masterkey.bin versioning, and uses a masterkey.bin that does
    * not change between system versions (though still between regions). This comes from a dedicated title for
    * each region that is still at v0. The Wii U AES keys are stored in pcl (Parental Controls) .rodata.
    * As a result, the unused ("version") digits in the inquiry number are extra console-unique filler
    * (derived from MAC address).
     */
    if(session->algorithm == 2) {
        if(props->v2.no_versions)
            snprintf(file_name, sizeof(file_name), props->v2.mkey_file, region);
        else
            snprintf(file_name, sizeof(file_name), props->v2.mkey_file, region, version);

        ret = mkey_read_mkey_file(session, file_name, &data);
        if(ret) return -2;

        snprintf(file_name, sizeof(file_name), props->v2.aes_file, region);
        ret = mkey_read_aes_key(session, file_name, aes_key);
        if(ret) return -2;
    }
    /*
     * The 3DS-only v1 algorithm uses a raw HMAC key stored in mset .rodata.
     * No encryption is used for this. Similar to v2 on Wii U, the version field is unused.
     * The unused ("version") digits again are extra console-unique filler (derived from MAC address).
     * This was short-lived, and corresponds to system versions 7.0.0 and 7.1.0.
     */
    else {
        snprintf(file_name, sizeof(file_name), props->v1.hmac_file, region);
        ret = mkey_read_hmac_key(session, file_name, data.hmac_key);
        if(ret) return -2;
    }

    /*
     * If v2, we must decrypt the HMAC key using an AES key from .rodata.
     * The HMAC key is encrypted in masterkey.bin (offset 0x20->0x40) using AES-128-CTR.
     * The counter is also stored in masterkey.bin (offset 0x10->0x20).
     */
    if(session->algorithm == 2) {
        // Verify the region field.
        if(data.region != region) {
            if(ctx->dbg) {
                printf("Error: %s has an incorrect region field (expected 0x%02"PRIX8", got 0x%02"PRIX8").\n",
                    file_name, region, data.region);
            }

            return -3;
        }

        // Verify the version field.
        if(data.version != version && !props->v2.no_versions) {
            if(ctx->dbg) {
                printf("Error: %s has an incorrect version field (expected 0x%02"PRIX8", got 0x%02"PRIX8").\n",
                    file_name, version, data.version);
            }

            return -3;
        }

        if(ctx->dbg) {
            printf("\nAES key:\n");
            hexdump(aes_key, sizeof(aes_key));

            printf("\nAES counter:\n");
            hexdump(data.ctr, sizeof(data.ctr));

            printf("\nEncrypted HMAC key:\n");
            hexdump(data.hmac_key, sizeof(data.hmac_key));
        }

        // Decrypt the HMAC key.
        ctr_aes_context aes;
        ctr_init_counter(&aes, aes_key, data.ctr);
        ctr_crypt_counter(&aes, data.hmac_key, data.hmac_key, sizeof(data.hmac_key));
    }

    // Create the input buffer.
    char inbuf[15] = {0};
    snprintf(inbuf, sizeof(inbuf), "%02"PRIu8 "%02"PRIu8 "%010"PRIu64, month, day, inquiry % 10000000000);

    if(ctx->dbg) {
        printf("\nHMAC key:\n");
        hexdump(data.hmac_key, sizeof(data.hmac_key));

        printf("\nHash input:\n");
        hexdump(inbuf, strlen(inbuf));
    }

    u8 outbuf[0x20] = {0};
    sha2_hmac(data.hmac_key, sizeof(data.hmac_key), (u8*)inbuf, strlen(inbuf), outbuf, false);

    if(ctx->dbg) {
        printf("\nHash output:\n");
        hexdump(outbuf, sizeof(outbuf));
    }

    u32 output = 0;

    // Wii U is big endian.
    if(props->big_endian)
        output = getbe32(outbuf);
    else
        output = getle32(outbuf);

    if(ctx->dbg) printf("\nOutput word: %"PRIu32".\n", output);

    // Truncate to 5 decimal digits to form the final master key.
    snprintf(master_key, 10, "%05d", output % 100000);

    return 0;
}

static int mkey_generate_v3_v4(mkey_session* session, u64 inquiry, const char* aux, char* master_key)
{
    int ret = 0;
    mkey_ctx* ctx = session->ctx;
    const mkey_props* props = session->props;

    struct stat st;
    if(!ctx->data_path_set || stat(ctx->data_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if(ctx->dbg) printf("v3/v4 attempted, but data directory doesn't exist or was not specified.\n");
        return -1;
    }

    if(session->algorithm == 4 && !aux) {
        if(ctx->dbg) printf("v4 attempted, but no auxiliary string (device ID required).\n");
        return -1;
    }

    if(session->algorithm == 4 && strlen(aux) != 16) {
        if(ctx->dbg) printf("v4 attempted, but auxiliary string (device ID) of invalid length.\n");
        return -1;
    }

    mkey_data data = {0};

    /*
     * Extract key ID fields from inquiry number.
     * If this system uses masterkey.bin, there is an AES key for the region which is also required.
     * This key is used to decrypt the encrypted HMAC key stored in masterkey.bin. See below.
     */
    u8 version = 0;
    if(session->algorithm == 4)
        version = (inquiry / 10000) % 100;
    else
        version = (inquiry / 100000000) % 100;

    char file_name[MAX_PATH] = {0};
    if(session->algorithm == 4)
        snprintf(file_name, sizeof(file_name), props->v4.hmac_file, version);
    else
        snprintf(file_name, sizeof(file_name), props->v3.hmac_file, version);

    ret = mkey_read_hmac_key(session, file_name, data.hmac_key);
    if(ret) return -2;

    // Create the input buffer.
    char inbuf[15] = {0};
    size_t inbuf_size = 0;

    if(session->algorithm == 4)
        snprintf(inbuf, sizeof(inbuf), "%06"PRIu64, inquiry % 1000000);
    else
        snprintf(inbuf, sizeof(inbuf), "%010"PRIu64, inquiry % 10000000000);

    inbuf_size = strlen(inbuf);

    if(session->algorithm == 4) {
        putbe32((u8*)inbuf + strlen(inbuf), 1);
        inbuf_size += sizeof(u32);

        u64 device_id = strtoull(aux, 0, 16);
        u8 mkey_hmac_seed[sizeof(device_id) + sizeof(data.hmac_key)] = {0};

        putle64(mkey_hmac_seed, device_id);
        memcpy(mkey_hmac_seed + sizeof(device_id), data.hmac_key, sizeof(data.hmac_key));

        if(ctx->dbg) {
            printf("\nHMAC key seed:\n");
            hexdump(mkey_hmac_seed, sizeof(mkey_hmac_seed));
        }

        sha2(mkey_hmac_seed, sizeof(mkey_hmac_seed), data.hmac_key, 0);
    }

    if(ctx->dbg) {
        printf("\nHMAC key:\n");
        hexdump(data.hmac_key, sizeof(data.hmac_key));

        printf("\nHash input:\n");
        hexdump(inbuf, inbuf_size);
    }

    u8 outbuf[0x20] = {0};
    if(session->algorithm == 4) {
        u8 tmpbuf[sizeof(outbuf)] = {0};
        sha2_hmac(data.hmac_key, sizeof(data.hmac_key), (u8*)inbuf, inbuf_size, outbuf, false);
        memcpy(tmpbuf, outbuf, sizeof(tmpbuf));

        for(int i = 1; i < 10000; i++) {
            sha2_hmac(data.hmac_key, sizeof(data.hmac_key), tmpbuf, sizeof(tmpbuf), tmpbuf, false);
            for(unsigned int j = 0; j < sizeof(tmpbuf); j++) {
                outbuf[j] ^= tmpbuf[j];
            }
        }
    } else
        sha2_hmac(data.hmac_key, sizeof(data.hmac_key), (u8*)inbuf, strlen(inbuf), outbuf, false);

    if(ctx->dbg) {
        printf("\nHash output:\n");
        hexdump(outbuf, sizeof(outbuf));
    }

    u64 output = getle64(outbuf) & 0x0000FFFFFFFFFFFF;

    if(ctx->dbg) printf("\nOutput word: %"PRIu64".\n", output);

    // Truncate to 8 decimal digits to form the final master key.
    snprintf(master_key, 10, "%08"PRId64, output % 100000000);

    return 0;
}

int mkey_generate(mkey_ctx* ctx, const char* inquiry_number, u8 month, u8 day, const char* aux, const char* device, char* master_key)
{
    int res = 0;

    if(!inquiry_number) return -1;
    if(!isnumeric(inquiry_number)) return -1;
    u64 inquiry = strtoull(inquiry_number, 0, 10);

    if(!device) device = ctx->default_device;

    if (month < 1 || month > 12) {
        if(ctx->dbg) printf("Error: month must be between 1 and 12.\n");
        return -1;
    }

    if (day < 1 || day > 31) {
        if(ctx->dbg) printf("Error: day must be between 1 and 31.\n");
        return -1;
    }

    const mkey_props* props = mkey_get_props(device);
    if(!props) {
        if(ctx->dbg) printf("Error: unsupported device %s.\n", device);
        return -2;
    }

    mkey_session session = {
        .ctx = ctx,
        .props = props,
        .device = device,
    };

    // We can glean information about the required algorithm from the inquiry number.
    session.algorithm = mkey_detect_algorithm(&session, inquiry_number);
    if(session.algorithm < 0) return -2;

    // Perform calculation of master key.
    if(session.algorithm == 0)
        res = mkey_generate_v0(&session, inquiry, month, day, master_key);
    else if(session.algorithm == 1 || session.algorithm == 2)
        res = mkey_generate_v1_v2(&session, inquiry, month, day, master_key);
    else if(session.algorithm == 3 || session.algorithm == 4)
        res = mkey_generate_v3_v4(&session, inquiry, aux, master_key);

    if(res) return -3;

    if(ctx->dbg) printf("\n");

    return 0;
}

// Read AES key (v2).
static int mkey_read_aes_key(mkey_session* session, const char* file_name, void* out)
{
    if(!file_name || !out) return -1;
    mkey_ctx* ctx = session->ctx;

    char file_path[MAX_PATH] = {0};
    snprintf(file_path, sizeof(file_path), "%s/%s", ctx->data_path, file_name);

    if(ctx->dbg) printf("Using %s.\n", file_path);

    FILE* file = fopen(file_path, "rb");
    if(!file) {
        if(ctx->dbg) printf("Error: could not open %s.\n", file_name);
        return -2;
    }

    size_t aes_key_size = 0x10;

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if(size != aes_key_size) {
        if(ctx->dbg) {
            printf("Error: Size of AES key %s is invalid (expected 0x%02zX, got 0x%02zX).\n",
                file_name, aes_key_size, size);
        }

        fclose(file);
        return -3;
    }

    int count = fread(out, aes_key_size, 1, file);
    fclose(file);

    if(count != 1) {
        if(ctx->dbg) printf("Error: Failed to read AES key %s.\n", file_name);
        return -4;
    }

    return 0;
}

// Read masterkey.bin (v2).
static int mkey_read_mkey_file(mkey_session* session, const char* file_name, void* out)
{
    if(!file_name || !out) return -1;
    mkey_ctx* ctx = session->ctx;

    char file_path[MAX_PATH] = {0};
    snprintf(file_path, sizeof(file_path), "%s/%s", ctx->data_path, file_name);

    if(ctx->dbg) printf("Using %s.\n", file_path);

    FILE* file = fopen(file_path, "rb");
    if(!file) {
        if(ctx->dbg) printf("Error: could not open %s.\n", file_name);
        return -2;
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if(size != sizeof(mkey_data)) {
        if(ctx->dbg) {
            printf("Error: Size of masterkey.bin %s is invalid (expected 0x%02zX, got 0x%02zX).\n",
                file_name, sizeof(mkey_data), size);
        }

        fclose(file);
        return -3;
    }

    int count = fread(out, sizeof(mkey_data), 1, file);
    fclose(file);

    if(count != 1) {
        if(ctx->dbg) printf("Error: Failed to read masterkey.bin %s.\n", file_name);
        return -4;
    }

    return 0;
}

// Read HMAC key (v1/v3/v4).
static int mkey_read_hmac_key(mkey_session* session, const char* file_name, void* out)
{
    if(!file_name || !out) return -1;
    mkey_ctx* ctx = session->ctx;

    char file_path[MAX_PATH] = {0};
    snprintf(file_path, sizeof(file_path), "%s/%s", ctx->data_path, file_name);

    if(ctx->dbg) printf("Using %s.\n", file_path);

    FILE* file = fopen(file_path, "rb");
    if(!file) {
        if(ctx->dbg) printf("Error: could not open %s.\n", file_name);
        return -2;
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if(size != sizeof_member(mkey_data, hmac_key)) {
        if(ctx->dbg) {
            printf("Error: Size of HMAC key %s is invalid (expected 0x%02zX, got 0x%02zX).\n",
                file_name, sizeof_member(mkey_data, hmac_key), size);
        }

        fclose(file);
        return -3;
    }

    int count = fread(out, sizeof_member(mkey_data, hmac_key), 1, file);
    fclose(file);

    if(count != 1) {
        if(ctx->dbg) printf("Error: Failed to read HMAC key %s.\n", file_name);
        return -4;
    }

    return 0;
}

// CRC-32 implementation (v0).
static u32 mkey_calculate_crc(u32 poly, u32 xorout, u32 addout, const void* inbuf, size_t size)
{
    u32 crc = 0xFFFFFFFF;
    const u8* in = inbuf;
    if(!in) size = 0;

    for(size_t i = 0; i < size; i++) {
        u8 byte = in[i];
        crc = crc ^ byte;

        for(int j = 0; j < 8; j++) {
            u32 mask = -(crc & 1);
            crc = (crc >> 1) ^ (poly & mask);
        }
    }

    crc ^= xorout;
    crc += addout;

    return crc;
}

void mkey_set_debug(mkey_ctx* ctx, bool enable)
{
    ctx->dbg = enable;
}

void mkey_set_data_path(mkey_ctx* ctx, const char* data_path)
{
    strncpy(ctx->data_path, data_path, sizeof(ctx->data_path));
    ctx->data_path_set = true;
}

void mkey_set_default_device(mkey_ctx* ctx, const char* device)
{
    const mkey_props* props = mkey_get_props(device);
    if(!props) {
        printf("Error: unsupported device %s.\n", device);
        return;
    }

    ctx->default_device = props->device;
}

void mkey_init(mkey_ctx* ctx, bool debug, const char* data_path)
{
    memset(ctx, 0, sizeof(mkey_ctx));
    mkey_set_debug(ctx, debug);
    mkey_set_default_device(ctx, mkey_default_device);
    if(data_path) mkey_set_data_path(ctx, data_path);
}
