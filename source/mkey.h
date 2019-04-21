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

#include "types.h"
#include "utils.h"

typedef struct {
    u8 region;
    u8 version;
    u8 reserved[0xE];
    u8 ctr[0x10];
    u8 hmac_key[0x20];
} mkey_data;

typedef struct {
    bool dbg;
    char data_path[MAX_PATH];
    bool data_path_set;
    const char* default_device;
} mkey_ctx;

extern const char mkey_devices[][4];
int mkey_num_devices(void);

void mkey_set_debug(mkey_ctx* ctx, bool enable);
void mkey_set_data_path(mkey_ctx* ctx, const char* data_path);
void mkey_set_default_device(mkey_ctx* ctx, const char* device);

void mkey_init(mkey_ctx* ctx, bool debug, const char* data_path);
int mkey_generate(mkey_ctx* ctx, const char* inquiry_number, u8 month, u8 day, const char* aux, const char* device, char* master_key);
