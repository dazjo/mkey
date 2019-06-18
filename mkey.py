#
# mkey - parental controls master key generator for certain video game consoles
# Copyright (C) 2015-2019, Daz Jones (Dazzozo) <daz@dazzozo.com>
# Copyright (C) 2015-2019, SALT
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import print_function

import os, struct, datetime

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Only require hexdump for debugging.
try: import hexdump
except ImportError: pass

class mkey_generator():
    __props = {
        "RVL": {
            "traits": ["big-endian"],
            "algorithms": ["v0"],
            "v0": {
                "poly": 0xEDB88320,
                "xorout": 0xAAAA,
                "addout": 0x14C1,
            },
        },
        "TWL": {
            "algorithms": ["v0"],
            "v0": {
                "poly": 0xEDB88320,
                "xorout": 0xAAAA,
                "addout": 0x14C1,
            },
        },
        "CTR": {
            "algorithms": ["v0", "v1", "v2"],
            "v0": {
                "poly": 0xEDBA6320,
                "xorout": 0xAAAA,
                "addout": 0x1657,
            },
            "v1": {
                "hmac_file": "ctr_%02x.bin",
            },
            "v2": {
                "mkey_file": "ctr_%02x_%02x.bin",
                "aes_file": "ctr_aes_%02x.bin",
            },
        },
        "WUP": {
            "traits": ["big-endian"],
            "algorithms": ["v0", "v2"],
            "v0": {
                "poly": 0xEDBA6320,
                "xorout": 0xAAAA,
                "addout": 0x1657,
            },
            "v2": {
                "traits": ["no-versions"],
                "mkey_file": "wup_%02x.bin",
                "aes_file": "wup_aes_%02x.bin",
            },
        },
        "HAC": {
            "algorithms": ["v3", "v4"],
            "v3": {
                "hmac_file": "hac_%02x.bin",
            },
            "v4": {
                "hmac_file": "hac_%02x.bin",
            },
        },
    }

    devices = __props.keys()
    default_device = "CTR"

    def __init__(self, data_path=None, debug=False):
        self._dbg = debug

        #
        # If debug mode is enabled, create our hexdump function.
        # This requires the hexdump module, an exception is raised here if it does not exist.
        #
        if self._dbg:
            try:
                hexdump # test the waters...
                self._hexdump = lambda inbuf: print("%s\n" % hexdump.hexdump(inbuf, "return"))
            except NameError:
                raise ImportError("Debug mode enabled, but hexdump module does not exist.")
        else:
            self._hexdump = None

        # If no data path was provided, check for a "data" directory where the script resides.
        if not data_path:
            self._data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
        else:
            self._data_path = data_path

        # Verify that this directory actually exists.
        if self._data_path and not os.path.isdir(self._data_path):
            self._data_path = None

    # Read AES key (v2).
    def _read_aes_key(self, file_name):
        file_path = os.path.join(self._data_path, file_name)
        if self._dbg: print("Using %s." % file_path)

        mkey_aes_key = open(file_path, "rb").read()
        aes_key_len = 0x10

        if len(mkey_aes_key) != aes_key_len:
            raise ValueError("Size of AES key %s is invalid (expected 0x%02X, got 0x%02X)." %
                file_name, aes_key_len, size)

        return mkey_aes_key

    # Read masterkey.bin (v2).
    def _read_mkey_file(self, file_name):
        file_path = os.path.join(self._data_path, file_name)
        if self._dbg: print("Using %s." % file_path)

        data = open(file_path, "rb").read()
        mkey_len = 0x40

        if len(data) != mkey_len:
            raise ValueError("Size of masterkey.bin %s is invalid (expected 0x%02X, got 0x%02X)." %
                file_name, mkey_len, size)

        mkey_data = struct.unpack("BB14x16s32s", data)
        return mkey_data

    # Read HMAC key (v1/v3/v4).
    def _read_hmac_key(self, file_name):
        file_path = os.path.join(self._data_path, file_name)
        if self._dbg: print("Using %s." % file_path)

        mkey_hmac_key = open(file_path, "rb").read()
        hmac_key_len = 0x20

        if len(mkey_hmac_key) != hmac_key_len:
            raise ValueError("Size of HMAC key %s is invalid (expected 0x%02X, got 0x%02X)." %
                file_name, hmac_key_len, size)

        return mkey_hmac_key

    def _detect_algorithm(self, device, inquiry):
        props = self.__props[device]
        algorithms = props["algorithms"]

        if len(inquiry) == 8:
            if "v0" in algorithms:
                return "v0"
            else:
                raise ValueError("v0 algorithm not supported by %s." % device)
        elif len(inquiry) == 10:
            version = int((int(inquiry) / 10000000) % 100)

            if "v1" in algorithms and version < 10:
                return "v1"
            elif "v2" in algorithms:
                return "v2"
            elif "v3" in algorithms:
                return "v3"
            else:
                raise ValueError("v1/v2/v3 algorithms not supported by %s." % device)
        elif len(inquiry) == 6:
            if "v4" in algorithms:
                return "v4"
            else:
                raise ValueError("v4 algorithm not supported by %s." % device)
        else:
            raise ValueError("Inquiry number must be 6, 8 or 10 digits.")

    # CRC-32 implementation (v0).
    def _calculate_crc(self, poly, xorout, addout, inbuf):
        crc = 0xFFFFFFFF

        for byte in inbuf:
            if not isinstance(byte, int):
                byte = ord(byte)

            crc = crc ^ byte

            for i in range(8):
                mask = -(crc & 1)
                crc = (crc >> 1) ^ (poly & mask)

        crc ^= xorout
        crc += addout

        return crc

    def _generate_v0(self, props, inquiry, month, day):
        poly = props["poly"]
        xorout = props["xorout"]
        addout = props["addout"]

        # Create the input buffer.
        inbuf = "%02u%02u%04u" % (month, day, inquiry % 10000)
        inbuf = inbuf.encode("ascii")

        if self._dbg:
            print("CRC polynomial: 0x%08X." % poly)
            print("CRC xor-out:    0x%X." % xorout)
            print("CRC add-out:    0x%X." % addout)
            print("")

            print("CRC input:")
            self._hexdump(inbuf)

        output = self._calculate_crc(poly, xorout, addout, inbuf)
        if self._dbg: print("Output word: %u.\n" % output)

        # Truncate to 5 decimal digits to form the final master key.
        master_key = output % 100000
        return "%05d" % master_key

    def _generate_v1_v2(self, props, inquiry, month, day):
        algorithm = props["algorithm"]
        traits = props["traits"]

        if self._data_path and not os.path.isdir(self._data_path):
            self._data_path = None

        if not self._data_path:
            raise ValueError("v1/v2 attempted, but data directory doesn't exist or was not specified.")

        #
        # Extract key ID fields from inquiry number.
        # If this system uses masterkey.bin, there is an AES key for the region which is also required.
        # This key is used to decrypt the encrypted HMAC key stored in masterkey.bin. See below.
        #
        region = int((inquiry / 1000000000) % 10)
        version = int((inquiry / 10000000) % 100)

        #
        # The v2 algorithm uses a masterkey.bin file that can be updated independently of the rest of the system,
        # avoiding the need for recompiling the parental controls application. The format consists of an ID field,
        # used to identify the required key files for the user's inquiry number, a HMAC key encrypted using AES-128-CTR,
        # and the AES counter value for decrypting it.
        # Obviously, what is missing from this list is the AES key itself, unique to each region, which is usually
        # hardcoded within the parental controls application (i.e. .rodata).
        #
        # The 3DS implementation stores the masterkey.bin file in the CVer title, which is updated anyway for every
        # system update (it also contains the user-facing system version number). The AES key is stored in mset
        # (System Settings) .rodata.
        #
        # The Wii U implementation does away with the masterkey.bin versioning, and uses a masterkey.bin that does
        # not change between system versions (though still between regions). This comes from a dedicated title for
        # each region that is still at v0. The Wii U AES keys are stored in pcl (Parental Controls) .rodata.
        # As a result, the unused ("version") digits in the inquiry number are extra console-unique filler
        # (derived from MAC address).
        #
        if algorithm == "v2":
            if "no-versions" in traits:
                file_name = props["mkey_file"] % region
            else:
                file_name = props["mkey_file"] % (region, version)

            (mkey_region, mkey_version, mkey_ctr, mkey_hmac_key) = self._read_mkey_file(file_name)

            file_name = props["aes_file"] % region
            mkey_aes_key = self._read_aes_key(file_name)
        #
        # The 3DS-only v1 algorithm uses a raw HMAC key stored in mset .rodata.
        # No encryption is used for this. Similar to v2 on Wii U, the version field is unused.
        # The unused ("version") digits again are extra console-unique filler (derived from MAC address).
        # This was short-lived, and corresponds to system versions 7.0.0 and 7.1.0.
        #
        else:
            file_name = props["hmac_file"] % region
            mkey_hmac_key = self._read_hmac_key(file_name)

        if self._dbg: print("")
        #
        # If v2, we must decrypt the HMAC key using an AES key from .rodata.
        # The HMAC key is encrypted in masterkey.bin (offset 0x20->0x40) using AES-128-CTR.
        # The counter is also stored in masterkey.bin (offset 0x10->0x20).
        #
        if algorithm == "v2":
            # Verify the region field.
            if mkey_region != region:
                raise ValueError("%s has an incorrect region field (expected 0x%02X, got 0x%02X)." %
                    file_name, region, mkey_region)

            # Verify the version field.
            if mkey_version != version and "no-versions" not in traits:
                raise ValueError("%s has an incorrect version field (expected 0x%02X, got 0x%02X)." %
                    file_name, version, mkey_version)

            if self._dbg:
                print("AES key:")
                self._hexdump(mkey_aes_key)

                print("AES counter:")
                self._hexdump(mkey_ctr)

                print("Encrypted HMAC key:")
                self._hexdump(mkey_hmac_key)

            # Decrypt the HMAC key.
            ctr = Counter.new(128, initial_value = bytes_to_long(mkey_ctr))
            ctx = AES.new(mkey_aes_key, AES.MODE_CTR, counter = ctr)
            mkey_hmac_key = ctx.decrypt(mkey_hmac_key)

        # Create the input buffer.
        inbuf = "%02u%02u%010u" % (month, day, inquiry % 10000000000)
        inbuf = inbuf.encode("ascii")

        if self._dbg:
            print("HMAC key:")
            self._hexdump(mkey_hmac_key)

            print("Hash input:")
            self._hexdump(inbuf)

        outbuf = HMAC.new(mkey_hmac_key, inbuf, digestmod = SHA256).digest()

        if self._dbg:
            print("Hash output:")
            self._hexdump(outbuf)

        # Wii U is big endian.
        if "big-endian" in traits:
            output = struct.unpack_from(">I", outbuf)[0]
        else:
            output = struct.unpack_from("<I", outbuf)[0]

        if self._dbg: print("Output word: %u.\n" % output)

        # Truncate to 5 decimal digits to form the final master key.
        master_key = output % 100000
        return "%05d" % master_key

    def _generate_v3_v4(self, props, inquiry, aux = None):
        algorithm = props["algorithm"]
        traits = props["traits"]

        if self._data_path and not os.path.isdir(self._data_path):
            self._data_path = None

        if not self._data_path:
            raise ValueError("v3/v4 attempted, but data directory doesn't exist or was not specified.")

        if algorithm == "v4" and not aux:
            raise ValueError("v4 attempted, but no auxiliary string (device ID required).")

        if algorithm == "v4" and len(aux) != 16:
            raise ValueError("v4 attempted, but auxiliary string (device ID) of invalid length.")

        if algorithm == "v4":
            version = int((inquiry / 10000) % 100)
        else:
            version = int((inquiry / 100000000) % 100)

        file_name = props["hmac_file"] % version
        mkey_hmac_key = self._read_hmac_key(file_name)

        if self._dbg: print("")

        # Create the input buffer.
        if algorithm == "v4":
            inbuf = "%06u" % (inquiry % 1000000)
        else:
            inbuf = "%010u" % (inquiry % 10000000000)

        inbuf = inbuf.encode("ascii")

        if algorithm == "v4":
            inbuf += struct.pack(">I", 1)

            device_id = struct.pack('<Q', int(aux, 16))
            mkey_hmac_seed = device_id + mkey_hmac_key

            if self._dbg:
                print("HMAC key seed:")
                self._hexdump(mkey_hmac_seed)

            mkey_hmac_key = SHA256.new(mkey_hmac_seed).digest()

        if self._dbg:
            print("HMAC key:")
            self._hexdump(mkey_hmac_key)

            print("Hash input:")
            self._hexdump(inbuf)

        if algorithm == "v4":
            outbuf = HMAC.new(mkey_hmac_key, inbuf, digestmod = SHA256).digest()
            tmpbuf = outbuf

            for i in range(1, 10000):
                tmpbuf = HMAC.new(mkey_hmac_key, tmpbuf, digestmod = SHA256).digest()
                outbuf = strxor(outbuf, tmpbuf)
        else:
            outbuf = HMAC.new(mkey_hmac_key, inbuf, digestmod = SHA256).digest()

        if self._dbg:
            print("Hash output:")
            self._hexdump(outbuf)

        output = struct.unpack_from("<Q", outbuf)[0] & 0x0000FFFFFFFFFFFF

        if self._dbg: print("Output word: %u.\n" % output)

        # Truncate to 8 decimal digits to form the final master key.
        master_key = output % 100000000
        return "%08d" % master_key

    def generate(self, inquiry, month = None, day = None, aux = None, device = None):
        inquiry = inquiry.replace(" ", "")
        if not inquiry.isdigit():
            raise ValueError("Inquiry string must represent a decimal number.")

        if month is None:
            month = datetime.date.today().month
        if day is None:
            day = datetime.date.today().day

        if month < 1 or month > 12:
            raise ValueError("Month must be between 1 and 12.")

        if day < 1 or day > 31:
            raise ValueError("Day must be between 1 and 31.")

        if not device: device = self.default_device
        if device not in self.devices:
            raise ValueError("Unsupported device: %s." % device)

        # We can glean information about the required algorithm from the inquiry number.
        algorithm = self._detect_algorithm(device, inquiry)
        inquiry = int(inquiry, 10)

        # Prepare the local properties structure.
        props = self.__props[device].copy()
        traits = props["traits"] if "traits" in props else []

        # Extract the properties for the selected algorithm.
        algoprops = props[algorithm]
        algotraits = algoprops["traits"] if "traits" in algoprops else []

        # Destroy unused algorithm info.
        for i in props["algorithms"]: del props[i]
        del props["algorithms"]

        # Merge the algorithm properties and the device properties.
        props.update(algoprops)

        # Merge the algorithm traits and device traits.
        traits = list(set(algotraits) | set(traits))
        props.update({"algorithm": algorithm, "traits": traits})

        # Perform calculation of master key.
        if algorithm == "v0":
            output = self._generate_v0(props, inquiry, month, day)
        elif algorithm == "v1" or algorithm == "v2":
            output = self._generate_v1_v2(props, inquiry, month, day)
        elif algorithm == "v3" or algorithm == "v4":
            output = self._generate_v3_v4(props, inquiry, aux)

        return output

def main():
    import argparse
    desc = "mkey (c) 2015-2016, SALT"
    parser = argparse.ArgumentParser(description = desc)

    desc = "8 or 10 digit inquiry number"
    parser.add_argument("inquiry", type = str, help = desc)

    desc = "month displayed on device (system date)"
    parser.add_argument("-m", "--month", type = int, help = desc)

    desc = "day displayed on device (system date)"
    parser.add_argument("-d", "--day", type = int, help = desc)

    desc = "auxiliary data (e.g. device ID)"
    parser.add_argument("-a", "--aux", type = str, help = desc)

    desc = "device type (%s by default)" % mkey_generator.default_device
    parser.add_argument("device", type = str, help = desc, nargs = "?",
        choices = mkey_generator.devices, default = mkey_generator.default_device)

    desc = "enable debugging output"
    parser.add_argument("-v", "--verbose", action = "store_true", help = desc)

    args = parser.parse_args()

    mkey = mkey_generator(debug = args.verbose)

    master_key = mkey.generate(args.inquiry, args.month, args.day, args.aux, args.device)
    print("Master key is %s." % master_key)

if __name__ == "__main__":
    main()
