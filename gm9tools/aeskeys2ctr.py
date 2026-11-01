#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
aeskeys2ctr.py -- Convert 3DS AES keys into 7-Zip CTR "keystone" folders.

The N3dsHandler in 7-Zip CTR does NOT hardcode any key. It loads text files
from a folder next to 7z.dll (overridable in keystone.ini):
    keystone\ctraes_retail\  (retail unit keys)  each file "slot0x2CKeyX=0123...ABCD"
    keystone\ctraes_dev\     (devkit unit keys)  same format

This tool turns the output of GodMode9 (aes_keys.txt from the built-in
DumpKeys script, an aeskeydb.bin, or raw slot0x*.bin dumped from the K: drive)
into those folders, and SPLITS keys by whether they are safe to publish to a
public GitHub repository.

Classification (3dbrew "Keyslot ranges" / AES key-init):
  * PUBLISHABLE (common keydata / already leaked fixed keys):
        slot0x03, 0x18, 0x1B, 0x25, 0x2C..0x3F  (KeyX/KeyY/KeyN)
        common0..common5, common0N..common5N, nfc*, generator, dlp, etc.
  * PRIVATE (console-unique, derived from OTP / movable.sed on each unit):
        slot0x04..0x2B  KeyX   (the remaining slots)
        movable.sed, OTP

NOTE: on real retail 3DS the "console-unique" keyX values happen to be
identical across units (Nintendo ships a fixed conunique block), so they are
already public on 3dbrew. We still keep them in keystone_private/ by default to
be conservative. Pass --all-pub if you verified your values match the public
ones and want them in keystone\ctraes_retail\ too.

Usage:
    python aeskeys2ctr.py <input> [--out <dir>] [--all-pub] [--boot9 <boot9.bin>]

    <input> may be:
      - a path to aes_keys.txt      (GodMode9 DumpKeys / Citra format)
      - a path to aeskeydb.bin      (GodMode9 key database, 32 B/entry)
      - a directory of slot0x*.bin  (dumped from GodMode9 K: drive)

Output layout (under <out>, default "keystone_out"):
    keystone\ctraes_retail\   retail publishable  -> copy next to 7z.dll
    keystone\ctraes_dev\       devkit publishable  -> copy next to 7z.dll
    keystone\pubkey\           FIRM RSA-2048 moduli + pubkey.ini (public keys)
    keystone_private\         console-unique / OTP-derived (DO NOT publish)

The FIRM public keys live in boot9.bin at 0xB1E0 (retail) and 0xC4E0 (devkit,
256 bytes big-endian each). Pass --boot9 to extract them, or let the tool pick
up a boot9.bin sitting next to the input (the GodMode9 script writes one into
its priv/ folder). They are public keys: safe to publish, unlike the AES keys.
"""

import os
import re
import sys
import struct
import shutil

PUBLISHABLE_SLOTS = {0x03, 0x18, 0x1B, 0x25} | set(range(0x2C, 0x40))

# Names not using the slot0x%02X pattern but still publishable
PUB_NAME_PREFIXES = ("common", "nfc", "generator", "dlp", "slot0x03",)


def classify_name(name_lower):
    """Return 'pub' or 'priv' for a normalized (lowercase) key name."""
    m = re.match(r"slot0x([0-9a-f]{2})key([xyn])", name_lower)
    if m:
        slot = int(m.group(1), 16)
        return "pub" if slot in PUBLISHABLE_SLOTS else "priv"
    # special / non-slot keys
    for p in PUB_NAME_PREFIXES:
        if name_lower.startswith(p):
            return "pub"
    return "priv"


def unit_of_name(name_lower):
    # common0..common5 = retail, common0N..common5N = devkit (New3DS/DEV set)
    if name_lower.startswith("common"):
        return "dev" if name_lower.endswith("n") else "ret"
    # ordinary slot0x..KeyX/Y/N: unit cannot be told from the name alone;
    # a retail dump goes to keystone\ctraes_retail\, a devkit dump to
    # keystone\ctraes_dev\ (--devkit)
    return "ret"


def write_key(out_dir, name, hexval):
    """Write one key text file: '<Name>=<hex>'."""
    os.makedirs(out_dir, exist_ok=True)
    # strip any non-hex chars (spaces, dashes, etc.)
    hexval = re.sub(r"[^0-9a-fA-F]", "", hexval)
    if len(hexval) < 32:
        return 0
    path = os.path.join(out_dir, name + ".key")
    with open(path, "w") as f:
        f.write("%s=%s\n" % (name, hexval[:32].upper()))
    return 1


def parse_aes_keys_txt(path):
    """GodMode9 DumpKeys / Citra aes_keys.txt:  'slot0x2CKeyX=0123...' per line."""
    keys = []  # (name, hex, unit)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, val = line.split("=", 1)
            name = name.strip().lower()
            val = val.strip()
            keys.append((name, val, ""))
    return keys


def parse_aeskeydb(path):
    """GodMode9 aeskeydb.bin: 32-byte AesKeyInfo entries."""
    keys = []
    data = open(path, "rb").read()
    if len(data) % 32 != 0:
        print("WARN: aeskeydb.bin size not multiple of 32", file=sys.stderr)
    for off in range(0, len(data) - 31, 32):
        slot = data[off]
        typ = chr(data[off + 1] if 32 <= data[off + 1] < 127 else 0)
        ident = data[off + 2:off + 12].rstrip(b"\x00").decode("latin1", "replace")
        unit_type = data[off + 14]   # 0 ALL / 1 devkit / 2 retail
        key = data[off + 16:off + 32]
        if typ in ("X", "Y", "N", "I") and any(key):
            suffix = {"X": "KeyX", "Y": "KeyY", "N": "KeyN", "I": "Iv"}[typ]
            name = "slot0x%02x%s%s" % (slot, suffix, ident or "")
            unit = {1: "dev", 2: "ret"}.get(unit_type, "")
            keys.append((name.lower(), key.hex(), unit))
    return keys


def parse_raw_bin_dir(path):
    """Directory of slot0x*.bin (16-byte keys) dumped from GodMode9 K: drive."""
    keys = []
    if os.path.isdir(path):
        for fn in os.listdir(path):
            if fn.lower().startswith("slot0x") and fn.lower().endswith(".bin"):
                p = os.path.join(path, fn)
                data = open(p, "rb").read()[:16]
                if len(data) == 16:
                    base = fn[:-4]  # strip .bin -> slot0x18KeyX.ret
                    unit = "dev" if ".dev" in base else ("ret" if ".ret" in base else "")
                    name = base.replace(".dev", "").replace(".ret", "").lower()
                    keys.append((name, data.hex(), unit))
    return keys


FIRM_PUBKEY_OFF = {"retail": 0xB1E0, "dev": 0xC4E0}
FIRM_PUBKEY_LEN = 256
PUBKEY_INI = ("[FirmPubKey]\r\n"
              "RetailFirmPubKeyFile=retail_firm_pubkey.bin\r\n"
              "DevFirmPubKeyFile=dev_firm_pubkey.bin\r\n")


def extract_firm_pubkeys(boot9_path, out):
    """Write keystone/pubkey/{retail,dev}_firm_pubkey.bin + pubkey.ini."""
    with open(boot9_path, "rb") as f:
        blob = f.read()
    if len(blob) < 0x10000:
        print("boot9.bin is only %d bytes (expected 65536): %s" % (len(blob), boot9_path),
              file=sys.stderr)
        return 0
    pubdir = os.path.join(out, "keystone", "pubkey")
    os.makedirs(pubdir, exist_ok=True)
    written = 0
    for unit, off in FIRM_PUBKEY_OFF.items():
        mod = blob[off:off + FIRM_PUBKEY_LEN]
        if len(mod) != FIRM_PUBKEY_LEN or not any(mod) or mod.count(0xFF) == FIRM_PUBKEY_LEN:
            print("warning: %s FIRM modulus at 0x%X looks empty (wrong dump?), skipped"
                  % (unit, off), file=sys.stderr)
            continue
        with open(os.path.join(pubdir, "%s_firm_pubkey.bin" % unit), "wb") as f:
            f.write(mod)
        written += 1
        print("  %s_firm_pubkey.bin  %s..." % (unit, mod[:16].hex()))
    if written:
        with open(os.path.join(pubdir, "pubkey.ini"), "w", encoding="ascii", newline="") as f:
            f.write(PUBKEY_INI)
    return written


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    src = sys.argv[1]
    out = "keystone_out"
    all_pub = False
    devkit = False
    boot9 = None
    i = 2
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--out" and i + 1 < len(sys.argv):
            out = sys.argv[i + 1]; i += 2
        elif a == "--all-pub":
            all_pub = True; i += 1
        elif a == "--devkit":
            devkit = True; i += 1
        elif a == "--boot9" and i + 1 < len(sys.argv):
            boot9 = sys.argv[i + 1]; i += 2
        else:
            i += 1

    # a boot9.bin next to the input is used for the FIRM public keys
    if not boot9:
        probe = os.path.join(src if os.path.isdir(src) else os.path.dirname(src) or ".",
                             "boot9.bin")
        if os.path.isfile(probe):
            boot9 = probe

    keys = []
    if os.path.isdir(src):
        keys = parse_raw_bin_dir(src)
    elif src.lower().endswith(".txt"):
        keys = parse_aes_keys_txt(src)
    elif src.lower().endswith(".bin"):
        keys = parse_aeskeydb(src)
    else:
        print("Unrecognized input type", file=sys.stderr)
        return 1

    if not keys and not boot9:
        print("No keys found in input.", file=sys.stderr)
        return 1

    pub_r, pub_d, priv = {}, {}, {}
    for name, hexval, unit in keys:
        cls = classify_name(name)
        u = unit or unit_of_name(name)
        if cls == "pub":
            if u == "dev":
                pub_d[name] = hexval
            else:
                pub_r[name] = hexval
        else:
            priv[name] = hexval

    if all_pub:
        pub_r.update(priv)
        priv = {}

    if devkit:
        # put all publishable retail slots into keystone\ctraes_dev (devkit dump)
        pub_d.update(pub_r)
        pub_r = {}

    n = 0
    for name, h in pub_r.items():
        n += write_key(os.path.join(out, "keystone", "ctraes_retail"), name, h)
    for name, h in pub_d.items():
        n += write_key(os.path.join(out, "keystone", "ctraes_dev"), name, h)
    for name, h in priv.items():
        n += write_key(os.path.join(out, "keystone_private"), name, h)

    pubkeys = 0
    if boot9:
        print("FIRM public keys from %s:" % boot9)
        pubkeys = extract_firm_pubkeys(boot9, out)
        if not pubkeys:
            print("  (none written)", file=sys.stderr)
        else:
            print("  -> keystone\\pubkey\\  (%d files + pubkey.ini)" % pubkeys)

    print("Parsed %d keys -> %d written" % (len(keys), n))
    print("  retail publishable : %d  (-> keystone\\ctraes_retail\\)" % len(pub_r))
    print("  devkit publishable : %d  (-> keystone\\ctraes_dev\\)" % len(pub_d))
    print("  private (no upload): %d  (-> keystone_private\\)" % len(priv))
    print("Output dir: %s" % os.path.abspath(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
