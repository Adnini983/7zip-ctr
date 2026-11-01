-- DumpKeysCTR.lua -- GodMode9 Lua script for 7-Zip CTR
--
-- Builds a READY-TO-USE keystone\ tree on the SD card: no PC-side conversion,
-- no manual hex copying. Compared to DumpKeysCTR.gm9 this one can slice files
-- (fs.read_file with an offset) and gets the console data from GodMode9 itself
-- (sys.serial / IS_DEVKIT / CONSOLE_TYPE), so everything lands in the final
-- layout the handler expects.
--
-- Output: 0:/gm9/out/7zctr-keys/
--   keystone/ctraes_retail/*.key        retail AES keys   (safe to publish)
--   keystone/ctraes_dev/*.key           devkit AES keys   (safe to publish)
--   keystone/pubkey/retail_firm_pubkey.bin
--   keystone/pubkey/dev_firm_pubkey.bin
--   keystone/pubkey/pubkey.ini
--   keystone/ctrdevice/<SERIAL>/boot9.bin
--   keystone/ctrdevice/<SERIAL>/otp.mem
--   keystone/ctrdevice/<SERIAL>/otp_dec.mem
--   keystone/ctrdevice/<SERIAL>/nand_cid.mem
--   keystone/ctrdevice/<SERIAL>/ctrindex.ini
--   keystone_private/*.key              console-unique keys (NEVER publish)
--   seeddb.bin                          (when the SysNAND has one)
--   README.txt
--
-- HOW TO RUN
--   1. GodMode9 -> Scripts -> DumpKeys   (built-in; writes 0:/gm9/out/aes_keys.txt)
--      ... if you skip this, the [K:] AESKEYDB drive (aeskeydb.bin in the SD
--      root) is used as the AES key source instead.
--   2. Put this file in 0:/gm9/luascripts/ and use HOME -> "Lua scripts..."
--      (or select the file in the browser -> "Execute Lua script").
--   3. Copy 0:/gm9/out/7zctr-keys/keystone + keystone_private + seeddb.bin
--      next to 7z.dll (merge with the existing keystone folder).
--
-- Everything is ASCII on purpose: GodMode9's default font has no CJK glyphs.

local OUT = GM9OUT .. "/7zctr-keys"
local KS = OUT .. "/keystone"
local PVT = OUT .. "/keystone_private"
local SERIAL = (sys.serial and sys.serial ~= "" and sys.serial) or "UNKNOWN"
local DEV = KS .. "/ctrdevice/" .. SERIAL
local UNIT = IS_DEVKIT and "dev" or "retail"
local MODEL = (CONSOLE_TYPE == "N3DS") and "snake" or "ctr"
local BOOT9 = "M:/boot9.bin"

local PUB_SLOTS = { [0x03] = true, [0x18] = true, [0x1B] = true, [0x25] = true }
for s = 0x2C, 0x3F do PUB_SLOTS[s] = true end

local stats = { keys = 0, priv = 0, files = 0, fails = 0 }

-- ---------------------------------------------------------------- helpers
local function say(fmt, ...) print(string.format(fmt, ...)) end

local function fail(msg)
  stats.fails = stats.fails + 1
  say("  [FAIL] %s", tostring(msg))
end

local function exists(p)
  local ok, r = pcall(fs.exists, p)
  return ok and r
end

local function mkdir(p)
  if exists(p) then return true end
  local ok, err = pcall(fs.mkdir, p)
  if not ok then fail("mkdir " .. p .. ": " .. tostring(err)) end
  return ok
end

-- GodMode9's io.open(path, "wb") CANNOT create a file: its shim calls
-- fs.truncate() first, and truncate fails when the file is missing (that is why
-- the first hardware run only produced the fs.copy() files). fs.write_file uses
-- FA_OPEN_ALWAYS, so it creates the file when needed.
local function write_bytes(path, data)
  if fs.exists(path) then pcall(fs.remove, path) end
  local n, err = fs.write_file(path, 0, data)
  if type(n) ~= "number" then error("cannot write " .. path .. ": " .. tostring(err)) end
  if n ~= #data then error(string.format("short write on %s (%d/%d)", path, n, #data)) end
  stats.files = stats.files + 1
end

local function read_all(path)
  local ok, st = pcall(fs.stat, path)
  if not ok or st.type ~= "file" then return nil end
  return fs.read_file(path, 0, st.size)
end

local function read_bytes(path, off, size)
  local ok, data = pcall(fs.read_file, path, off, size)
  if not ok then return nil, tostring(data) end
  return data
end

local function copy_file(src, dst)
  if not exists(src) then return false end
  local ok, err = pcall(fs.copy, src, dst, { overwrite = true, silent = true, no_cancel = true })
  if not ok then fail("copy " .. src .. ": " .. tostring(err)); return false end
  stats.files = stats.files + 1
  return true
end

local function tohex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function all_same_byte(mod, value)
  for i = 1, #mod do
    if string.byte(mod, i) ~= value then return false end
  end
  return true
end

local function slot_of(name)
  local s = name:match("slot0x(%x%x)key")
  return s and tonumber(s, 16) or nil
end

local function is_publishable(name)
  local s = slot_of(name)
  if s and PUB_SLOTS[s] then return true end
  if name:match("^common") or name:match("^nfc") or name:match("^generator")
     or name:match("^dlp") or name:match("^slot0x03") then
    return true
  end
  return false
end

local function unit_of(name)
  if name:match("^common") and name:match("n$") then return "dev" end
  return "ret"
end

-- File names are normalised to the same shape the shipped folders use
-- (slot0x2CKeyX.key, common0N.key), even though the handler lowercases everything
-- internally. This keeps the output visually identical to build\keystone\*.
local function canonical(name)
  local slot, kind = name:match("^slot0x(%x%x)key([xyn])$")
  if slot then
    return string.format("slot0x%02XKey%s", tonumber(slot, 16), kind:upper())
  end
  local idx, n = name:match("^common(%d)(n?)$")
  if idx then return "common" .. idx .. ((n == "n") and "N" or "") end
  return name
end

local function emit_key(name, hex, unit)
  name = name:lower()
  hex = hex:gsub("[^0-9a-fA-F]", "")
  if #hex < 32 then return end
  hex = hex:sub(1, 32):upper()
  local dir
  if is_publishable(name) then
    local u = unit or unit_of(name)
    dir = KS .. ((u == "dev") and "/ctraes_dev" or "/ctraes_retail")
  else
    dir = PVT
    stats.priv = stats.priv + 1
  end
  local out_name = canonical(name)
  local ok, err = pcall(write_bytes, dir .. "/" .. out_name .. ".key", out_name .. "=" .. hex .. "\r\n")
  if ok then stats.keys = stats.keys + 1 else fail(tostring(err)) end
end

-- ---------------------------------------------------------------- 1. folders
say("7-Zip CTR key dumper")
say("serial: %s  unit: %s  model: %s", SERIAL, UNIT, MODEL)

-- one permission request for the whole output tree (GodMode9 asks once per path)
if not fs.allow(OUT, { ask_all = true }) then
  say("")
  say("Write access was not granted -- nothing was written.")
  ui.ask("Press A to exit")
  return
end

mkdir(OUT)
mkdir(KS)
mkdir(PVT)
mkdir(KS .. "/ctraes_retail")
mkdir(KS .. "/ctraes_dev")
mkdir(KS .. "/pubkey")
mkdir(KS .. "/ctrdevice")
mkdir(DEV)

-- ------------------------------------------------------------ 2. FIRM pubkeys
say("")
say("FIRM public keys (boot9.bin @0xB1E0 / @0xC4E0):")
do
  local b9, err = read_bytes(BOOT9, 0, 0x10000)
  if not b9 or #b9 < 0x10000 then
    say("  boot9.bin not readable at %s (%s)", BOOT9, tostring(err))
    say("  -> copy it from [M:] MEMORY VIRTUAL first, then re-run")
  else
    local function one(filename, off)
      local mod = b9:sub(off + 1, off + 256)
      if #mod ~= 256 then error("short read at 0x" .. string.format("%X", off)) end
      if all_same_byte(mod, 0) or all_same_byte(mod, 255) then
        error("modulus at 0x" .. string.format("%X", off) .. " looks empty")
      end
      write_bytes(KS .. "/pubkey/" .. filename, mod)
      say("  %s  %s...", filename, tohex(mod:sub(1, 16)))
    end
    local ok, erred = pcall(function()
      one("retail_firm_pubkey.bin", 0xB1E0)
      one("dev_firm_pubkey.bin", 0xC4E0)
      write_bytes(KS .. "/pubkey/pubkey.ini",
        "[FirmPubKey]\r\n" ..
        "RetailFirmPubKeyFile=retail_firm_pubkey.bin\r\n" ..
        "DevFirmPubKeyFile=dev_firm_pubkey.bin\r\n")
    end)
    if not ok then fail(erred) end
  end
end

-- ------------------------------------------------- 3. device profile material
say("")
say("Device profile (keystone/ctrdevice/%s):", SERIAL)
do
  local copied = 0
  if copy_file(BOOT9, DEV .. "/boot9.bin") then copied = copied + 1 end
  if copy_file("M:/otp.mem", DEV .. "/otp.mem") then copied = copied + 1 end
  if copy_file("M:/otp_dec.mem", DEV .. "/otp_dec.mem") then copied = copied + 1 end
  if copy_file("M:/nand_cid.mem", DEV .. "/nand_cid.mem") then copied = copied + 1 end
  say("  %d/4 files copied", copied)
  if copied < 2 then
    say("  hint: [M:] MEMORY VIRTUAL must expose boot9.bin / otp.mem / nand_cid.mem")
  end
  local ok, err = pcall(write_bytes, DEV .. "/ctrindex.ini",
    "[ctrindex]\r\n" ..
    "unit=" .. UNIT .. "\r\n" ..
    "type=" .. MODEL .. "\r\n" ..
    "sn=" .. SERIAL .. "\r\n" ..
    "boot9=boot9.bin\r\n" ..
    "optdump=otp.mem\r\n" ..
    "optdec=otp_dec.mem\r\n" ..
    "nandcidfile=nand_cid.mem\r\n")
  if not ok then fail(err) end
end

-- ------------------------------------------------------------- 4. AES keys
say("")
say("AES keys:")

-- 4a) preferred: GodMode9's own DumpKeys output
local aes_txt = nil
for _, cand in ipairs({ GM9OUT .. "/aes_keys.txt", "0:/aes_keys.txt", GM9OUT .. "/7zctr-keys/aes_keys.txt" }) do
  if exists(cand) then aes_txt = cand; break end
end
if aes_txt then
  local data = read_all(aes_txt)
  if data then
    local n = 0
    for line in data:gmatch("[^\r\n]+") do
      local name, hex = line:match("^%s*([%w_]+)%s*=%s*(%x+)")
      if name and hex then
        emit_key(name, hex)
        n = n + 1
      end
    end
    say("  source: GodMode9 DumpKeys output, %d keys -> converted to loose .key files", n)
  else
    say("  aes_keys.txt exists but cannot be read")
  end
else
  -- 4b) fallback: the [K:] AESKEYDB drive
  say("  aes_keys.txt not found, trying [K:] AESKEYDB ...")
  local okK, list = pcall(fs.list_dir, "K:/")
  if okK and list then
    local n = 0
    for _, e in ipairs(list) do
      if e.type == "file" and e.name:lower():match("^slot0x%x%x") then
        local data = read_bytes("K:/" .. e.name, 0, 16)
        if data and #data >= 16 then
          local base = e.name:gsub("%.bin$", "")
          local unit = base:match("%.dev$") and "dev" or (base:match("%.ret$") and "ret" or nil)
          base = base:gsub("%.dev$", ""):gsub("%.ret$", "")
          emit_key(base, tohex(data:sub(1, 16)), unit)
          n = n + 1
        end
      end
    end
    say("  source: [K:] AESKEYDB, %d slots -> converted to loose .key files", n)
  else
    say("  no key source found.")
    say("  Run GodMode9's built-in  Scripts -> DumpKeys  first: it writes")
    say("  0:/gm9/out/aes_keys.txt, which this script converts into .key files.")
    say("  (Or put aeskeydb.bin in the SD root to use the [K:] AESKEYDB drive.)")
  end
end

-- ------------------------------------------------------------ 5. seed database
say("")
for _, p in ipairs({ "S:/ro/sys/seeddb.bin", "1:/ro/sys/seeddb.bin" }) do
  if copy_file(p, OUT .. "/seeddb.bin") then
    say("seeddb.bin: copied from %s", p)
    break
  end
end

-- ---------------------------------------------------------------- 6. readme
pcall(write_bytes, OUT .. "/README.txt",
  "7-Zip CTR key package\r\n" ..
  "=====================\r\n\r\n" ..
  "Copy the following into the folder that holds 7z.dll (merge with what is there):\r\n\r\n" ..
  "  keystone\\ctraes_retail\\   retail AES keys\r\n" ..
  "  keystone\\ctraes_dev\\      devkit AES keys\r\n" ..
  "  keystone\\pubkey\\          FIRM RSA-2048 public keys + pubkey.ini\r\n" ..
  "  keystone\\ctrdevice\\" .. SERIAL .. "\\  boot9 / OTP / NAND CID device profile\r\n" ..
  "  keystone_private\\         console-unique keys -- DO NOT upload anywhere\r\n" ..
  "  seeddb.bin                 goes next to 7z.dll\r\n\r\n" ..
  "Then open a .firm to check 'FIRM Signature = Valid', and open your nand.bin.\r\n")

-- ---------------------------------------------------------------- 7. summary
say("")
say("========== done ==========")
say("output : %s", OUT)
say("keys   : %d loose .key files (%d console-unique)", stats.keys, stats.priv)
say("files  : %d", stats.files)
if stats.fails > 0 then
  say("failures: %d (see [FAIL] lines above)", stats.fails)
end
say("layout : keystone/ctraes_retail/*.key  keystone/ctraes_dev/*.key")
say("         keystone/pubkey/*  keystone/ctrdevice/%s/*", SERIAL)
say("copy keystone/ + keystone_private/ + seeddb.bin next to 7z.dll")
ui.ask("Press A to exit")
