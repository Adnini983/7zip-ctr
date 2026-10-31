// N3dsHandler.cpp
// Nintendo 3DS container formats: CIA, NCSD (.3ds), NCCH (CXI/CFA), ExeFS, RomFS.
// Read-only archive handler for 7-Zip (inspired by 7-Zip ZS codec integration).

#define _CRT_SECURE_NO_WARNINGS
#include "StdAfx.h"

#pragma warning(disable: 4324)   // align specifier padding in CHandler

#include <stdio.h>
#include <stdarg.h>

#include "../../../C/CpuArch.h"
#include "../../../C/Aes.h"
#include "../../../C/Sha256.h"
#include "../../../C/Sha1.h"

#include "../../Common/ComTry.h"
#include "../../Common/IntToString.h"
#include "../../Common/MyBuffer.h"
#include "../../Common/MyCom.h"
#include "../../Common/MyString.h"
#include "../../Common/MyVector.h"

#include "../../Windows/PropVariant.h"
#include "../../Windows/PropVariantUtils.h"

#include "../Common/RegisterArc.h"
#include "../Common/StreamUtils.h"

namespace NArchive {
namespace NN3ds {

static const UInt64 kMediaUnit = 0x200;

#define MY_ALIGN_16(x)  (((x) + 15) & ~(UInt64)15)
#define MY_ALIGN_200(x) (((x) + 0x1FF) & ~(UInt64)0x1FF)

struct CItem
{
  UString Path;
  UInt64 Offset;   // absolute offset in the input stream
  UInt64 Size;
  bool IsDir;
  bool Encrypted;   // this item lives inside an AES-CBC encrypted CIA content
  bool UseNewKey;   // decrypt with the New3DS (commonN) title key
  UInt64 CryptStart; // absolute offset where the CBC chain starts (content start)
  Byte CryptCtr[16]; // CBC IV for that content (from TMD chunk index)
  bool HasInnerKey;   // NCCH data-region AES-CTR normal key present
  Byte InnerKey[16];  // copy of the NCCH normal key (fixed buffer, survives Parse)
  Byte InnerCtr[16];  // GetNcchCtr base (partitionId reversed + section byte)
  UInt64 InnerBase;       // absolute offset of the NCCH region start (ExeFS/RomFS base)
  UInt64 InnerOff;        // byte offset from region start where the region's counter starts
  bool Virtual;           // metadata-only placeholder (CDN TMD content listing); no embedded bytes
  bool StreamCtr;         // NAND partition: bulk sequential AES-CTR from absolute offset
  bool StreamTwl;         // TWL (slot0x03) partition: DSi-scrambler AES-CTR + per-block reversal
  UInt64 GetSize() const { return Size; }
};

// Archive-level technical info (NCSD / CIA / NCCH headers), shown in the
// 7zFM "Properties" dialog via IArchive::GetArchivePropertyInfo/GetArchiveProperty.
// Mirrors the fields ctrtool prints (see 3DSGuy/Project_CTR ctrtool Cci/Cia/NcchProcess).
// (Named CN3dsInfo to avoid clashing with 7-Zip's own CArcInfo used by RegisterArc.)
struct CN3dsInfo
{
  int Container;                 // 0=none,1=CIA,2=NCSD,3=NCCH,4=CDN TMD,5=plain RomFS,6=plain ExeFS
  bool IsCia() const { return Container == 1; }
  bool IsNcsd() const { return Container == 2; }
  bool IsNcch() const { return Container == 3; }
  bool IsTmd() const { return Container == 4; }
  bool IsRomfs() const { return Container == 5; }
  bool IsExefs() const { return Container == 6; }
  bool IsFirm() const { return Container == 7; }

  // ---- CDN TMD (title metadata) ----
  char   Issuer[0x41];           // signing issuer string, e.g. Root-CA00000003-CP0000000b
  UInt32 TmdTitleType;            // header+0x54
  UInt16 TmdGroupId;             // header+0x58

  // ---- CIA header (offset 0x00, 0x20 bytes) ----
  UInt32 CiaType;                // low16
  UInt32 CiaVersion;             // high16
  UInt64 CiaContentSize;

  // ---- Ticket (at offsetTicket) ----
  UInt64 TicketId;               // 0x9C
  UInt32 DeviceId;               // 0xA4
  UInt64 TitleId;                // 0xA8
  UInt32 CommonKeyIdx;           // 0x1F1
  Byte   TitleKey[16];           // decrypted (if available)
  bool   HasTitleKey;

  // ---- TMD ----
  UInt16 TmdTitleVersion;        // 0xAC
  UInt16 ContentCount;           // 0xAE
  UInt32 Content0Id;             // first content record id
  UInt64 Content0Size;

  // ---- NCSD header (0x100) ----
  UInt64 MediaId;                // 0x108 (card title id)
  UInt32 NumPartitions;
  bool TwlFailed;                // NAND: TWL (slot0x03) key could not be derived

  // ---- NCCH header (0x100) ----
  UInt64 NcchTitleId;            // 0x108
  UInt64 ProgramId;              // 0x118
  UInt16 NcchVersion;            // 0x112
  UInt16 MakerCode;              // 0x110
  char   ProductCode[0x10];      // 0x128
  Byte   NcchFlags[8];           // 0x180
  UInt32 Crypto;                 // 0=none 1=fixed 2=secure 3=seeded
  UInt32 SeedIndex;              // 0x1BC
  UInt64 ExeFsOff, ExeFsSize;    // 0x198
  UInt64 RomFsOff, RomFsSize;    // 0x1A0

  // ---- FIRM (standalone .firm: NATIVE/SAFE_MODE/TWL/AGB/homebrew) ----
  // signature state: 0=unknown/not-verified, 1=valid (official), 2=sighax/homebrew,
  // 3=corrupt/missing
  int    FirmSigState;
  int    FirmSectionsOk;         // sections whose embedded SHA-256 matched
  int    FirmSectionsTotal;
  UInt32 FirmArm9Entry;         // header+0x00C
  UInt32 FirmArm11Entry;        // header+0x008
  char   FirmKind[24];          // heuristic label: NATIVE / SAFE_MODE / TWL / AGB / HOMEBREW

  void Clear() { memset(this, 0, sizeof(*this)); Container = 0; }
};

static UString NumToUString(UInt32 v)
{
  char buf[32];
  ConvertUInt32ToString(v, buf);
  return UString(buf);
}

static UString HexUInt64(UInt64 v)
{
  char buf[32];
  ConvertUInt64ToHex(v, buf);
  return UString(buf);
}

// 16-digit zero-padded lowercase hex (used for CIA file naming from title id)
static UString HexUInt64Padded(UInt64 v)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)v);
  return UString(buf);
}

static UString HexUInt32(UInt32 v)
{
  char buf[32];
  ConvertUInt32ToHex(v, buf);
  return UString(buf);
}

static UString BytesToHex(const Byte *p, unsigned n)
{
  char buf[512];
  unsigned k = 0;
  for (unsigned i = 0; i < n && k + 2 < sizeof(buf); i++)
  {
    buf[k++] = "0123456789ABCDEF"[p[i] >> 4];
    buf[k++] = "0123456789ABCDEF"[p[i] & 0xF];
  }
  buf[k] = 0;
  return UString(buf);
}

static UString ReadAscii(const Byte *p, unsigned n)
{
  char buf[32];
  unsigned k = 0;
  for (unsigned i = 0; i < n && k + 1 < sizeof(buf); i++)
    if (p[i] >= 0x20 && p[i] < 0x7F)
      buf[k++] = (char)p[i];
    else
      buf[k++] = ' ';
  buf[k] = 0;
  return UString(buf);
}

// ----------------------------------------------------------------
// External 3DS keys - NEVER hardcoded.
// Default folders (next to 7z.dll, overridable in keystone.ini):
//   <7z.dll dir>\keystone\ctraes_retail\*.key  (retail)
//   <7z.dll dir>\keystone\ctraes_dev\*.key     (developer)
// Custom folders are set in <7z.dll dir>\keystone.ini, section [Keystone],
// keys RetailCTRAESKeyDir= / DevCTRAESKeyDir=; absolute paths are used as-is,
// relative paths resolve against the 7z.dll directory. Each key file holds one
// key as text:
// "KeyName=XXXXXXXX...XXXX" (32 hex chars). See 3dbrew AES_Registers.
// ----------------------------------------------------------------
static UString GetDllDirectory()
{
  HMODULE h = NULL;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
      (LPCWSTR)(const void *)(void *)&GetDllDirectory, &h))
    return UString();
  wchar_t buf[MAX_PATH];
  DWORD n = GetModuleFileNameW(h, buf, MAX_PATH);
  if (n == 0)
    return UString();
  UString path(buf);
  int pos = path.ReverseFind(L'\\');
  if (pos < 0)
    return UString();
  return path.Left(pos);
}

// ---- keystone.ini: optional custom key folders ---------------------------
static bool KeystoneIsAbsPath(const UString &s)
{
  if (s.Len() >= 2 && s[1] == L':') return true;            // drive:
  if (s.Len() >= 2 && s[0] == L'\\' && s[1] == L'\\') return true; // UNC
  return false;
}

// drop leading/trailing whitespace, surrounding quotes and a trailing backslash
static UString KeystoneSimplify(const UString &v)
{
  unsigned i = 0, n = v.Len();
  while (i < n)
  {
    wchar_t c = v[i];
    if (c != L' ' && c != L'\t' && c != L'"') break;
    i++;
  }
  unsigned j = n;
  while (j > i)
  {
    wchar_t c = v[j - 1];
    if (c != L' ' && c != L'\t' && c != L'"' && c != L'\\') break;
    j--;
  }
  return v.Mid(i, j - i);
}

static UString ReadKeystoneIni(const UString &dllDir, const wchar_t *key)
{
  wchar_t buf[MAX_PATH] = { 0 };
  UString ini = dllDir + UString(L"\\keystone.ini");
  GetPrivateProfileStringW(L"Keystone", key, L"", buf, MAX_PATH, ini.Ptr());
  return UString(buf);
}

// empty config -> built-in default relative folder; absolute used as-is;
// relative resolves against the 7z.dll directory.
static UString ResolveKeystoneDir(const UString &dllDir, const UString &cfg, const wchar_t *defRel)
{
  UString v = KeystoneSimplify(cfg);
  if (v.IsEmpty())
    return dllDir + UString(L"\\") + defRel;
  if (KeystoneIsAbsPath(v))
    return v;
  return dllDir + UString(L"\\") + v;
}

static Byte HexToByte(wchar_t c)
{
  if (c >= L'0' && c <= L'9') return (Byte)(c - L'0');
  if (c >= L'a' && c <= L'f') return (Byte)(c - L'a' + 10);
  if (c >= L'A' && c <= L'F') return (Byte)(c - L'A' + 10);
  return 0xFF;
}

// keep only [0-9a-z] (lowercased) - so "slot0x03KeyX" and "slot0x03keyx" match
static UString NormalizeKeyName(const UString &s)
{
  UString r;
  for (unsigned i = 0; i < s.Len(); i++)
  {
    wchar_t c = s[i];
    if (c >= L'0' && c <= L'9')
      r += c;
    else if (c >= L'a' && c <= L'z')
      r += c;
    else if (c >= L'A' && c <= L'Z')
      r += (wchar_t)(c - L'A' + L'a');
  }
  return r;
}

struct CKeyEntry
{
  UString Name;   // normalized, lowercase, alphanumeric
  Byte Data[16];
  bool IsDev;
};

// forward declarations; implemented in the unified-cache section below
static UInt64 DirSig64(const UString &dir, const wchar_t *pattern);
static bool KeystoneCacheSigPresent(Byte type, UInt64 sig);
static void KeystoneCacheAppendKey(const UString &name, const Byte data[16], bool isDev, UInt64 sig);
static bool LoadFirmModulusCached(bool dev, Byte N[256]);

class C3dsKeys
{
  CObjectVector<CKeyEntry> _keys;
  bool _loaded;
  unsigned _retail;
  unsigned _dev;

  void LoadDir(const UString &dir, bool isDev)
  {
    UString pattern = dir + UString(L"\\*.key");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
      return;
    do
    {
      if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        LoadFile(dir + UString(L"\\") + (const wchar_t *)fd.cFileName, isDev);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }

  void LoadFile(const UString &path, bool isDev)
  {
    FILE *f = NULL;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f)
      return;
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    // locate '='
    int eq = -1;
    for (int i = 0; i < (int)n; i++)
      if (buf[i] == '=')
      {
        eq = i;
        break;
      }

    UString name;
    if (eq >= 0)
    {
      for (int i = 0; i < eq; i++)
        name += (wchar_t)buf[i];
    }
    else
    {
      // fall back to file name
      name = path;
      int slash = name.ReverseFind(L'\\');
      if (slash >= 0)
        name = name.Ptr(slash + 1);
      int dot = name.ReverseFind(L'.');
      if (dot >= 0)
        name = name.Left(dot);
    }
    name = NormalizeKeyName(name);
    if (name.IsEmpty() || name.Len() > 64)
      return;

    Byte data[16];
    bool ok = false;
    if (eq >= 0)
    {
      int pos = eq + 1;
      int got = 0;
      while (pos < (int)n && got < 16)
      {
        Byte hi = HexToByte((wchar_t)(unsigned char)buf[pos]);
        if (hi == 0xFF) { pos++; continue; }
        if (pos + 1 < (int)n)
        {
          Byte lo = HexToByte((wchar_t)(unsigned char)buf[pos + 1]);
          if (lo != 0xFF)
          {
            data[got++] = (Byte)((hi << 4) | lo);
            pos += 2;
            continue;
          }
        }
        pos++;
      }
      ok = (got == 16);
    }
    else
    {
      // no '=' : treat as raw 16-byte binary key
      if (n >= 16)
      {
        memcpy(data, buf, 16);
        ok = true;
      }
    }
    if (!ok)
      return;

    for (unsigned i = 0; i < _keys.Size(); i++)
      if (_keys[i].Name == name && _keys[i].IsDev == isDev)
        return;   // already present

    CKeyEntry e;
    e.Name = name;
    e.IsDev = isDev;
    memcpy(e.Data, data, 16);
    _keys.Add(e);
    if (isDev)
      _dev++;
    else
      _retail++;
  }

public:
  C3dsKeys(): _loaded(false), _retail(0), _dev(0) {}

  void EnsureLoaded()
  {
    if (_loaded)
      return;
    _loaded = true;
    UString dll = GetDllDirectory();
    if (dll.IsEmpty())
      return;
    UString retailDir = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"RetailCTRAESKeyDir"), L"keystone\\ctraes_retail");
    UString devDir   = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"DevCTRAESKeyDir"),    L"keystone\\ctraes_dev");
    LoadDir(retailDir, false);
    LoadDir(devDir, true);

    // persist the loaded AES keys into the single obfuscated cache file;
    // skip a folder whose records are already cached (sig unchanged) to avoid bloat
    UInt64 retailSig = DirSig64(retailDir, L"*.key");
    UInt64 devSig   = DirSig64(devDir,   L"*.key");
    bool haveRetail = KeystoneCacheSigPresent(1, retailSig);
    bool haveDev    = KeystoneCacheSigPresent(1, devSig);
    for (unsigned i = 0; i < _keys.Size(); i++)
    {
      const CKeyEntry &e = _keys[i];
      if (e.IsDev ? haveDev : haveRetail)
        continue;
      KeystoneCacheAppendKey(e.Name, e.Data, e.IsDev, e.IsDev ? devSig : retailSig);
    }
  }

  // Drop the process-static key table; next EnsureLoaded() re-enumerates the folders.
  void Invalidate()
  {
    _loaded = false;
    _keys.Clear();
    _retail = 0;
    _dev = 0;
  }

  // name must already be normalized (lowercase alphanumeric); isDev selects the dev/retail table
  const Byte *Find(const char *name, bool isDev) const
  {
    unsigned len = (unsigned)strlen(name);
    for (unsigned i = 0; i < _keys.Size(); i++)
    {
      const CKeyEntry &e = _keys[i];
      if (e.IsDev != isDev || e.Name.Len() != len)
        continue;
      unsigned j;
      for (j = 0; j < len; j++)
      {
        wchar_t a = e.Name[j];
        char b = name[j];
        if (a != (wchar_t)(unsigned char)b)
          break;
      }
      if (j == len)
        return e.Data;
    }
    return NULL;
  }

  unsigned Retail() const { return _retail; }
  unsigned Dev() const { return _dev; }

  // ---- seeddb.bin support (GodMode9 SeedInfo): 32 bytes/entry,
  //   titleId (u64 LE) + seed[16] + reserved[8], entries start at offset 16.
  bool FindSeed(Byte *seed, UInt64 titleId, UInt32 hashSeed) const
  {
    UString dll = GetDllDirectory();
    if (dll.IsEmpty())
      return false;
    UString p = dll + UString(L"\\seeddb.bin");
    FILE *f = NULL;
    if (_wfopen_s(&f, p, L"rb") != 0 || !f)
      return false;
    // read header (16 bytes) + entries
    Byte hdr[16];
    size_t rh = fread(hdr, 1, 16, f);
    UInt32 n = (rh >= 4) ? GetUi32(hdr) : 0;
    if (n > 4096)   // sanity
      n = 0;
    bool found = false;
    Byte seedBuf[16];
    for (UInt32 i = 0; i < n; i++)
    {
      Byte ent[32];
      if (fread(ent, 1, 32, f) != 32)
        break;
      UInt64 t = GetUi64(ent);
      if (t != titleId)
        continue;
      memcpy(seedBuf, ent + 8, 16);
      // validate: SHA256(seed || titleId LE); its first 4 bytes as a
      // little-endian u32 must equal the NCCH hash_seed field (u32 LE).
      Byte msg[24];
      memcpy(msg, seedBuf, 16);
      memcpy(msg + 16, ent, 8);   // titleId LE
      Byte dg[32];
      CSha256 st;
      Sha256_Init(&st);
      Sha256_Update(&st, msg, 24);
      Sha256_Final(&st, dg);
      if (GetUi32(dg) == hashSeed)
      {
        memcpy(seed, seedBuf, 16);
        found = true;
        break;
      }
    }
    fclose(f);
    return found;
  }

  static C3dsKeys &Instance()
  {
    static C3dsKeys g;
    return g;
  }
};

// RomFS names are UTF-16LE (read as u16 on little-endian host, per GodMode9), null-terminated.
static UString ReadName16BE(const Byte *p, UInt32 sizeBytes)
{
  UString s;
  UInt32 i = 0;
  for (; i + 1 < sizeBytes; i += 2)
  {
    UInt32 c = GetUi16(p + i);
    if (c == 0)
      break;
    s += (wchar_t)c;
  }
  return s;
}

// ExeFS names are 8-byte ASCII, space padded.
static UString ReadName8(const Byte *p)
{
  UString s;
  for (unsigned i = 0; i < 8 && p[i] != 0 && p[i] != ' '; i++)
    s += (wchar_t)p[i];
  return s;
}

// Validate an ExeFS header (there is no magic): the 10 file entries must be
// plausible (GodMode9 ValidateExeFsHeader). Returns true if at least one entry
// is valid.
static bool ValidExeFsHdr(const Byte *hdr)
{
  UInt32 n = 0;
  for (unsigned i = 0; i < 10; i++)
  {
    const Byte *e = hdr + i * 0x10;
    UInt32 off = GetUi32(e + 8);
    UInt32 size = GetUi32(e + 12);
    if (size == 0)
      continue;
    if (e[0] == 0)            // zero filename
      return false;
    if ((off % (UInt32)kMediaUnit) != 0)
      return false;
    if (size >= 0xFFFFFE00)
      return false;
    n++;
  }
  return n != 0;
}

// ----------------------------------------------------------------
// AES-CBC helpers (7-Zip C/Aes). CIA content and title keys are AES-CBC
// (GodMode9 AES_CNT_TITLEKEY_DECRYPT_MODE).
// ----------------------------------------------------------------
static struct CAesGen { CAesGen() { AesGenTables(); } } g_AesGen;

// state must be __declspec(align(16)) UInt32[AES_NUM_IVMRK_WORDS]
static void AesCbc_Start(UInt32 *state, const Byte *key, const Byte *iv)
{
  Aes_SetKey_Dec(state + 4, key, 16);
  AesCbc_Init(state, iv);
}

static void AesCbc_Step(UInt32 *state, Byte *data, size_t numBlocks)
{
  g_AesCbc_Decode(state, data, numBlocks);
}

// CBC single shot on a 16-byte-aligned data array (numBlocks)
static void AesCbc_Block(const Byte *key, const Byte *iv, Byte *data, size_t numBlocks)
{
  __declspec(align(16)) UInt32 state[AES_NUM_IVMRK_WORDS];
  AesCbc_Start(state, key, iv);
  AesCbc_Step(state, data, numBlocks);
}

// 3DS keyslot keyscrambler (hardware key generator):
//   NormalKey = (((KeyX ROL 2) XOR KeyY) + C1) ROR 41   over 128-bit big-endian wraparound
//   C1 = 0x<redacted-key>
static void C3dsNormalKey(Byte nk[16], const Byte *keyX, const Byte *keyY)
{
  const UInt64 C1hi = (UInt64)0x1FF9E9AAC5FE0408ull;
  const UInt64 C1lo = (UInt64)0x024591DC5D52768Aull;
  UInt64 xh = ((UInt64)keyX[0]<<56)|((UInt64)keyX[1]<<48)|((UInt64)keyX[2]<<40)|((UInt64)keyX[3]<<32)
            | ((UInt64)keyX[4]<<24)|((UInt64)keyX[5]<<16)|((UInt64)keyX[6]<<8)|((UInt64)keyX[7]);
  UInt64 xl = ((UInt64)keyX[8]<<56)|((UInt64)keyX[9]<<48)|((UInt64)keyX[10]<<40)|((UInt64)keyX[11]<<32)
            | ((UInt64)keyX[12]<<24)|((UInt64)keyX[13]<<16)|((UInt64)keyX[14]<<8)|((UInt64)keyX[15]);
  UInt64 yh = ((UInt64)keyY[0]<<56)|((UInt64)keyY[1]<<48)|((UInt64)keyY[2]<<40)|((UInt64)keyY[3]<<32)
            | ((UInt64)keyY[4]<<24)|((UInt64)keyY[5]<<16)|((UInt64)keyY[6]<<8)|((UInt64)keyY[7]);
  UInt64 yl = ((UInt64)keyY[8]<<56)|((UInt64)keyY[9]<<48)|((UInt64)keyY[10]<<40)|((UInt64)keyY[11]<<32)
            | ((UInt64)keyY[12]<<24)|((UInt64)keyY[13]<<16)|((UInt64)keyY[14]<<8)|((UInt64)keyY[15]);
  // ROL 2 over 128 bits
  UInt64 rh = (xh << 2) | (xl >> 62);
  UInt64 rl = (xl << 2) | (xh >> 62);
  // XOR keyY
  rh ^= yh;
  rl ^= yl;
  // + C1 (mod 2^128)
  UInt64 sl = rl + C1lo;
  UInt64 carry = (sl < rl) ? (UInt64)1 : (UInt64)0;
  UInt64 sh = rh + C1hi + carry;
  // ROR 41
  UInt64 nh = (sh >> 41) | (sl << 23);
  UInt64 nl = ((sh & (((UInt64)1 << 41) - 1)) << 23) | (sl >> 41);
  nk[0]=(Byte)(nh>>56); nk[1]=(Byte)(nh>>48); nk[2]=(Byte)(nh>>40); nk[3]=(Byte)(nh>>32);
  nk[4]=(Byte)(nh>>24); nk[5]=(Byte)(nh>>16); nk[6]=(Byte)(nh>>8);  nk[7]=(Byte)(nh);
  nk[8]=(Byte)(nl>>56); nk[9]=(Byte)(nl>>48); nk[10]=(Byte)(nl>>40); nk[11]=(Byte)(nl>>32);
  nk[12]=(Byte)(nl>>24); nk[13]=(Byte)(nl>>16); nk[14]=(Byte)(nl>>8); nk[15]=(Byte)(nl);
}

// 3DS hardware AES-CTR (CTRNAND mode): the whole 128-bit counter is
// incremented as a big-endian integer, counter + (offsetBytes/16) per block.
static void AddCtrBe(Byte *ctr, UInt32 v)
{
  UInt32 carry = v;
  for (int i = 15; i >= 0 && carry != 0; i--)
  {
    UInt32 s = (UInt32)ctr[i] + carry;
    carry = s >> 8;
    ctr[i] = (Byte)(s & 0xFF);
  }
}

// Decrypt (XOR keystream) an NCCH data region with 3DS AES-CTR.
// key     : the normal key (keyscrambler result)
// ctr128  : 16-byte counter base (GetNcchCtr output)
// offBytes: byte offset into the region to start the counter at (adds offBytes/16 to the counter)
static void AesCtr_Decode3ds(const Byte *key, const Byte *ctr128, UInt64 offBytes, Byte *data, size_t size)
{
  __declspec(align(16)) UInt32 aes[AES_NUM_IVMRK_WORDS];
  Byte ctr[16];
  memcpy(ctr, ctr128, 16);
  UInt32 blockAdd = (UInt32)(offBytes >> 4);   // whole 16-byte blocks
  UInt32 byteOff  = (UInt32)(offBytes & 15);   // unaligned remainder
  AddCtrBe(ctr, blockAdd);
  Aes_SetKey_Enc(aes + 4, key, 16);
  size_t pos = 0;
  bool first = true;
  while (pos < size)
  {
    __declspec(align(16)) Byte blk[16];
    memcpy(blk, ctr, 16);
    memset(aes, 0, 16);           // IV = 0 -> single-block CBC-encode = AES_encrypt
    g_AesCbc_Encode(aes, blk, 1); // blk = AES_enc(ctr)
    size_t from = first ? byteOff : 0;
    size_t take = 16 - from;
    if (take > size - pos)
      take = size - pos;
    for (size_t j = 0; j < take; j++)
      data[pos + j] ^= blk[from + j];
    pos += take;
    first = false;
    AddCtrBe(ctr, 1);
  }
}

// ---- TWL (slot0x03, DSi NAND) -------------------------------------------
// DSi keyscrambler (different from the 3DS formula):
//   NormalKey = ROL128( (KeyX_int XOR KeyY_int) + C2, 42 )
// KeyX/KeyY are 128-bit integers read LITTLE-endian; the result is emitted
// BIG-endian as the AES normal key. C2 = 0xFFFEFB4E295902582A680F5F1A4F3E79.
// kxBytes16 is KeyX already laid out as a LE-128 memory image (lo4 + fixed8 + hi4).
static UInt64 ReadLe64(const Byte *p)
{
  return (UInt64)p[0]
      | ((UInt64)p[1] << 8) | ((UInt64)p[2] << 16) | ((UInt64)p[3] << 24)
      | ((UInt64)p[4] << 32) | ((UInt64)p[5] << 40) | ((UInt64)p[6] << 48)
      | ((UInt64)p[7] << 56);
}

static void WriteBe64(Byte *p, UInt64 v)
{
  p[0]=(Byte)(v>>56); p[1]=(Byte)(v>>48); p[2]=(Byte)(v>>40); p[3]=(Byte)(v>>32);
  p[4]=(Byte)(v>>24); p[5]=(Byte)(v>>16); p[6]=(Byte)(v>>8);  p[7]=(Byte)(v);
}

static void CDsiNormalKey(Byte nk[16], const Byte *kxBytes16, bool dev)
{
  const UInt64 C2hi = (UInt64)0xFFFEFB4E29590258ull;
  const UInt64 C2lo = (UInt64)0x2A680F5F1A4F3E79ull;
  // fixed KeyY literal integers (high64, low64)
  UInt64 kyh, kyl;
  if (dev)
  { kyh=(UInt64)0xE1A00005266A6497ull; kyl=(UInt64)0x66E8B87AF176BFAAull; }
  else
  { kyh=(UInt64)0xE1A00005202DDD1Dull; kyl=(UInt64)0xBD4DC4D30AB9DC76ull; }

  UInt64 kxh = ReadLe64(kxBytes16 + 8);
  UInt64 kxl = ReadLe64(kxBytes16);

  UInt64 th = kxh ^ kyh;
  UInt64 tl = kxl ^ kyl;
  UInt64 sl = tl + C2lo;
  UInt64 carry = (sl < tl) ? (UInt64)1 : (UInt64)0;
  UInt64 sh = th + C2hi + carry;

  // ROL 42 over the 128-bit SUM (sh:sl), not the pre-add XOR (sh:tl)
  UInt64 nh = (sh << 42) | (sl >> 22);
  UInt64 nl = (sl << 42) | (sh >> 22);

  WriteBe64(nk, nh);
  WriteBe64(nk + 8, nl);
}

// TWL AES-CTR: same BE counter progression as 3DS CTR, but every 16-byte block
// reverses its bytes before feeding the stream and reverses the output block
// (DSi endianness). Equivalent to out[j] = in[j] XOR AES_enc(ctr)[15-j].
static void AesCtr_DecodeTwl(const Byte *key, const Byte *ctr128, UInt64 offBytes, Byte *data, size_t size)
{
  __declspec(align(16)) UInt32 aes[AES_NUM_IVMRK_WORDS];
  Byte ctr[16];
  memcpy(ctr, ctr128, 16);
  UInt32 blockAdd = (UInt32)(offBytes >> 4);
  UInt32 byteOff  = (UInt32)(offBytes & 15);
  AddCtrBe(ctr, blockAdd);
  Aes_SetKey_Enc(aes + 4, key, 16);
  size_t pos = 0;
  bool first = true;
  while (pos < size)
  {
    __declspec(align(16)) Byte blk[16];
    memcpy(blk, ctr, 16);
    memset(aes, 0, 16);
    g_AesCbc_Encode(aes, blk, 1);   // blk = AES_enc(ctr), used reversed as keystream
    size_t from = first ? byteOff : 0;
    size_t take = 16 - from;
    if (take > size - pos)
      take = size - pos;
    for (size_t j = 0; j < take; j++)
      data[pos + j] ^= blk[15 - (from + j)];
    pos += take;
    first = false;
    AddCtrBe(ctr, 1);
  }
}

// SHA256(sig16 || seed16) -> first 16 bytes (seed key Y).
static void NcchSeedKeyY(Byte keyY[16], const Byte *sig16, const Byte *seed)
{
  Byte msg[32];
  memcpy(msg, sig16, 16);
  memcpy(msg + 16, seed, 16);
  Byte dg[32];
  CSha256 st;
  Sha256_Init(&st);
  Sha256_Update(&st, msg, 32);
  Sha256_Final(&st, dg);
  memcpy(keyY, dg, 16);
}

// ----------------------------------------------------------------
// ctrdevice: console-unique NAND key material loaded from
//   <dll>\keystone\ctrdevice\<SN>\  (boot9.bin, otp.mem / otp_dec.mem,
//   nand_cid.mem or nandcidhex, ctrindex.ini).
// Derives slot0x04-0x07 normalkeys through the boot9 keyinit and the
// CTRNAND AES-CTR nonce = SHA256(nand_cid)[0:16]. No per-device key is
// hardcoded here. slot0x03 (TWL, DSi NAND) is derived separately in
// CDsiNormalKey from the encrypted OTP first 8 bytes + a fixed DSi KeyY
// via the DSi keyscrambler, with a per-block-reversed AES-CTR counter =
// BE128(LE128(SHA1(nand_cid)[:16])).
// ----------------------------------------------------------------
struct CDeviceNand
{
  UString Sn;
  bool IsDev;
  bool IsSnake;
  Byte Nonce[16];       // CTRNAND CTR nonce = SHA256(nand_cid)[:16]
  Byte Nk[8][16];
  bool HasSlot[8];
  // ---- TWL (slot0x03, DSi NAND) console-unique material ----
  Byte OtpEnc8[8];      // encrypted OTP[0:8] (dev) used to build the TWL KeyX
  Byte Cid16[16];       // nand_cid raw, source of the TWL counter
  Byte TwlNk[16];       // derived TWL normal key (DSi keyscrambler)
  Byte TwlNonce[16];    // BE128(LE128(SHA1(cid)[:16]))
  bool HasTwl;
  // Runtime-only, NOT serialized into the cache snapshot: when the user picks an
  // Old/New 3DS in the bare-material prompt, only that CTRNAND slot is tried
  // (-1 = auto, try both slot0x04 and slot0x05).
  int SlotWanted;
  CDeviceNand()
  {
    // Zero the POD members explicitly. Do NOT memset the whole struct: that wipes
    // the UString Sn's internal pointer into a broken shell that crashes on copy.
    IsDev = false;
    IsSnake = false;
    HasTwl = false;
    SlotWanted = -1;
    memset(Nonce, 0, sizeof(Nonce));
    memset(Nk, 0, sizeof(Nk));
    memset(HasSlot, 0, sizeof(HasSlot));
    memset(OtpEnc8, 0, sizeof(OtpEnc8));
    memset(Cid16, 0, sizeof(Cid16));
    memset(TwlNk, 0, sizeof(TwlNk));
    memset(TwlNonce, 0, sizeof(TwlNonce));
  }
};

static bool ReadRawFile(const UString &path, Byte *buf, unsigned maxLen, unsigned &got)
{
  FILE *f = NULL;
  got = 0;
  if (_wfopen_s(&f, path, L"rb") != 0 || !f)
    return false;
  got = (unsigned)fread(buf, 1, maxLen, f);
  fclose(f);
  return got > 0;
}

static void Hex16FromText(const UString &hex, Byte out[16])
{
  memset(out, 0, 16);
  unsigned got = 0;
  for (unsigned i = 0; i + 1 < hex.Len() && got < 16; i++)
  {
    Byte hi = HexToByte(hex[i]);
    Byte lo = HexToByte(hex[i + 1]);
    if (hi != 0xFF && lo != 0xFF)
    {
      out[got++] = (Byte)((hi << 4) | lo);
      i++;
    }
  }
}

// ---- FIRM RSA-2048 public modulus (external; never hardcoded) -------------
// Source priority for a unit (retail/dev):
//   1) keystone.ini [Keystone] RetailFirmPubKeyHex= / DevFirmPubKeyHex= (512 hex)
//   2) RetailFirmPubKeyFile= / DevFirmPubKeyFile= (256B big-endian binary, or hex text)
//   3) FirmPubKeyDir= folder (default keystone\pubkey). This folder is managed
//      by its OWN independent .ini file "pubkey.ini" ([FirmPubKey] section):
//        RetailFirmPubKeyHex= / DevFirmPubKeyHex=  (512-hex plaintext modulus)
//        RetailFirmPubKeyFile= / DevFirmPubKeyFile= (standalone 256B big-endian
//            modulus files: retail_firm_pubkey.bin / dev_firm_pubkey.bin, e=65537)
//      Hex keys take precedence over the file keys inside pubkey.ini; boot9.bin
//      must NOT be placed in this folder.
//      If pubkey.ini is missing/corrupt or neither the hex nor the referenced
//      files can be used, fall through to the ctrdevice scan below.
//   4) FirmBoot9Path= explicit boot9.bin.
//   5) ctrdevice scan: each per-console sub-folder under DeviceDataDir
//      (default keystone\ctrdevice) is examined for its "ctrindex.ini"; the
//      [ctrindex] "boot9=" key locates the usable boot9.bin (relative to that
//      sub-folder or absolute). A private 64KB boot9 dump holds BOTH key sets:
//      keyslot1 NAND-FIRM modulus retail @0xB1E0 / dev @0xC4E0.
//      If NO ctrindex.ini with a usable boot9= is found, no public key is
//      loaded and FIRM signature verification is SKIPPED entirely (the archive
//      reports "Not verified (no public key loaded)").
// The successful load is persisted into the unified keystone.cache (type=3
// record) so later opens skip the file/hex/ctrdevice scan; "Rebuild cache" in
// the options page drops it together with the other cached records.
static unsigned HexStrToBytesN(const UString &hex, Byte *out, unsigned max)
{
  memset(out, 0, max);
  unsigned n = 0;
  bool hi = true;
  Byte cur = 0;
  for (unsigned i = 0; i < hex.Len() && n < max; i++)
  {
    Byte v = HexToByte(hex[i]);
    if (v == 0xFF)
      continue;
    if (hi) { cur = v; hi = false; }
    else { out[n++] = (Byte)((cur << 4) | v); hi = true; }
  }
  return n;
}

// Read a standalone FIRM public-key file: 256B big-endian modulus, or hex text.
static bool ReadFirmPubKeyFile(const UString &p, Byte N[256])
{
  Byte buf[2048];
  unsigned got = 0;
  if (!ReadRawFile(p, buf, sizeof(buf), got) || got == 0)
    return false;
  if (got == 256)
  {
    memcpy(N, buf, 256);
    return true;
  }
  UString hs;
  for (unsigned i = 0; i < got; i++)
    hs += (wchar_t)buf[i];
  return HexStrToBytesN(hs, N, 256) == 256;
}

// Read a "boot9=" path from a per-console ctrindex.ini and extract the keyslot1
// NAND-FIRM modulus for the requested unit (retail @0xB1E0 / dev @0xC4E0).
static bool ReadBoot9FromCtrindex(const UString &iniDir, bool dev, Byte N[256])
{
  UString ini = iniDir + UString(L"\\ctrindex.ini");
  wchar_t buf[MAX_PATH] = { 0 };
  GetPrivateProfileStringW(L"ctrindex", L"boot9", L"", buf, MAX_PATH, ini.Ptr());
  if (!buf[0])
    return false;
  UString b9 = UString(buf);
  UString p = KeystoneIsAbsPath(b9) ? b9 : iniDir + UString(L"\\") + b9;
  unsigned got = 0;
  Byte b9b[65536];
  if (!ReadRawFile(p, b9b, sizeof(b9b), got) || got < 65536)
    return false;
  memcpy(N, b9b + (dev ? 0xC4E0 : 0xB1E0), 256);
  return N[255] != 0;
}

static bool LoadFirmModulus(bool dev, Byte N[256])
{
  memset(N, 0, 256);
  UString dll = GetDllDirectory();

  UString hex = ReadKeystoneIni(dll, dev ? L"DevFirmPubKeyHex" : L"RetailFirmPubKeyHex");
  if (HexStrToBytesN(hex, N, 256) == 256)
    return true;

  UString fp = ReadKeystoneIni(dll, dev ? L"DevFirmPubKeyFile" : L"RetailFirmPubKeyFile");
  if (!fp.IsEmpty())
  {
    UString p = KeystoneIsAbsPath(fp) ? fp : dll + UString(L"\\") + fp;
    if (ReadFirmPubKeyFile(p, N))
      return true;
  }

  // Standalone FIRM public-key folder (FirmPubKeyDir=, default keystone\pubkey).
  // It is managed by its OWN independent "pubkey.ini" ([FirmPubKey] section)
  // which names the modulus files. The folder holds ONLY those extracted 256B
  // big-endian RSA-2048 moduli - never a boot9.bin dump:
  //   pubkey.ini
  //   retail_firm_pubkey.bin / dev_firm_pubkey.bin
  UString kd = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"FirmPubKeyDir"), L"keystone\\pubkey");
  {
    UString ini = kd + UString(L"\\pubkey.ini");
    // pubkey.ini may carry the modulus directly as 512-hex plaintext; that
    // takes precedence over the named 256B files inside the same ini.
    wchar_t hexBuf[2048] = { 0 };
    GetPrivateProfileStringW(L"FirmPubKey",
        dev ? L"DevFirmPubKeyHex" : L"RetailFirmPubKeyHex",
        L"", hexBuf, 2048, ini.Ptr());
    if (HexStrToBytesN(UString(hexBuf), N, 256) == 256)
      return true;
    wchar_t buf[MAX_PATH] = { 0 };
    GetPrivateProfileStringW(L"FirmPubKey",
        dev ? L"DevFirmPubKeyFile" : L"RetailFirmPubKeyFile",
        dev ? L"dev_firm_pubkey.bin" : L"retail_firm_pubkey.bin",
        buf, MAX_PATH, ini.Ptr());
    UString fn = UString(buf);
    if (fn.IsEmpty())
      fn = UString(dev ? L"dev_firm_pubkey.bin" : L"retail_firm_pubkey.bin");
    UString p = KeystoneIsAbsPath(fn) ? fn : kd + UString(L"\\") + fn;
    if (ReadFirmPubKeyFile(p, N))
      return true;
    // pubkey.ini missing/corrupt or referenced file unreadable -> fall through.
  }

  // Explicit FirmBoot9Path= fallback.
  UString b9p = ReadKeystoneIni(dll, L"FirmBoot9Path");
  if (!b9p.IsEmpty())
  {
    UString p = KeystoneIsAbsPath(b9p) ? b9p : dll + UString(L"\\") + b9p;
    unsigned got = 0;
    Byte b9[65536];
    if (ReadRawFile(p, b9, sizeof(b9), got) && got >= 65536)
    {
      memcpy(N, b9 + (dev ? 0xC4E0 : 0xB1E0), 256);
      if (N[255] != 0)
        return true;
    }
  }

  // ctrdevice scan: each per-console sub-folder under DeviceDataDir is checked
  // for a ctrindex.ini whose "boot9=" key locates a usable boot9.bin.
  UString devRoot = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"DeviceDataDir"), L"keystone\\ctrdevice");
  if (!devRoot.IsEmpty())
  {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(devRoot + UString(L"\\*"), &fd);
    if (h != INVALID_HANDLE_VALUE)
    {
      do
      {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != L'.')
        {
          UString sub = devRoot + UString(L"\\") + (const wchar_t *)fd.cFileName;
          if (ReadBoot9FromCtrindex(sub, dev, N))
          {
            FindClose(h);
            return true;
          }
        }
      } while (FindNextFileW(h, &fd));
      FindClose(h);
    }
  }

  // No public key available: the caller SKIPS FIRM signature verification.
  return false;
}

// ---- RSA-2048 / PKCS#1 v1.5 / SHA-256 FIRM signature verify (Windows CNG,
// dynamically loaded; no bcrypt.lib link needed). Returns:
//   1 = verified against this unit's public key, 0 = not verified / no key,
//  -1 = key present but signature rejected.
namespace FirmBcrypt {
typedef ULONG (WINAPI *pOpenAlg)(void**, const wchar_t*, const wchar_t*, ULONG);
typedef ULONG (WINAPI *pImport)(void*, void*, const wchar_t*, void**, Byte*, ULONG, ULONG);
typedef ULONG (WINAPI *pVerify)(void*, void*, Byte*, ULONG, Byte*, ULONG, ULONG);
typedef ULONG (WINAPI *pDestroyKey)(void*);
typedef ULONG (WINAPI *pCloseAlg)(void*, ULONG);
struct RSA_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus;
                 ULONG cbPrime1; ULONG cbPrime2; };
}

#pragma warning(push)
#pragma warning(disable:4191)   // FARPROC -> CNG function pointer cast (runtime lib)
static int FirmRsaCheck(const Byte header[256], const Byte sig[256], bool dev)
{
  Byte N[256];
  if (!LoadFirmModulusCached(dev, N))
    return 0;

  HMODULE bc = LoadLibraryW(L"bcrypt.dll");
  if (!bc)
    return 0;
  FirmBcrypt::pOpenAlg   OpenAlg   = (FirmBcrypt::pOpenAlg)  GetProcAddress(bc, "BCryptOpenAlgorithmProvider");
  FirmBcrypt::pImport    Import    = (FirmBcrypt::pImport)   GetProcAddress(bc, "BCryptImportKeyPair");
  FirmBcrypt::pVerify    Verify    = (FirmBcrypt::pVerify)   GetProcAddress(bc, "BCryptVerifySignature");
  FirmBcrypt::pDestroyKey DestroyKey= (FirmBcrypt::pDestroyKey)GetProcAddress(bc, "BCryptDestroyKey");
  FirmBcrypt::pCloseAlg   CloseAlg = (FirmBcrypt::pCloseAlg) GetProcAddress(bc, "BCryptCloseAlgorithmProvider");
  if (!OpenAlg || !Import || !Verify || !DestroyKey || !CloseAlg)
    return 0;

  // BCRYPT_RSAKEY_BLOB (24-byte header) + exp(0x010001) + modulus (big-endian)
  Byte blob[24 + 3 + 256];
  memset(blob, 0, sizeof(blob));
  FirmBcrypt::RSA_BLOB *hb = (FirmBcrypt::RSA_BLOB *)blob;
  hb->Magic = 0x31415352;            // "RSA1" public key (BCRYPT_RSAPUBLIC_MAGIC, little-endian)
  hb->BitLength = 2048;
  hb->cbPublicExp = 3;
  hb->cbModulus = 256;
  hb->cbPrime1 = 0;
  hb->cbPrime2 = 0;
  Byte *exp = blob + 24;
  exp[0] = 0x01; exp[1] = 0x00; exp[2] = 0x01;
  memcpy(exp + 3, N, 256);

  void *hAlg = NULL, *hKey = NULL;
  int result = 0;   // 0=no key/CNG unavailable, -1=key present but rejected, 1=valid
  if (OpenAlg(&hAlg, L"RSA", NULL, 0) != 0)
    return 0;
  if (Import(hAlg, NULL, L"RSAPUBLICBLOB", &hKey, blob, (ULONG)sizeof(blob), 0) != 0)
  {
    CloseAlg(hAlg, 0);
    return 0;
  }
  {
    Byte digest[32];
    CSha256 st;
    Sha256_Init(&st);
    Sha256_Update(&st, header, 256);
    Sha256_Final(&st, digest);
    // BCRYPT_PAD_PKCS1 = 2; pPaddingInfo = BCRYPT_PKCS1_PADDING_INFO{pszAlgId=L"SHA256"};
    // pbHash = raw SHA-256 digest; pbSignature = signature big-endian as stored.
    struct { const wchar_t *pszAlgId; } padInfo = { L"SHA256" };
    if (Verify(hKey, &padInfo, digest, 32, (Byte *)sig, 256, 2) == 0)
      result = 1;
    else
      result = -1;
  }
  if (hKey) DestroyKey(hKey);
  if (hAlg) CloseAlg(hAlg, 0);
  return result;
}
#pragma warning(pop)

// ============ Unified keystone cache: ONE indexed, obfuscated file ============
// <program dir>\keystone\cache\keystone.cache
// Layout: 24B header -> fixed-size index entries -> XOR-obfuscated data area.
// LOCAL ONLY: holds derived console keys + AES keys; never share, commit, or ship.

static UString CacheFilePath()
{
  UString dll = GetDllDirectory();
  if (dll.IsEmpty())
    return UString();
  CreateDirectoryW((dll + L"\\keystone").Ptr(), NULL);
  CreateDirectoryW((dll + L"\\keystone\\cache").Ptr(), NULL);
  return dll + UString(L"\\keystone\\cache\\keystone.cache");
}

// FNV-1a 64-bit over files matching `pattern` in dir (size + last-write time).
// Any add/remove/modify of a source file changes the signature.
static UInt64 DirSig64(const UString &dir, const wchar_t *pattern)
{
  UInt64 h = 1469598103934665603ULL;
  UString pat = dir + UString(L"\\") + UString(pattern ? pattern : L"*");
  WIN32_FIND_DATAW fd;
  HANDLE hf = FindFirstFileW(pat.Ptr(), &fd);
  if (hf != INVALID_HANDLE_VALUE)
  {
    do
    {
      if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      {
        UInt64 sz = ((UInt64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        UInt64 mt = ((UInt64)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime;
        h ^= sz; h *= 1099511628211ULL;
        h ^= mt; h *= 1099511628211ULL;
      }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
  }
  return h;
}

// Light obfuscation stream over the data area (anti-casual-viewer, NOT crypto):
// each byte XORed with a position-dependent value so Notepad cannot read plaintext keys.
static Byte ObfByte(UInt32 i)
{
  return (Byte)(0x7A ^ ((i * 13u) & 0xFFu));
}

static void KS_PutU32(Byte *p, UInt32 v)
{
  p[0] = (Byte)v; p[1] = (Byte)(v >> 8); p[2] = (Byte)(v >> 16); p[3] = (Byte)(v >> 24);
}
static UInt32 KS_GetU32(const Byte *p)
{
  return (UInt32)p[0] | ((UInt32)p[1] << 8) | ((UInt32)p[2] << 16) | ((UInt32)p[3] << 24);
}

// XOR-obfuscate the UTF-16LE name bytes (symmetric: same call decodes). Keeps
// the record name out of plaintext so Notepad cannot read key/device names.
static void ObfuscateName(const UString &name, Byte *out)
{
  const Byte *src = (const Byte *)name.Ptr();
  unsigned n = (unsigned)name.Len() * sizeof(wchar_t);
  for (unsigned i = 0; i < n; i++)
    out[i] = src[i] ^ ObfByte(i);
}

// ---- records persisted inside the unified cache file (append-only) ----
// Record layout: type u8 | nameLen u8(wchar count) | sigLo u32 | sigHi u32 |
// dataSize u32 | name (XOR-obfuscated UTF-16LE) | data (XOR-obfuscated).
// The cache file holds both device (type=2) and AES-key (type=1) records in
// ONE file; neither names nor payload are stored in plaintext.

static void KeystoneCacheAppendDevice(const UString &name, const CDeviceNand &dv, UInt64 sig)
{
  UString path = CacheFilePath();
  if (path.IsEmpty())
    return;

  // serialize device data into a plain buffer, then obfuscate it.
  // layout: IsDev u8 | IsSnake u8 | SnLen u8 | Sn UTF16 | Nonce16 |
  //         Nk[4..7] x16 | HasSlotBits u8[8] | HasTwl u8 | TwlNk16 | TwlNonce16
  unsigned cap = 1 + 1 + 1 + (unsigned)dv.Sn.Len() * 2 + 16 + 4 * 16 + 8 + 1 + 16 + 16;
  Byte *plain = (Byte *)malloc(cap);
  unsigned p = 0;
  plain[p++] = dv.IsDev ? 1 : 0;
  plain[p++] = dv.IsSnake ? 1 : 0;
  plain[p++] = (Byte)dv.Sn.Len();
  for (UInt32 i = 0; i < dv.Sn.Len(); i++)
  {
    plain[p++] = (Byte)(dv.Sn[i] & 0xFF);
    plain[p++] = (Byte)((dv.Sn[i] >> 8) & 0xFF);
  }
  memcpy(plain + p, dv.Nonce, 16); p += 16;
  for (int s = 4; s <= 7; s++) { memcpy(plain + p, dv.Nk[s], 16); p += 16; }
  for (int s = 0; s < 8; s++)
    plain[p++] = dv.HasSlot[s] ? 1 : 0;
  plain[p++] = dv.HasTwl ? 1 : 0;
  memcpy(plain + p, dv.TwlNk, 16); p += 16;
  memcpy(plain + p, dv.TwlNonce, 16); p += 16;

  unsigned dataSize = p;
  Byte *obf = (Byte *)malloc(dataSize);
  for (unsigned i = 0; i < dataSize; i++)
    obf[i] = plain[i] ^ ObfByte(i);
  free(plain);

  HANDLE h = CreateFileW(path.Ptr(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE)
  {
    Byte hdr[14];
    Byte *q = hdr;
    *q++ = 2;                                  // type = device
    *q++ = (Byte)name.Len();
    KS_PutU32(q, (UInt32)(sig & 0xFFFFFFFF)); q += 4;
    KS_PutU32(q, (UInt32)(sig >> 32)); q += 4;
    KS_PutU32(q, (UInt32)dataSize); q += 4;
    Byte *obfName = (Byte *)malloc(name.Len() * sizeof(wchar_t));
    ObfuscateName(name, obfName);
    DWORD wr;
    WriteFile(h, hdr, sizeof(hdr), &wr, NULL);
    WriteFile(h, obfName, (DWORD)(name.Len() * sizeof(wchar_t)), &wr, NULL);
    WriteFile(h, (const void *)obf, dataSize, &wr, NULL);
    free(obfName);
    CloseHandle(h);
  }
  free(obf);
}

// Scan the cache for an existing record of the given type carrying this sig;
// used to skip re-appending an unchanged folder and keep the file compact.
static bool KeystoneCacheSigPresent(Byte type, UInt64 sig)
{
  UString path = CacheFilePath();
  if (path.IsEmpty())
    return false;
  HANDLE h = CreateFileW(path.Ptr(), GENERIC_READ, FILE_SHARE_READ, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD sz = GetFileSize(h, NULL);
  Byte *buf = (Byte *)malloc(sz + 1);
  DWORD rd = 0;
  ReadFile(h, buf, sz, &rd, NULL);
  CloseHandle(h);
  bool found = false;
  UInt32 pos = 0;
  while (pos + 14 <= sz)
  {
    Byte t = buf[pos];
    Byte nameLen = buf[pos + 1];
    UInt32 sLo = KS_GetU32(buf + pos + 2);
    UInt32 sHi = KS_GetU32(buf + pos + 6);
    UInt32 ds = KS_GetU32(buf + pos + 10);
    UInt32 dataOff = pos + 14 + (UInt32)nameLen * 2;
    UInt32 next = dataOff + ds;
    if (next > sz)
      break;
    if (t == type && ((UInt64)sLo | ((UInt64)sHi << 32)) == sig)
    {
      found = true;
      break;
    }
    pos = next;
  }
  free(buf);
  return found;
}

// Append one AES-key record (type=1) into the unified cache.
// data = IsDev u8 + key[16]; sig = owning key-folder signature for invalidation.
static void KeystoneCacheAppendKey(const UString &name, const Byte data[16], bool isDev, UInt64 sig)
{
  UString path = CacheFilePath();
  if (path.IsEmpty())
    return;

  Byte plain[17];
  plain[0] = isDev ? 1 : 0;
  memcpy(plain + 1, data, 16);
  Byte obf[17];
  for (int i = 0; i < 17; i++)
    obf[i] = plain[i] ^ ObfByte((UInt32)i);

  HANDLE h = CreateFileW(path.Ptr(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE)
  {
    Byte hdr[14];
    Byte *q = hdr;
    *q++ = 1;                                  // type = AES key
    *q++ = (Byte)name.Len();
    KS_PutU32(q, (UInt32)(sig & 0xFFFFFFFF)); q += 4;
    KS_PutU32(q, (UInt32)(sig >> 32)); q += 4;
    KS_PutU32(q, 17); q += 4;
    Byte *obfName = (Byte *)malloc(name.Len() * sizeof(wchar_t));
    ObfuscateName(name, obfName);
    DWORD wr;
    WriteFile(h, hdr, sizeof(hdr), &wr, NULL);
    WriteFile(h, obfName, (DWORD)(name.Len() * sizeof(wchar_t)), &wr, NULL);
    WriteFile(h, obf, 17, &wr, NULL);
    free(obfName);
    CloseHandle(h);
  }
}

// Finds a device record matching name + current source signature; fills dv on hit.
static bool KeystoneCacheLoadDevice(const UString &name, UInt64 curSig, CDeviceNand &dv)
{
  UString path = CacheFilePath();
  if (path.IsEmpty())
    return false;
  HANDLE h = CreateFileW(path.Ptr(), GENERIC_READ, FILE_SHARE_READ, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD sz = GetFileSize(h, NULL);
  Byte *buf = (Byte *)malloc(sz + 1);
  DWORD rd = 0;
  ReadFile(h, buf, sz, &rd, NULL);
  CloseHandle(h);

  bool ok = false;
  UInt32 pos = 0;
  while (pos + 14 <= sz)
  {
    Byte type = buf[pos];
    Byte nameLen = buf[pos + 1];
    UInt32 sigLo = KS_GetU32(buf + pos + 2);
    UInt32 sigHi = KS_GetU32(buf + pos + 6);
    UInt32 dataSize = KS_GetU32(buf + pos + 10);
    UInt32 nameOff = pos + 14;
    UInt32 dataOff = nameOff + (UInt32)nameLen * 2;
    UInt32 next = dataOff + dataSize;
    
    if (next > sz)
      break;
    // decode the obfuscated record name before comparing
    UInt32 nb = (UInt32)nameLen * 2;
    
    Byte *decName = (Byte *)malloc(nb);
    for (UInt32 i = 0; i < nb; i++)
      decName[i] = buf[nameOff + i] ^ ObfByte(i);
    
    bool nameMatch = (UInt32)name.Len() == nameLen && memcmp(decName, name.Ptr(), nb) == 0;
    free(decName);
    
    if (type == 2 && nameMatch &&
        ((UInt64)sigLo | ((UInt64)sigHi << 32)) == curSig)
    {
      
      const Byte *enc = buf + dataOff;
      Byte *plain = (Byte *)malloc(dataSize);
      
      for (UInt32 i = 0; i < dataSize; i++)
        plain[i] = enc[i] ^ ObfByte(i);
      
      // minimum payload: IsDev, IsSnake, SnLen, Nonce16, Nk[4..7]x64, HasSlotBits8,
      // HasTwl, TwlNk16, TwlNonce16. Reject a stale/older-format record on mismatch
      // so the caller falls back to re-deriving instead of reading misaligned keys.
      unsigned q = 0;
      if (dataSize < 3 + 16 + 4 * 16 + 8 + 1 + 16 + 16)
      {
        free(plain);
        pos = next;
        continue;
      }
      dv.IsDev = plain[q++] == 1;
      dv.IsSnake = plain[q++] == 1;
      Byte snLen = plain[q++];
      
      // Build into a local wide buffer then assign as one UString; UString has no
      // safe single-char operator+=, appending char-by-char faults on this build.
      wchar_t snBuf[80];
      unsigned si = 0;
      for (Byte i = 0; i < snLen; i++)
      {
        wchar_t c = (wchar_t)(plain[q] | (plain[q + 1] << 8));
        q += 2;
        if (si < 79)
          snBuf[si++] = c;
      }
      snBuf[si] = 0;
      dv.Sn = UString(snBuf);
      
      memcpy(dv.Nonce, plain + q, 16); q += 16;
      
      for (int s = 4; s <= 7; s++) { memcpy(dv.Nk[s], plain + q, 16); q += 16; }
      
      for (int s = 0; s < 8; s++)
        dv.HasSlot[s] = plain[q++] == 1;
      dv.HasTwl = plain[q++] == 1;
      
      memcpy(dv.TwlNk, plain + q, 16); q += 16;
      memcpy(dv.TwlNonce, plain + q, 16); q += 16;
      
      free(plain);
      
      ok = true;
      break;
    }
    pos = next;
  }
  free(buf);
  return ok;
}

// ---- FIRM public-key records (type=3) in the unified keystone cache ----
// data = IsDev u8 + N[256] (257B, XOR-obfuscated); name = "firm_pub_retail" /
// "firm_pub_dev". sig covers every source that can feed LoadFirmModulus, so a
// changed pubkey.ini / hex / file / ctrdevice boot9 invalidates the record.

// FNV-1a over the per-console sub-folders of the ctrdevice root: for each
// sub-folder hash ctrindex.ini and boot9.bin (contents change => sig changes).
static UInt64 DevRootSig64(const UString &root)
{
  UInt64 h = 1469598103934665603ULL;
  WIN32_FIND_DATAW fd;
  HANDLE hf = FindFirstFileW((root + UString(L"\\*")).Ptr(), &fd);
  if (hf != INVALID_HANDLE_VALUE)
  {
    do
    {
      if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != L'.')
      {
        UString sub = root + UString(L"\\") + (const wchar_t *)fd.cFileName;
        h ^= DirSig64(sub, L"ctrindex.ini");
        h *= 1099511628211ULL;
        h ^= DirSig64(sub, L"boot9.bin");
        h *= 1099511628211ULL;
      }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
  }
  return h;
}

// Combined signature of every FIRM-modulus source: keystone.ini (hex/file/dir/
// boot9-path keys), the FirmPubKeyDir folder (pubkey.ini + 256B files) and the
// ctrdevice root (per-console ctrindex.ini + boot9.bin).
static UInt64 FirmPubKeySourceSig(const UString &dll)
{
  UInt64 s = DirSig64(dll, L"keystone.ini");
  UString kd = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"FirmPubKeyDir"), L"keystone\\pubkey");
  s ^= DirSig64(kd, L"*");
  UString devRoot = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"DeviceDataDir"), L"keystone\\ctrdevice");
  s ^= DevRootSig64(devRoot);
  return s;
}

// Append one FIRM public-key record (type=3).
static void KeystoneCacheAppendPubKey(bool dev, const Byte N[256], UInt64 sig)
{
  UString path = CacheFilePath();
  if (path.IsEmpty())
    return;
  UString name = UString(dev ? L"firm_pub_dev" : L"firm_pub_retail");

  Byte plain[257];
  plain[0] = dev ? 1 : 0;
  memcpy(plain + 1, N, 256);
  Byte obf[257];
  for (int i = 0; i < 257; i++)
    obf[i] = plain[i] ^ ObfByte((UInt32)i);

  HANDLE h = CreateFileW(path.Ptr(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h != INVALID_HANDLE_VALUE)
  {
    Byte hdr[14];
    Byte *q = hdr;
    *q++ = 3;                                  // type = FIRM public key
    *q++ = (Byte)name.Len();
    KS_PutU32(q, (UInt32)(sig & 0xFFFFFFFF)); q += 4;
    KS_PutU32(q, (UInt32)(sig >> 32)); q += 4;
    KS_PutU32(q, 257); q += 4;
    Byte *obfName = (Byte *)malloc(name.Len() * sizeof(wchar_t));
    ObfuscateName(name, obfName);
    DWORD wr;
    WriteFile(h, hdr, sizeof(hdr), &wr, NULL);
    WriteFile(h, obfName, (DWORD)(name.Len() * sizeof(wchar_t)), &wr, NULL);
    WriteFile(h, obf, 257, &wr, NULL);
    free(obfName);
    CloseHandle(h);
  }
}

// Load a FIRM public-key record (type=3) matching unit + source signature.
static bool KeystoneCacheLoadPubKey(bool dev, UInt64 sig, Byte N[256])
{
  UString path = CacheFilePath();
  if (path.IsEmpty())
    return false;
  UString name = UString(dev ? L"firm_pub_dev" : L"firm_pub_retail");
  HANDLE h = CreateFileW(path.Ptr(), GENERIC_READ, FILE_SHARE_READ, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD sz = GetFileSize(h, NULL);
  Byte *buf = (Byte *)malloc(sz + 1);
  DWORD rd = 0;
  ReadFile(h, buf, sz, &rd, NULL);
  CloseHandle(h);

  bool ok = false;
  UInt32 pos = 0;
  while (pos + 14 <= sz)
  {
    Byte type = buf[pos];
    Byte nameLen = buf[pos + 1];
    UInt32 sigLo = KS_GetU32(buf + pos + 2);
    UInt32 sigHi = KS_GetU32(buf + pos + 6);
    UInt32 dataSize = KS_GetU32(buf + pos + 10);
    UInt32 nameOff = pos + 14;
    UInt32 dataOff = nameOff + (UInt32)nameLen * 2;
    UInt32 next = dataOff + dataSize;
    if (next > sz)
      break;
    if (type == 3 && (UInt32)name.Len() == nameLen &&
        ((UInt64)sigLo | ((UInt64)sigHi << 32)) == sig)
    {
      Byte *decName = (Byte *)malloc((UInt32)nameLen * 2);
      for (UInt32 i = 0; i < (UInt32)nameLen * 2; i++)
        decName[i] = buf[nameOff + i] ^ ObfByte(i);
      bool nm = memcmp(decName, name.Ptr(), (UInt32)nameLen * 2) == 0;
      free(decName);
      if (nm && dataSize >= 257)
      {
        const Byte *enc = buf + dataOff;
        Byte plain[257];
        for (UInt32 i = 0; i < 257; i++)
          plain[i] = enc[i] ^ ObfByte(i);
        if ((plain[0] == 1) == dev)
        {
          memcpy(N, plain + 1, 256);
          ok = true;
          break;
        }
      }
    }
    pos = next;
  }
  free(buf);
  return ok;
}

// Top-level FIRM modulus loader with disk-cache: compute the combined source
// signature, hit the type=3 cache record if unchanged, otherwise run the full
// LoadFirmModulus chain and persist the result into the unified cache.
static bool LoadFirmModulusCached(bool dev, Byte N[256])
{
  UString dll = GetDllDirectory();
  UInt64 sig = FirmPubKeySourceSig(dll);
  if (KeystoneCacheLoadPubKey(dev, sig, N))
    return true;
  if (!LoadFirmModulus(dev, N))
    return false;
  KeystoneCacheAppendPubKey(dev, N, sig);
  return true;
}

// single-block AES-ECB encrypt (IV=0 CBC encode == ECB), mirrors AesCtr_Decode3ds
static void AesEcbEncBlock(const Byte *key, const Byte *in, Byte *out16)
{
  __declspec(align(16)) UInt32 aes[AES_NUM_IVMRK_WORDS];
  Aes_SetKey_Enc(aes + 4, key, 16);
  memset(aes, 0, 16);
  memcpy(out16, in, 16);
  g_AesCbc_Encode(aes, out16, 1);
}

// manual CBC-encrypt of 64 bytes (4 blocks) with explicit IV chaining
static void AesCbcEnc64(const Byte *key, const Byte *iv, const Byte *in64, Byte *out64)
{
  Byte prev[16];
  memcpy(prev, iv, 16);
  for (int b = 0; b < 4; b++)
  {
    Byte x[16];
    for (int j = 0; j < 16; j++)
      x[j] = in64[b * 16 + j] ^ prev[j];
    AesEcbEncBlock(key, x, out64 + b * 16);
    memcpy(prev, out64 + b * 16, 16);
  }
}

// Decrypt the raw encrypted OTP blob (256B) with boot9-stored CBC key/IV.
static bool OtpDecryptMem(const Byte *otp, const Byte *b9, bool dev, Byte *out256)
{
  unsigned nkOff = dev ? 0xD700 : 0xD6E0;
  unsigned ivOff = dev ? 0xD710 : 0xD6F0;
  __declspec(align(16)) UInt32 st[AES_NUM_IVMRK_WORDS];
  AesCbc_Start(st, b9 + nkOff, b9 + ivOff);
  memcpy(out256, otp, 256);
  AesCbc_Step(st, out256, 16);
  if (memcmp(out256, "\x0F\xB0\xAD\xDE", 4) != 0)
    return false;
  Byte dg[32];
  CSha256 s;
  Sha256_Init(&s);
  Sha256_Update(&s, out256, 0xE0);
  Sha256_Final(&s, dg);
  return memcmp(dg, out256 + 0xE0, 32) == 0;
}

// boot9 keyinit: derive slot0x04-0x07 normalkeys from decrypted OTP + boot9.
static bool KeyInitDerive(const Byte *otpPlain, const Byte *b9, bool dev, Byte nk[8][16])
{
  const Byte *b = b9 + 0x8000;              // last 32KB of the 64KB boot9 dump
  unsigned kb = dev ? 0x5C60 : 0x5860;
  const Byte *keygen = b + kb;

  Byte seed[0x40];
  memcpy(seed, otpPlain + 0x90, 0x1C);     // OTP_dec[0x90:0xAC]
  memcpy(seed + 0x1C, keygen, 0x24);       // b9_extdata_otp[0:0x24]
  Byte cxy[32];
  CSha256 s;
  Sha256_Init(&s);
  Sha256_Update(&s, seed, 0x40);
  Sha256_Final(&s, cxy);

  Byte s3f[16];
  C3dsNormalKey(s3f, cxy, cxy + 16);       // slot0x3f normal key

  Byte enc[64];
  AesCbcEnc64(s3f, keygen + 36, keygen + 52, enc);
  const Byte *keyX = enc;                 // shared slot keyX = enc[:16]

  // fixed New3DS CTRNAND slot0x05 keyY (common to dev/retail, not from keyblob)
  static const Byte ky05[16] =
  { 0x4D,0x80,0x4F,0x4E,0x99,0x90,0x19,0x46,0x13,0xA2,0x04,0xAC,0x58,0x44,0x60,0xBE };

  C3dsNormalKey(nk[4], keyX, b + kb + 0x1F0);
  C3dsNormalKey(nk[5], keyX, ky05);
  C3dsNormalKey(nk[6], keyX, b + kb + 0x210);
  C3dsNormalKey(nk[7], keyX, b + kb + 0x220);
  return true;
}

// ---- Bare-material profile (no ctrindex.ini next to nand.bin) ----
// When boot9/OTP/nand_cid sit beside nand.bin without an ini, the console unit
// and model are unknown to the program. Resolve them from (1) process env vars set
// by the CLI (-unit/-type/-slot), or (2) a two-step GUI prompt in 7zFM.
enum
{
  kBareOk = 0,
  kBareCancel,      // user cancelled the prompt -> abort open
  kBareMissing,     // required files are not all present
  kBareNeedParam,   // console host, -unit not provided
  kBareBadParam     // -unit/-type/-slot value unrecognized
};

struct CBareProfile
{
  bool IsDev;
  bool IsSnake;
  int SlotWanted;   // -1 auto (try slot0x04 & 0x05), 4 Old, 5 New
  CBareProfile(): IsDev(false), IsSnake(false), SlotWanted(-1) {}
};
static CBareProfile g_bareProfile;

static bool BareFilePresent(const UString &dir, const wchar_t *name)
{
  return GetFileAttributesW((dir + UString(L"\\") + UString(name)).Ptr()) != INVALID_FILE_ATTRIBUTES;
}

static bool BareMaterialPresent(const UString &dir)
{
  if (!BareFilePresent(dir, L"boot9.bin"))
    return false;
  // OTP dumps may carry either .mem or .bin (encrypted: otp.mem/otp.bin;
  // plaintext: otp_dec.mem/otp_dec.bin). boot9 is always .bin and unchanged.
  bool otp = BareFilePresent(dir, L"otp.mem") || BareFilePresent(dir, L"otp.bin")
          || BareFilePresent(dir, L"otp_dec.mem") || BareFilePresent(dir, L"otp_dec.bin");
  bool cid = BareFilePresent(dir, L"nand_cid.mem") || BareFilePresent(dir, L"nand_cid.bin");
  return otp && cid;
}

// GUI host = 7zFM.exe, flagged by OpenArchive via Z7CTR_GUI=1. The console
// subsystem (7z.exe) never prompts: it must not block a redirected/scripted run.
// GetConsoleWindow() is unreliable under redirection (returns NULL without a
// console even for console apps), so we rely on this explicit marker instead.
static bool IsGuiHost()
{
  wchar_t v[8] = { 0 };
  return GetEnvironmentVariableW(L"Z7CTR_GUI", v, 8) > 0 && v[0] == L'1';
}

// Dynamic MessageBoxW (user32 loaded at runtime, no link-time dependency).
// Returns IDYES/IDNO/IDCANCEL; IDCANCEL when not interactive or unavailable.
static int GuiAskYesNoCancel(LPCWSTR text)
{
  if (!IsGuiHost())
    return IDCANCEL;
  HMODULE u32 = LoadLibraryW(L"user32.dll");
  if (!u32)
    return IDCANCEL;
  typedef int (WINAPI *PFN_MB)(HWND, LPCWSTR, LPCWSTR, UINT);
#pragma warning(push)
#pragma warning(disable: 4191)
  PFN_MB pMB = reinterpret_cast<PFN_MB>(GetProcAddress(u32, "MessageBoxW"));
#pragma warning(pop)
  if (!pMB)
    return IDCANCEL;
  return pMB(NULL, text, L"7-Zip CTR", MB_YESNOCANCEL | MB_ICONQUESTION);
}

static int ReadBareEnv(const wchar_t *name, wchar_t *buf, unsigned cap)
{
  DWORD n = GetEnvironmentVariableW(name, buf, cap);
  return (n > 0 && n < cap) ? 1 : 0;
}

// Resolve the bare profile; fills g_bareProfile on kBareOk.
static int ResolveBareProfile(const UString &dir)
{
  if (!BareMaterialPresent(dir))
    return kBareMissing;

  g_bareProfile = CBareProfile();
  wchar_t ev[256];

  // ---- unit: retail | dev (env Z7CTR_UNIT) ----
  bool unitFromEnv = false;
  if (ReadBareEnv(L"Z7CTR_UNIT", ev, 256))
  {
    unitFromEnv = true;
    if (_wcsicmp(ev, L"retail") == 0)
      g_bareProfile.IsDev = false;
    else if (_wcsicmp(ev, L"dev") == 0)
      g_bareProfile.IsDev = true;
    else
      return kBareBadParam;
  }

  // ---- type: ctr | snake (dev only, env Z7CTR_TYPE) ----
  if (ReadBareEnv(L"Z7CTR_TYPE", ev, 256))
  {
    if (_wcsicmp(ev, L"ctr") == 0)
      g_bareProfile.IsSnake = false;
    else if (_wcsicmp(ev, L"snake") == 0)
      g_bareProfile.IsSnake = true;
    else
      return kBareBadParam;
  }

  // ---- slot: 4 (Old) | 5 (New), env Z7CTR_SLOT ----
  if (ReadBareEnv(L"Z7CTR_SLOT", ev, 256))
  {
    if (wcscmp(ev, L"4") == 0)
      g_bareProfile.SlotWanted = 4;
    else if (wcscmp(ev, L"5") == 0)
      g_bareProfile.SlotWanted = 5;
    else
      return kBareBadParam;
  }

  if (unitFromEnv)
    return kBareOk;

  // No -unit: a console host cannot prompt, so demand the parameter.
  if (!IsGuiHost())
    return kBareNeedParam;

  // ---- GUI two-step prompt ----
  int r1 = GuiAskYesNoCancel(
      L"Device material was found next to nand.bin, but the console type is not declared.\n\n"
      L"Which unit is this console?\n"
      L"  Yes = Retail unit\n"
      L"  No  = Devkit unit\n"
      L"  Cancel = abort");
  if (r1 == IDCANCEL)
    return kBareCancel;
  g_bareProfile.IsDev = (r1 == IDNO);

  if (g_bareProfile.IsDev)
  {
    int r2 = GuiAskYesNoCancel(
        L"Which development board type?\n"
        L"  Yes = CTR\n"
        L"  No  = SNAKE\n"
        L"  Cancel = abort");
    if (r2 == IDCANCEL)
      return kBareCancel;
    g_bareProfile.IsSnake = (r2 == IDNO);
  }
  else
  {
    int r2 = GuiAskYesNoCancel(
        L"Which retail model?\n"
        L"  Yes = Old 3DS / 2DS (slot 0x04)\n"
        L"  No  = New 3DS / 2DS (slot 0x05)\n"
        L"  Cancel = abort");
    if (r2 == IDCANCEL)
      return kBareCancel;
    g_bareProfile.SlotWanted = (r2 == IDNO) ? 5 : 4;
  }
  return kBareOk;
}

// Returns true when a device was derived and appended; false when the directory
// exists but required material is missing or derivation failed.
static bool LoadCtrDevice(const UString &dir, CObjectVector<CDeviceNand> &out)
{
  UString ini = dir + UString(L"\\ctrindex.ini");
  // Bare mode: no ctrindex.ini next to the files (material sits beside nand.bin).
  // Then unit defaults to retail; dev must be declared explicitly in the ini.
  bool iniExists = (GetFileAttributesW(ini.Ptr()) != INVALID_FILE_ATTRIBUTES);
  wchar_t buf[MAX_PATH] = { 0 };

  CDeviceNand dv;
  if (iniExists)
  {
    // Bare mode (no ctrindex.ini) skips the profile API entirely: calling
    // GetPrivateProfileStringW against a missing absolute ini path stalls/ABs.
    GetPrivateProfileStringW(L"ctrindex", L"unit", L"dev", buf, MAX_PATH, ini.Ptr());
    dv.IsDev = (_wcsicmp(buf, L"dev") == 0);
    GetPrivateProfileStringW(L"ctrindex", L"type", L"ctr", buf, MAX_PATH, ini.Ptr());
    dv.IsSnake = (_wcsicmp(buf, L"snake") == 0);
    GetPrivateProfileStringW(L"ctrindex", L"sn", L"", buf, MAX_PATH, ini.Ptr());
    dv.Sn = UString(buf);
    GetPrivateProfileStringW(L"ctrindex", L"boot9", L"boot9.bin", buf, MAX_PATH, ini.Ptr());
  }
  else
  {
    // Bare profile already resolved by ResolveBareProfile (env vars or GUI prompt).
    dv.IsDev = g_bareProfile.IsDev;
    dv.IsSnake = g_bareProfile.IsSnake;
    dv.SlotWanted = g_bareProfile.SlotWanted;
    // Sn stays at its default-constructed empty UString; no Empty() call needed.
    wcscpy(buf, L"boot9.bin");
  }
  Byte b9[65536];
  unsigned got = 0;
  if (!ReadRawFile(dir + UString(L"\\") + UString(buf), b9, sizeof(b9), got) || got < 65536)
    return false;


  // Encrypted otp dump (otp.mem/otp.bin, or ini optdump): keep first 8 bytes
  // for the dev TWL KeyX even when a plaintext otp_dec is also present.
  // Optional in bare mode when a plaintext otp_dec is available.
  Byte otpRaw[256];
  if (iniExists)
    GetPrivateProfileStringW(L"ctrindex", L"optdump", L"otp.mem", buf, MAX_PATH, ini.Ptr());
  else
    wcscpy(buf, L"otp.mem");
  unsigned rg = 0;
  bool haveRaw = ReadRawFile(dir + UString(L"\\") + UString(buf), otpRaw, 256, rg) && rg == 256;
  // Bare mode: fall back to otp.bin when otp.mem is absent.
  if (!haveRaw && !iniExists)
    haveRaw = ReadRawFile(dir + UString(L"\\otp.bin"), otpRaw, 256, rg) && rg == 256;
  if (haveRaw)
    memcpy(dv.OtpEnc8, otpRaw, 8);


  // Plaintext OTP: ini optdec first; bare mode auto-detects otp_dec.mem;
  // otherwise decrypt the encrypted dump with boot9.
  Byte otpPlain[256];
  if (iniExists)
    GetPrivateProfileStringW(L"ctrindex", L"optdec", L"", buf, MAX_PATH, ini.Ptr());
  else
    buf[0] = 0;
  bool havePlain = false;
  if (buf[0])
    havePlain = ReadRawFile(dir + UString(L"\\") + UString(buf), otpPlain, 256, got) && got == 256;
  if (!havePlain && !iniExists)
    havePlain = ReadRawFile(dir + UString(L"\\otp_dec.mem"), otpPlain, 256, got) && got == 256;
  if (!havePlain && !iniExists)
    havePlain = ReadRawFile(dir + UString(L"\\otp_dec.bin"), otpPlain, 256, got) && got == 256;
  if (!havePlain)
  {
    // No plaintext OTP: decrypt the encrypted dump with boot9. If there is no
    // encrypted dump either (only a plaintext otp_dec missing here means the
    // file was unreadable), fail; CTRNAND still cannot be derived.
    if (!haveRaw || !OtpDecryptMem(otpRaw, b9, dv.IsDev, otpPlain))
      return false;
  }


  // NAND CID: ini nandcidfile/nandcidhex first; bare mode auto-detects
  // nand_cid.mem / nand_cid.bin.
  Byte cid[16];
  if (iniExists)
    GetPrivateProfileStringW(L"ctrindex", L"nandcidfile", L"", buf, MAX_PATH, ini.Ptr());
  else
    buf[0] = 0;
  if (buf[0])
  {
    unsigned cg = 0;
    if (!ReadRawFile(dir + UString(L"\\") + UString(buf), cid, 16, cg) || cg != 16)
      return false;
  }
  else
  {
    if (iniExists)
      GetPrivateProfileStringW(L"ctrindex", L"nandcidhex", L"", buf, MAX_PATH, ini.Ptr());
    else
      buf[0] = 0;
    if (buf[0])
      Hex16FromText(UString(buf), cid);
    else
    {
      unsigned cg = 0;
      if ((!ReadRawFile(dir + UString(L"\\nand_cid.mem"), cid, 16, cg) &&
           !ReadRawFile(dir + UString(L"\\nand_cid.bin"), cid, 16, cg)) || cg != 16)
      return false;
    }
  }

  memcpy(dv.Cid16, cid, 16);
  

  // CTRNAND nonce = SHA256(cid)[0:16]
  CSha256 cs;
  Sha256_Init(&cs);
  Sha256_Update(&cs, cid, 16);
  Sha256_Final(&cs, dv.Nonce);

  // ---- TWL (slot0x03) derivation: DSi keygen + SHA1(cid) counter ----
  // Retail TWL needs only otp_dec[0x8:0x10], always available here. Dev TWL
  // needs the encrypted OTP first 8 bytes (haveRaw); when only a plaintext
  // otp_dec is present, dev TWL cannot be derived -> HasTwl=false (degrade,
  // CTRNAND/Firm/AGB still work; TWL listed raw and flagged in Properties).
  {
    bool canTwl = !dv.IsDev || haveRaw;
    if (canTwl)
    {
      Byte kx[16];
      if (dv.IsDev)
      {
        // KeyX = otp_enc[0:4] (lo LE) || 1e4b7aee8bc042af || otp_enc[4:8] (hi LE)
        memcpy(kx, dv.OtpEnc8, 4);
        const Byte fixed8[8] = { 0x1E,0x4B,0x7A,0xEE,0x8B,0xC0,0x42,0xAF };
        memcpy(kx + 4, fixed8, 8);
        memcpy(kx + 12, dv.OtpEnc8 + 4, 4);
      }
      else
      {
        // retail: otp_dec[0x8:0x10], lo ^= 0xB358A6AF, lo |= 0x80000000, hi ^= 0x08C267B7
        UInt32 lo = (UInt32)otpPlain[8]
            | ((UInt32)otpPlain[9] << 8) | ((UInt32)otpPlain[10] << 16) | ((UInt32)otpPlain[11] << 24);
        UInt32 hi = (UInt32)otpPlain[12]
            | ((UInt32)otpPlain[13] << 8) | ((UInt32)otpPlain[14] << 16) | ((UInt32)otpPlain[15] << 24);
        lo ^= 0xB358A6AFull; lo |= 0x80000000u;
        hi ^= 0x08C267B7u;
        kx[0]=(Byte)lo; kx[1]=(Byte)(lo>>8); kx[2]=(Byte)(lo>>16); kx[3]=(Byte)(lo>>24);
        memcpy(kx + 4, "NINTENDO", 8);
        kx[12]=(Byte)hi; kx[13]=(Byte)(hi>>8); kx[14]=(Byte)(hi>>16); kx[15]=(Byte)(hi>>24);
      }
      CDsiNormalKey(dv.TwlNk, kx, dv.IsDev);

      // TWL counter = BE128( LE128(SHA1(cid)[:16]) ) = byte-reversed SHA1 prefix
      CSha1 h1;
      Sha1_Init(&h1);
      Sha1_Update(&h1, cid, 16);
      Byte sd[20];
      Sha1_Final(&h1, sd);
      for (int i = 0; i < 16; i++)
        dv.TwlNonce[i] = sd[15 - i];
      dv.HasTwl = true;
    }
  }
  

  if (!KeyInitDerive(otpPlain, b9, dv.IsDev, dv.Nk))
    return false;

  for (int s = 4; s <= 7; s++)
    dv.HasSlot[s] = true;

  // persist derived result into the unified cache (local only, do not share)
  {
    UString devName = dir;
    int sl = devName.ReverseFind(L'\\');
    if (sl >= 0)
      devName = devName.Ptr(sl + 1);
    KeystoneCacheAppendDevice(devName, dv, DirSig64(dir, L"*"));
  }
  out.Add(dv);
  return true;
}

// Device-data root: <7z.dll>\keystone\ctrdevice by default; overridable in
// keystone.ini [Keystone] DeviceDataDir= (absolute as-is, relative vs dll dir).
// Rescanned on every call instead of cached once, so a device folder copied in
// after the program starts (or a path edited in the options page) is picked up.
// Process-static cache for the ctrdevice scan: enumerated once and reused until the
// root directory's write time changes (a device folder added/removed on disk) or the
// user presses "Rebuild cache" in the options page. Avoids re-enumerating on every open.
static bool g_devsCached = false;
static FILETIME g_devsRootMtime;
static CObjectVector<CDeviceNand> g_devCache;

static bool DirWriteTime(const UString &path, FILETIME &ft)
{
  WIN32_FILE_ATTRIBUTE_DATA ad;
  if (!GetFileAttributesExW(path.Ptr(), GetFileExInfoStandard, &ad))
    return false;
  ft = ad.ftLastWriteTime;
  return true;
}

// Remove the unified on-disk cache file (keystone.cache) on rebuild/invalidate.
static void DropDeviceSnapshots()
{
  UString path = CacheFilePath();
  if (!path.IsEmpty())
    DeleteFileW(path.Ptr());
}

static void InvalidateCtrDevices()
{
  g_devsCached = false;
  g_devCache.Clear();
  DropDeviceSnapshots();
}

static CObjectVector<CDeviceNand> &CtrDevices()
{
  UString dll = GetDllDirectory();
  if (dll.IsEmpty())
  {
    InvalidateCtrDevices();
    return g_devCache;
  }
  UString root = ResolveKeystoneDir(dll, ReadKeystoneIni(dll, L"DeviceDataDir"), L"keystone\\ctrdevice");

  FILETIME cur;
  if (g_devsCached && DirWriteTime(root, cur) &&
      CompareFileTime(&cur, &g_devsRootMtime) == 0)
    return g_devCache;

  g_devCache.Clear();
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW(root + UString(L"\\*"), &fd);
  if (h != INVALID_HANDLE_VALUE)
  {
    do
    {
      if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && fd.cFileName[0] != L'.')
      {
        UString dir = root + UString(L"\\") + (const wchar_t *)fd.cFileName;
        UString devName = (const wchar_t *)fd.cFileName;
        
        CDeviceNand dv;
        // hit a valid on-disk record -> skip OTP decrypt/keyinit entirely
        bool hit = KeystoneCacheLoadDevice(devName, DirSig64(dir, L"*"), dv);
        
        if (hit)
          g_devCache.Add(dv);
        else
        {
          
          LoadCtrDevice(dir, g_devCache);
          
        }
      }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  DirWriteTime(root, g_devsRootMtime);
  g_devsCached = true;
  return g_devCache;
}

// Called from the options page "Rebuild cache" button: drop both the key table cache
// and the ctrdevice scan cache so the next access re-reads disk.
extern "C" void Z7CtrInvalidateKeystoneCache()
{
  C3dsKeys::Instance().Invalidate();
  InvalidateCtrDevices();
}


// Live decrypting seekable stream over a single NAND partition. Used by
// IInArchiveGetStream so 7zFM opens the partition in place (MBR/FAT handler
// reads from this stream directly) instead of dumping the whole volume to a
// temp file.
Z7_CLASS_IMP_IInStream(CDecryptNandStream)
  CMyComPtr<IInStream> Stream;
  UInt64 BaseAbs;   // partition absolute offset in the source image
  UInt64 Size;      // partition size
  Byte Key[16];
  Byte Ctr[16];
  bool Twl;
  UInt64 _virtPos;
  UInt64 _phyPos;
public:
  HRESULT Init(IInStream *s, UInt64 baseAbs, UInt64 size,
      const Byte *key, const Byte *ctr, bool twl)
  {
    Stream = s;
    BaseAbs = baseAbs;
    Size = size;
    Twl = twl;
    memcpy(Key, key, 16);
    memcpy(Ctr, ctr, 16);
    _virtPos = 0;
    _phyPos = (UInt64)(Int64)-1;
    return S_OK;
  }
};

Z7_COM7F_IMF(CDecryptNandStream::Read(void *data, UInt32 size, UInt32 *processedSize))
{
  if (processedSize)
    *processedSize = 0;
  if (_virtPos >= Size)
    return S_OK;
  {
    UInt64 rem = Size - _virtPos;
    if (size > rem)
      size = (UInt32)rem;
  }
  if (size == 0)
    return S_OK;

  const UInt64 abs = BaseAbs + _virtPos;
  if (_phyPos != abs)
  {
    RINOK(Stream->Seek((Int64)abs, STREAM_SEEK_SET, NULL));
    _phyPos = abs;
  }
  UInt32 got = 0;
  RINOK(Stream->Read(data, size, &got));
  _phyPos += got;
  _virtPos += got;

  if (got != 0)
  {
    Byte *out = (Byte *)data;
    if (Twl)
    {
      // Plaintext NCSD header prefix: only the MBR table [0x1BE,0x200) is
      // encrypted; ciphertext (block reversal) starts at 0x12E00.
      const UInt64 kPlainEnd = 0x12E00, kMbrLo = 0x1BE, kMbrHi = 0x200;
      size_t p = 0;
      while (p < got)
      {
        UInt64 cur = abs + p;
        size_t avail = got - p;
        if (cur < kPlainEnd)
        {
          if (cur < kMbrHi && cur + avail > kMbrLo)
          {
            UInt64 s = (cur > kMbrLo) ? cur : kMbrLo;
            UInt64 e = (cur + avail < kMbrHi) ? cur + avail : kMbrHi;
            Byte mbr[0x42];
            AesCtr_DecodeTwl(Key, Ctr, s, mbr, (size_t)(e - s));
            memcpy(out + p + (size_t)(s - cur), mbr, (size_t)(e - s));
          }
          size_t step = (size_t)(kPlainEnd - cur);
          if (step > avail) step = avail;
          p += step;
        }
        else
        {
          AesCtr_DecodeTwl(Key, Ctr, cur, out + p, avail);
          p += avail;
        }
      }
    }
    else
      AesCtr_Decode3ds(Key, Ctr, abs, out, got);
  }

  if (processedSize)
    *processedSize = got;
  return S_OK;
}

Z7_COM7F_IMF(CDecryptNandStream::Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition))
{
  switch (seekOrigin)
  {
    case STREAM_SEEK_SET: break;
    case STREAM_SEEK_CUR: offset += (Int64)_virtPos; break;
    case STREAM_SEEK_END: offset += (Int64)Size; break;
    default: return STG_E_INVALIDFUNCTION;
  }
  if (offset < 0)
    return HRESULT_WIN32_ERROR_NEGATIVE_SEEK;
  _virtPos = (UInt64)offset;
  if (newPosition)
    *newPosition = (UInt64)offset;
  return S_OK;
}

Z7_CLASS_IMP_CHandler_IInArchive_1(
  IInArchiveGetStream
)
  CMyComPtr<IInStream> _stream;
  CObjectVector<CItem> _items;

  // CIA title key (decrypted once) + per-content CBC decryption state
  bool _titleKeyOk;
  Byte _titleKey[16];
  bool _titleKeyNewOk;
  Byte _titleKeyNew[16];
  const Byte *_cryptKeyPtr;
  bool _cryptActive;
  UInt64 _cryptStart;
  Byte _cryptCtr[16];
  __declspec(align(16)) UInt32 _cryptState[AES_NUM_IVMRK_WORDS];
  UInt64 _cryptPos;
  CByteBuffer _decBuf;      // whole-decrypted content buffer used during parsing/extract
  UInt64 _decStart;
  bool _decActive;
  bool _decUseNew;
  Byte _decCtr[16];
  CByteBuffer _chunkBuf;    // 1MB heap chunk (avoid large stack arrays; 7zFM uses a small stack)

  CN3dsInfo _info;          // archive-level technical info for the Properties dialog

  bool _isDev;              // unit-key type (dev vs retail), lazily determined
  bool _isDevSet;

  UString _srcDir;          // directory of the opened source file (nand.bin),
                            // used to look up per-device key material next to it

  // SNAKE update: Contents.cnt container expansion (CupTheCnt format)
  UInt64 _cntOff;
  UInt64 _cntSize;
  bool _cntFound;
  UString _cntDir;          // directory that holds Contents.cnt (e.g. "Partition_0/contents/")
  unsigned _cupCount;
  UInt64 _cupTitles[256];   // CupList title ids (little-endian u64), index-aligned with Contents entries

  void AddItem(const UString &path, UInt64 off, UInt64 size, bool isDir,
      bool encrypted = false, UInt64 cryptStart = 0, const Byte *cryptCtr = NULL,
      bool useNewKey = false, const Byte *innerKey = NULL,
      const Byte *innerCtr = NULL, UInt64 innerBase = 0, UInt64 innerOff = 0)
  {
    CItem it;
    it.Path = path;
    it.Offset = off;
    it.Size = size;
    it.IsDir = isDir;
    it.Encrypted = encrypted;
    it.UseNewKey = useNewKey;
    it.CryptStart = cryptStart;
    if (cryptCtr)
      memcpy(it.CryptCtr, cryptCtr, 16);
    else
      memset(it.CryptCtr, 0, 16);
    it.HasInnerKey = (innerKey != NULL);
    if (innerKey)
      memcpy(it.InnerKey, innerKey, 16);
    it.InnerBase = innerBase;
    it.InnerOff = innerOff;
    it.Virtual = false;
    it.StreamCtr = false;
    it.StreamTwl = false;
    if (innerCtr)
      memcpy(it.InnerCtr, innerCtr, 16);
    else
      memset(it.InnerCtr, 0, 16);
    _items.Add(it);
  }

  HRESULT Seek(UInt64 pos) { return InStream_SeekSet(_stream, pos); }
  HRESULT ReadF(Byte *p, size_t size) { return ReadStream_FALSE(_stream, p, size); }
  HRESULT ReadAt(UInt64 pos, Byte *p, size_t size)
  {
    RINOK(Seek(pos));
    return ReadF(p, size);
  }

  // Decryption-aware read: when _cryptActive, the input region is AES-CBC
  // encrypted with key=_titleKey, IV=_cryptCtr, chain starting at _cryptStart.
  // Sequential access from _cryptPos is cached in _cryptState (efficient for
  // the parser's mostly-linear walk); arbitrary seeks restart from _cryptStart.
  HRESULT ReadDec(UInt64 pos, Byte *p, size_t size)
  {
    if (_decActive)
    {
      // random access into the already-decrypted whole-content buffer
      if (pos < _decStart || pos + size > _decStart + _decBuf.Size())
        return S_FALSE;
      memcpy(p, _decBuf + (size_t)(pos - _decStart), size);
      return S_OK;
    }
    if (!_cryptActive)
      return ReadAt(pos, p, size);
    if (_cryptPos != pos)
    {
      // only restart from _cryptStart when seeking backwards; sequential
      // forward reads keep the running CBC chain (avoids O(n^2) restarts).
      if (pos < _cryptPos)
      {
        AesCbc_Start(_cryptState, _cryptKeyPtr, _cryptCtr);
        _cryptPos = _cryptStart;
      }
      // advance the CBC chain up to pos (decrypt intermediate blocks, no emit):
      UInt64 target = pos & ~(UInt64)15;
      __declspec(align(16)) Byte tmp[AES_BLOCK_SIZE];
      while (_cryptPos < target)
      {
        UInt64 a = _cryptPos & ~(UInt64)15;
        RINOK(ReadAt(a, tmp, AES_BLOCK_SIZE));
        AesCbc_Step(_cryptState, tmp, 1);
        _cryptPos = a + 16;
      }
    }
    size_t done = 0;
    while (done < size)
    {
      if (_cryptPos >= pos + size)
        break;
      UInt64 alignedStart = (pos + done) & ~(UInt64)15;
      __declspec(align(16)) Byte buf[AES_BLOCK_SIZE];
      RINOK(ReadAt(alignedStart, buf, AES_BLOCK_SIZE));
      AesCbc_Step(_cryptState, buf, 1);
      _cryptPos = alignedStart + 16;
      UInt64 take = (alignedStart + 16) - (pos + done);
      if (take > size - done)
        take = size - done;
      memcpy(p + done, buf + ((pos + done) - alignedStart), (size_t)take);
      done += (size_t)take;
    }
    return S_OK;
  }

  HRESULT ParseExeFS(UInt64 base, const UString &prefix,
      const Byte *nk0 = NULL, const Byte *nk1 = NULL, const Byte *ctr2 = NULL, bool inner = false);
  HRESULT ParseRomFS(UInt64 base, const UString &prefix,
      const Byte *nk1 = NULL, const Byte *ctr3 = NULL, bool inner = false);
  HRESULT ParseNCCH(UInt64 base, const UString &prefix);
  HRESULT ParseCia(UInt64 base);
  HRESULT ParseNcsd(UInt64 base);
  HRESULT ParseNandNcsd(UInt64 base);
  HRESULT ParseCntStandalone(UInt64 base);
  HRESULT ParseTmd(UInt64 base);
  HRESULT ParseFirm(UInt64 base);
  HRESULT Open2(IInStream *);

public:
  CHandler()
    : _titleKeyOk(false), _titleKeyNewOk(false), _cryptKeyPtr(NULL),
      _cryptActive(false), _cryptStart(0), _cryptPos(0),
      _decStart(0), _decActive(false), _decUseNew(false),
      _isDev(false), _isDevSet(false),
      _cntOff(0), _cntSize(0), _cntFound(false), _cupCount(0)
  {
    memset(_titleKey, 0, 16);
    memset(_titleKeyNew, 0, 16);
    memset(_cryptCtr, 0, 16);
    memset(_cryptState, 0, sizeof(_cryptState));
    memset(_decCtr, 0, 16);
    memset(_cupTitles, 0, sizeof(_cupTitles));
  }
  ~CHandler() {}
};

static const Byte kProps[] =
{
  kpidPath,
  kpidIsDir,
  kpidSize,
  kpidPackSize
};

// Custom archive property IDs (shown in the 7zFM Properties dialog).
// Defined from kpidUserDefined to avoid colliding with built-in PROPIDs.
enum
{
  kpidN3dsContainer   = kpidUserDefined,
  kpidN3dsMediaId,
  kpidN3dsTitleId,
  kpidN3dsProgramId,
  kpidN3dsTitleVer,
  kpidN3dsMakerCode,
  kpidN3dsProductCode,
  kpidN3dsCommonKey,
  kpidN3dsContentCount,
  kpidN3dsPartitions,
  kpidN3dsCiaType,
  kpidN3dsCiaVersion,
  kpidN3dsTicketId,
  kpidN3dsDeviceId,
  kpidN3dsTitleKey,
  kpidN3dsExefs,
  kpidN3dsRomfs,
  kpidN3dsCrypto,
  kpidN3dsContent0,
  kpidN3dsFirmSig,
  kpidN3dsFirmKind,
  kpidN3dsFirmEntry
};

static const CStatProp kArcProps[] =
{
  { "Container",        kpidN3dsContainer,     VT_BSTR },
  { "Media ID",         kpidN3dsMediaId,       VT_BSTR },
  { "Title ID",         kpidN3dsTitleId,       VT_BSTR },
  { "Program ID",       kpidN3dsProgramId,     VT_BSTR },
  { "Title Version",    kpidN3dsTitleVer,      VT_BSTR },
  { "Maker Code",       kpidN3dsMakerCode,     VT_BSTR },
  { "Product Code",     kpidN3dsProductCode,   VT_BSTR },
  { "Common Key",       kpidN3dsCommonKey,     VT_BSTR },
  { "Contents",         kpidN3dsContentCount,  VT_UI4 },
  { "Partitions",       kpidN3dsPartitions,    VT_UI4 },
  { "CIA Type",         kpidN3dsCiaType,       VT_BSTR },
  { "CIA Version",      kpidN3dsCiaVersion,    VT_BSTR },
  { "Ticket ID",        kpidN3dsTicketId,      VT_BSTR },
  { "Device ID",        kpidN3dsDeviceId,      VT_BSTR },
  { "Title Key",        kpidN3dsTitleKey,      VT_BSTR },
  { "ExeFS",            kpidN3dsExefs,         VT_BSTR },
  { "RomFS",            kpidN3dsRomfs,         VT_BSTR },
  { "Encryption",       kpidN3dsCrypto,        VT_BSTR },
  { "Content 0",        kpidN3dsContent0,      VT_BSTR },
  { "FIRM Signature",   kpidN3dsFirmSig,       VT_BSTR },
  { "FIRM Type",        kpidN3dsFirmKind,      VT_BSTR },
  { "FIRM Entrypoint",  kpidN3dsFirmEntry,     VT_BSTR },
  { "File System",      kpidFileSystem,        VT_BSTR }
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps_WITH_NAME

// ----------------------------------------------------------------
// FIRM (standalone .firm): magic 'FIRM' @0; section table @0x40 (4 x 0x30);
// RSA-2048 signature @0x100. Sections are listed raw (the New3DS arm9bin extra
// encryption layer is not decrypted this round).
// ----------------------------------------------------------------
HRESULT CHandler::ParseFirm(UInt64 base)
{
  Byte hdr[0x100];
  RINOK(ReadAt(base, hdr, 0x100));
  if (memcmp(hdr, "FIRM", 4) != 0)
    return S_FALSE;

  _info.Container = 7;
  _info.FirmArm11Entry = GetUi32(hdr + 0x08);
  _info.FirmArm9Entry  = GetUi32(hdr + 0x0C);

  // signature block @0x100 (0x100 bytes); all-zero means no signature present
  Byte sigBlock[0x100];
  memset(sigBlock, 0, sizeof(sigBlock));
  bool sigAllZero = true;
  if (ReadAt(base + 0x100, sigBlock, 0x100) == S_OK)
    for (int i = 0; i < 0x100; i++)
      if (sigBlock[i]) { sigAllZero = false; break; }

  static const char *kSecNames[4] =
    { "arm9.bin", "arm11_0.bin", "arm11_1.bin", "arm11_2.bin" };
  int ok = 0, total = 0;
  for (unsigned i = 0; i < 4; i++)
  {
    const Byte *sh = hdr + 0x40 + i * 0x30;
    UInt32 off  = GetUi32(sh + 0x00);
    UInt32 size = GetUi32(sh + 0x08);
    if (size == 0)
      continue;
    total++;

    // verify the embedded per-section SHA-256 (sh+0x10, 32 bytes) on a stream
    CSha256 st;
    Sha256_Init(&st);
    __declspec(align(16)) Byte blk[0x10000];
    UInt64 pos = base + off, left = size;
    while (left > 0)
    {
      UInt32 n = left > sizeof(blk) ? sizeof(blk) : (UInt32)left;
      if (ReadAt(pos, blk, n) != S_OK)
        break;
      Sha256_Update(&st, blk, n);
      pos += n;
      left -= n;
    }
    Byte dg[32];
    Sha256_Final(&st, dg);
    if (left == 0 && memcmp(dg, sh + 0x10, 32) == 0)
      ok++;

    AddItem(UString(kSecNames[i]), base + off, size, false,
        false, 0, NULL, false, NULL, NULL, base, off);
  }
  _info.FirmSectionsTotal = total;
  _info.FirmSectionsOk = ok;
  memset(_info.FirmKind, 0, sizeof(_info.FirmKind));

  // Signature tri-state: 1=valid(official), 2=sighax/homebrew(rejected by key),
  // 3=corrupt/missing, 0=not verified(no public key loaded). Try retail then dev.
  if (sigAllZero)
  {
    _info.FirmSigState = 3;
  }
  else
  {
    int vr = FirmRsaCheck(hdr, sigBlock, false);
    if (vr != 1)
      vr = FirmRsaCheck(hdr, sigBlock, true);
    if (vr == 1)
      _info.FirmSigState = 1;
    else if (vr == -1)
      _info.FirmSigState = 2;
    else
      _info.FirmSigState = 0;
  }
  return S_OK;
}

// ----------------------------------------------------------------
// ExeFS
// ----------------------------------------------------------------
HRESULT CHandler::ParseExeFS(UInt64 base, const UString &prefix,
    const Byte *nk0, const Byte *nk1, const Byte *ctr2, bool inner)
{
  Byte hdr[0x200];
  RINOK(ReadDec(base, hdr, 0x200));
  if (inner && nk0)
    AesCtr_Decode3ds(nk0, ctr2, 0, hdr, 0x200);   // ExeFS header: keyid0, counter starts at 0

  // ExeFS file table starts at offset 0x00: 10 x 0x10 (name[8] + offset + size).
  // File data sits at base + 0x200 + file->offset.
  for (unsigned i = 0; i < 10; i++)
  {
    const Byte *e = hdr + i * 0x10;
    UInt32 off = GetUi32(e + 8);
    UInt32 size = GetUi32(e + 12);
    if (size == 0)
      continue;
    UString name = ReadName8(e);
    // banner/icon use keyid 0 (signature key); all others use keyid 1.
    bool k0 = (name == L"banner" || name == L"icon");
    const Byte *fkey = k0 ? nk0 : nk1;
    AddItem(prefix + name, base + 0x200 + off, size, false,
        false, 0, NULL, false,
        (inner && fkey) ? fkey : NULL, ctr2, base, 0x200 + off);
  }
  return S_OK;
}

// ----------------------------------------------------------------
// RomFS (IVFC + level3 metadata, per GodMode9 romfs.h)
//   IVFC header @ base, level3 header @ base + 0x1000
//   level3 offsets are relative to (base + 0x1000)
// ----------------------------------------------------------------
HRESULT CHandler::ParseRomFS(UInt64 base, const UString &prefix,
    const Byte *nk1, const Byte *ctr3, bool inner)
{
  Byte hdr[0x1000];
  RINOK(ReadDec(base, hdr, 0x1000));
  if (inner && nk1)
    AesCtr_Decode3ds(nk1, ctr3, 0, hdr, 0x1000);   // whole RomFS region starts at counter base

  if (memcmp(hdr, "IVFC", 4) != 0)
    return S_FALSE;

  UInt64 lv3 = base + 0x1000;

  // RomFsLv3Header (10 u32):
  //   size_header@0x00 offset_dirhash@0x04 size_dirhash@0x08
  //   offset_dirmeta@0x0C size_dirmeta@0x10
  //   offset_filehash@0x14 size_filehash@0x18
  //   offset_filemeta@0x1C size_filemeta@0x20
  //   offset_filedata@0x24
  Byte l3[0x28];
  RINOK(ReadDec(lv3, l3, 0x28));
  if (inner && nk1)
    AesCtr_Decode3ds(nk1, ctr3, lv3 - base, l3, 0x28);

  UInt64 offDirMeta   = GetUi32(l3 + 0x0C);
  UInt64 offFileMeta  = GetUi32(l3 + 0x1C);
  UInt64 offFileData  = GetUi32(l3 + 0x24);

  UInt64 dmBase = lv3 + offDirMeta;   // directory meta table
  UInt64 fmBase = lv3 + offFileMeta;  // file meta table
  UInt64 fdBase = lv3 + offFileData;  // file data

  // DirMeta: parent@0, sibling@4, child@8, file@0xC, samehash@0x10, name_len@0x14, wname@0x18
  // FileMeta: parent@0, sibling@4, data@8(u64), size@0x10(u64), samehash@0x18, name_len@0x1C, wname@0x20

  struct CWalk
  {
    UInt32 DirOff;
    UString Path;
  };

  CObjectVector<CWalk> stack;
  {
    CWalk root;
    root.DirOff = 0;   // root dir meta is at offset 0
    root.Path = prefix;
    stack.Add(root);
  }

  CObjectVector<UInt32> seenDirs;
  UInt32 dirCount = 0, fileCount = 0;
  while (stack.Size() != 0)
  {
    if (dirCount > 200000)
      break;   // safety cap (dedupe should normally prevent this)
    CWalk cur = stack[stack.Size() - 1];
    stack.DeleteBack();
    UInt32 dOff = cur.DirOff;
    if (dOff == 0xFFFFFFFF)
      continue;
    bool isSeen = false;
    for (UInt32 _s = 0; _s < seenDirs.Size(); _s++)
      if (seenDirs[_s] == dOff) { isSeen = true; break; }
    if (isSeen)
      continue;
    seenDirs.Add(dOff);
    dirCount++;

    Byte dent[0x18];
    RINOK(ReadDec(dmBase + dOff, dent, 0x18));
    if (inner && nk1)
      AesCtr_Decode3ds(nk1, ctr3, (dmBase + dOff) - base, dent, 0x18);
    UInt32 child  = GetUi32(dent + 0x08);
    UInt32 file   = GetUi32(dent + 0x0C);
    UInt32 nameLen = GetUi32(dent + 0x14);

    UString dirName;
    if (nameLen > 0 && nameLen < 0x400)
    {
      CByteBuffer nb;
      nb.Alloc((size_t)nameLen);
      RINOK(ReadDec(dmBase + dOff + 0x18, nb, (size_t)nameLen));
      if (inner && nk1)
        AesCtr_Decode3ds(nk1, ctr3, (dmBase + dOff + 0x18) - base, nb, (size_t)nameLen);
      dirName = ReadName16BE(nb, nameLen);   // nameLen is UTF-16 BYTE count
    }
    else
      dirName = L"";   // root dir has empty name

    UString thisPath = cur.Path + dirName;
    if (!thisPath.IsEmpty() && thisPath.Back() != L'/')
      thisPath += L'/';

    // files in this dir
    UInt32 fOff = file;
    UInt32 guard = 0;
    while (fOff != 0xFFFFFFFF && guard++ < (1 << 22))
    {
      Byte fent[0x20];
      RINOK(ReadDec(fmBase + fOff, fent, 0x20));
      if (inner && nk1)
        AesCtr_Decode3ds(nk1, ctr3, (fmBase + fOff) - base, fent, 0x20);
      UInt32 sibling  = GetUi32(fent + 0x04);
      UInt64 dataOff  = GetUi64(fent + 0x08);
      UInt64 dataSize = GetUi64(fent + 0x10);
      UInt32 fnameLen = GetUi32(fent + 0x1C);

      UString fname;
      if (fnameLen > 0 && fnameLen < 0x400)
      {
        CByteBuffer nb;
        nb.Alloc((size_t)fnameLen);
        RINOK(ReadDec(fmBase + fOff + 0x20, nb, (size_t)fnameLen));
        if (inner && nk1)
          AesCtr_Decode3ds(nk1, ctr3, (fmBase + fOff + 0x20) - base, nb, (size_t)fnameLen);
        fname = ReadName16BE(nb, fnameLen);   // fnameLen is UTF-16 BYTE count
      }
      else
        fname = L"file";

      // ---- SNAKE update container: remember CupList title ids and Contents.cnt ----
      if (fname == L"CupList")
      {
        size_t cln = (size_t)dataSize;
        CByteBuffer clb;
        clb.Alloc(cln);
        RINOK(ReadDec(fdBase + dataOff, clb, cln));
        if (inner && nk1)
          AesCtr_Decode3ds(nk1, ctr3, (fdBase + dataOff) - base, clb, cln);
        _cupCount = (unsigned)(dataSize / 8);
        if (_cupCount > 256)
          _cupCount = 256;
        for (unsigned _c = 0; _c < _cupCount; _c++)
          _cupTitles[_c] = GetUi64((Byte *)clb + _c * 8);
      }
      else if (fname == L"Contents.cnt")
      {
        _cntOff = fdBase + dataOff;
        _cntSize = dataSize;
        _cntFound = true;
        _cntDir = thisPath;
      }

      AddItem(thisPath + fname, fdBase + dataOff, dataSize, false,
          false, 0, NULL, false,
          (inner && nk1) ? nk1 : NULL, ctr3, base, 0);
      fOff = sibling;
      fileCount++;
    }

    // push subdirectories
    UInt32 cOff = child;
    guard = 0;
    while (cOff != 0xFFFFFFFF && guard++ < (1 << 22))
    {
      bool pushed = false;
      for (UInt32 _s = 0; _s < seenDirs.Size(); _s++)
        if (seenDirs[_s] == cOff) { pushed = true; break; }
      if (!pushed)
      {
        CWalk w;
        w.DirOff = cOff;
        w.Path = thisPath;
        stack.Add(w);
      }
      Byte dent2[0x18];
      RINOK(ReadDec(dmBase + cOff, dent2, 0x18));
      if (inner && nk1)
        AesCtr_Decode3ds(nk1, ctr3, (dmBase + cOff) - base, dent2, 0x18);
      cOff = GetUi32(dent2 + 0x04); // sibling of this child dir
    }
  }

  // ---- Expand Contents.cnt (SNAKE update) into per-title .cia items ----
  if (_cntFound)
  {
    // Need header + 256 entries (8 B each at 0xC00) => 0x1400 bytes.
    UInt64 hs = (_cntSize < 0x1400) ? _cntSize : 0x1400;
    CByteBuffer hb;
    hb.Alloc((size_t)hs);
    RINOK(ReadDec(_cntOff, hb, (size_t)hs));
    if (inner && nk1)
      AesCtr_Decode3ds(nk1, ctr3, _cntOff - base, hb, (size_t)hs);
    if (memcmp((Byte *)hb, "CONT", 4) == 0)
    {
      // Contents_header: magic[4] + unknown[0xBFC] + 256 entries (offset, offset_end u32)
      // Each entry's CIA payload starts at Contents.cnt_abs + entry.offset + 0xC00.
      // Only entries with a nonzero CupList title id are real titles (matches reference).
      for (unsigned i = 0; i < 256; i++)
      {
        if (_cupTitles[i] == 0)          // no title -> not a real entry
          continue;
        UInt32 eOff = GetUi32((Byte *)hb + 0xC00 + i * 8);
        UInt32 eEnd = GetUi32((Byte *)hb + 0xC00 + i * 8 + 4);
        if (eOff == 0 || eEnd <= eOff || eEnd == 0xFFFFFFFF)   // invalid / sentinel
          continue;
        UInt64 cOff = _cntOff + (UInt64)eOff + 0xC00;
        UInt64 cSize = (UInt64)eEnd - eOff;
        // Per-title CIAs are collected in a dedicated "Contents/" subfolder of
        // the cnt's directory, instead of being flattened next to Contents.cnt.
        UString nm = _cntDir + UString(L"Contents/") + HexUInt64Padded(_cupTitles[i]) + UString(L".cia");
        AddItem(nm, cOff, cSize, false);
      }
    }
  }

  return S_OK;
}

// ----------------------------------------------------------------
// NCCH (CXI/CFA)
// ----------------------------------------------------------------
HRESULT CHandler::ParseNCCH(UInt64 base, const UString &prefix)
{
  Byte hdr[0x200];
  RINOK(ReadDec(base, hdr, 0x200));

  if (memcmp(hdr + 0x100, "NCCH", 4) != 0)
    return S_FALSE;

  // GodMode9 NcchHeader: offset_exefs@0x1A0, size_exefs@0x1A4,
  //                      offset_romfs@0x1B0, size_romfs@0x1B4  (media units)
  UInt64 exefsOff  = (UInt64)GetUi32(hdr + 0x1A0) * kMediaUnit;
  UInt64 exefsSize = (UInt64)GetUi32(hdr + 0x1A4) * kMediaUnit;
  UInt64 romfsOff  = (UInt64)GetUi32(hdr + 0x1B0) * kMediaUnit;
  UInt64 romfsSize = (UInt64)GetUi32(hdr + 0x1B4) * kMediaUnit;

  // ---- NCCH data-region AES-CTR (GodMode9 SetNcchKey / CryptNcch) ----
  Byte flags3 = hdr[0x18B];   // hdr + 0x188 + 3
  Byte flags7 = hdr[0x18F];   // hdr + 0x188 + 7
  Byte sig16[16];
  memcpy(sig16, hdr, 16);
  UInt64 programId = GetUi64(hdr + 0x118);   // ncch.h: program_id at 0x118 (0x108 is content_id)
  UInt32 hashSeed  = GetUi32(hdr + 0x114);   // ncch.h: hash_seed at 0x114
  bool noCrypto    = (flags7 & 0x04) != 0;
  bool fixedCrypto = (flags7 & 0x01) != 0;
  bool seedCrypto  = (flags7 & 0x20) != 0;

  // Directly-opened NCCH file (.cxi/.ncch/.cfa): fill archive technical info.
  if (prefix.IsEmpty())
  {
    _info.Clear();
    _info.Container = 3;
    _info.NcchTitleId = GetUi64(hdr + 0x108);
    _info.ProgramId = GetUi64(hdr + 0x118);
    _info.NcchVersion = GetBe16(hdr + 0x112);
    _info.MakerCode = GetBe16(hdr + 0x110);
    memcpy(_info.ProductCode, hdr + 0x128, 0x10);
    memcpy(_info.NcchFlags, hdr + 0x180, 8);
    _info.ExeFsOff = exefsOff; _info.ExeFsSize = exefsSize;
    _info.RomFsOff = romfsOff; _info.RomFsSize = romfsSize;
    _info.SeedIndex = GetUi16(hdr + 0x1BC);
    if (noCrypto) _info.Crypto = 0;
    else if (fixedCrypto) _info.Crypto = 1;
    else if (seedCrypto) _info.Crypto = 3;
    else _info.Crypto = 2;
  }

  // NCCH (version >= 2) counter base: partitionId reversed + section byte at [8]
  Byte partId[8];
  memcpy(partId, hdr + 0x108, 8);
  Byte ctrBase[16];
  memset(ctrBase, 0, 16);
  for (unsigned i = 0; i < 8; i++)
    ctrBase[i] = partId[7 - i];

  Byte nk0[16], nk1[16];
  bool haveNk0 = false, haveNk1 = false;
  if (noCrypto)
  {
    // plaintext data region, no inner layer
  }
  else if (fixedCrypto)
  {
    // fixed-key crypto: keyslot 0x11, key = sysKey/zeroKey used directly
    Byte sysKey[16] = { 0x52, 0x7C, 0xE6, 0x30, 0xA9, 0xCA, 0x30, 0x5F,
        0x36, 0x96, 0xF3, 0xCD, 0xE9, 0x54, 0x19, 0x4B };
    Byte zeroKey[16] = { 0 };
    const Byte *fk = (programId & ((UInt64)0x10 << 32)) ? sysKey : zeroKey;
    memcpy(nk0, fk, 16);
    memcpy(nk1, fk, 16);
    haveNk0 = haveNk1 = true;
  }
  else
  {
    // Load candidate keyX values for both retail and dev unit key sets.
    // Which set actually applies is decided by trial-decrypting the ExeFS header.
    const Byte *k0r = C3dsKeys::Instance().Find("slot0x2ckeyx", false);
    const Byte *k0d = C3dsKeys::Instance().Find("slot0x2ckeyx", true);

    Byte slot1 = (flags3 == 0x0A) ? 0x18 : (flags3 == 0x0B) ? 0x1B : (flags3 == 0) ? 0x2C : 0x25;
    char nm[32];
    sprintf_s(nm, "slot0x%02xkeyx", (unsigned)slot1);
    const Byte *k1r = C3dsKeys::Instance().Find(nm, false);
    const Byte *k1d = C3dsKeys::Instance().Find(nm, true);

    // Decide unit-key set by trial decryption of the ExeFS header (keyid0).
    if (!noCrypto && exefsSize != 0)
    {
      Byte ehdr0[0x200];
      RINOK(ReadDec(base + exefsOff, ehdr0, 0x200));
      Byte c2t[16];
      memcpy(c2t, ctrBase, 16); c2t[8] = 2;
      for (int pass = 0; pass < 2 && !haveNk0; pass++)
      {
        const Byte *kx = (pass == 0) ? k0r : k0d;
        if (!kx)
          continue;
        Byte nk[16];
        C3dsNormalKey(nk, kx, sig16);
        Byte t[0x200];
        memcpy(t, ehdr0, 0x200);
        AesCtr_Decode3ds(nk, c2t, 0, t, 0x200);
        if (ValidExeFsHdr(t))
        {
          memcpy(nk0, nk, 16);
          haveNk0 = true;
          _isDev = (pass == 1);
          _isDevSet = true;
        }
      }
      if (!haveNk0)
      {
        // Neither set decrypted the header cleanly; prefer dev if present.
        _isDev = k0d ? true : false;
        _isDevSet = true;
      }
    }
    else
    {
      _isDev = k0d ? true : false;
      _isDevSet = true;
    }

    // keyid 1 (.code, RomFS): keyslot by flags3, keyY = seed key or signature
    const Byte *k1 = _isDev ? k1d : k1r;
    if (k1)
    {
      if (seedCrypto)
      {
        Byte seed[16];
        if (C3dsKeys::Instance().FindSeed(seed, programId, hashSeed))
        {
          Byte seedY[16];
          NcchSeedKeyY(seedY, sig16, seed);
          C3dsNormalKey(nk1, k1, seedY);
          haveNk1 = true;
        }
      }
      else
      {
        C3dsNormalKey(nk1, k1, sig16);
        haveNk1 = true;
      }
    }
  }

  // ---- ExeFS ----
  if (exefsSize != 0)
  {
    Byte ehdr[0x200];
    RINOK(ReadDec(base + exefsOff, ehdr, 0x200));
    Byte c2[16];
    memcpy(c2, ctrBase, 16); c2[8] = 2;
    bool valid = ValidExeFsHdr(ehdr);
    bool inner = false;
    if (!valid && !noCrypto && haveNk0)
    {
      AesCtr_Decode3ds(nk0, c2, 0, ehdr, 0x200);   // inner AES-CTR, ExeFS header keyid0
      valid = ValidExeFsHdr(ehdr);
      inner = valid;
    }
    if (valid)
    {
      RINOK(ParseExeFS(base + exefsOff, prefix, nk0, haveNk1 ? nk1 : nk0, c2, inner));
    }
    else
    {
      AddItem(prefix + L"ExeFS.bin", base + exefsOff, exefsSize, false, false, 0, NULL, false);
    }
  }

  // ---- RomFS ----
  if (romfsSize != 0)
  {
    Byte magic[4];
    RINOK(ReadDec(base + romfsOff, magic, 4));
    bool plain = (memcmp(magic, "IVFC", 4) == 0);
    Byte c3[16];
    memcpy(c3, ctrBase, 16); c3[8] = 3;
    if (!plain && haveNk1)
    {
      Byte m[4];
      memcpy(m, magic, 4);
      AesCtr_Decode3ds(nk1, c3, 0, m, 4);
      plain = (memcmp(m, "IVFC", 4) == 0);
    }
    if (plain)
    {
      // plaintext RomFS (IVFC): parse directly, inner layer off; or decrypted above
      RINOK(ParseRomFS(base + romfsOff, prefix, haveNk1 ? nk1 : NULL, c3, haveNk1));
    }
    if (!plain)
    {
      AddItem(prefix + L"RomFS.bin", base + romfsOff, romfsSize, false, false, 0, NULL, false);
    }
  }

  // An NCCH with no usable partition must still open (expose the header).
  if (_items.Size() == 0)
    AddItem(prefix + L"ncch.bin", base, 0x200, false, false, 0, NULL, false);

  return S_OK;
}

// ----------------------------------------------------------------
// CIA (CTR Importable Archive)
// Layout follows GM9 CiaHeader / GetCiaInfo (this matches the real on-disk layout
// verified against archive.org eShop CIA and the Gigaleak CIA):
//   u32 size_header (0x2020), u16 type, u16 version,
//   u32 size_cert, u32 size_ticket, u32 size_tmd, u32 size_meta,
//   u64 size_content, then content_index[0x2000].
//   Sections in order: cert, ticket, tmd, content, meta, 64-byte aligned.
// ----------------------------------------------------------------
HRESULT CHandler::ParseCia(UInt64 base)
{
  Byte hdr[0x20];
  RINOK(ReadAt(base, hdr, 0x20));

  UInt32 headerSize = GetUi32(hdr + 0x00);   // 0x2020
  UInt32 type       = GetUi32(hdr + 0x04);   // low16: type, high16: version
  UInt32 certSize   = GetUi32(hdr + 0x08);
  UInt32 tikSize    = GetUi32(hdr + 0x0C);
  UInt32 tmdSize    = GetUi32(hdr + 0x10);
  UInt32 metaSize   = GetUi32(hdr + 0x14);
  UInt64 contentSize= GetUi64(hdr + 0x18);

  if (headerSize < 0x20 || (type & 0xFFFF) > 1)
    return S_FALSE;

  // ---- fill archive technical info (Properties dialog) ----
  _info.Clear();
  _info.Container = 1;
  _info.CiaType = type & 0xFFFF;
  _info.CiaVersion = type >> 16;
  _info.CiaContentSize = contentSize;

  #define MY_ALIGN_64(x) (((x) + 63) & ~(UInt64)63)

  UInt64 offsetCert   = MY_ALIGN_64(headerSize);
  UInt64 offsetTicket = offsetCert   + MY_ALIGN_64(certSize);
  UInt64 offsetTmd    = offsetTicket + MY_ALIGN_64(tikSize);
  UInt64 offsetContent= offsetTmd    + MY_ALIGN_64(tmdSize);
  UInt64 offsetMeta   = (metaSize != 0) ? offsetContent + MY_ALIGN_64(contentSize) : 0;

  if (certSize != 0)
    AddItem(UString(L"cert.bin"), base + offsetCert, certSize, false);
  if (tikSize != 0)
    AddItem(UString(L"ticket.bin"), base + offsetTicket, tikSize, false);
  if (tmdSize != 0)
    AddItem(UString(L"tmd.bin"), base + offsetTmd, tmdSize, false);

  // ---- decrypt the title key from the ticket (GodMode9 CryptTitleKey) ----
  _titleKeyOk = false;
  if (tikSize >= 0x1F4)
  {
    Byte tik[0x200];
    RINOK(ReadAt(base + offsetTicket, tik, 0x200));
    // Development units sign their ticket with issuer "Root-CA00000004-XS00000009"
    // (27 bytes, NUL-terminated). Compare exactly 27 bytes: the earlier 0x2A
    // (42-byte) memcmp read past the string literal into adjacent memory and
    // could never match, so dev tickets were misrouted to the retail key path.
    bool devkit = (memcmp(tik + 0x140, "Root-CA00000004-XS00000009", 0x1B) == 0);
    Byte ckIdx = tik[0x1F1];
    _info.TicketId = GetBe64(tik + 0x9C);
    _info.DeviceId = GetBe32(tik + 0xA4);
    _info.TitleId = GetBe64(tik + 0xA8);
    _info.CommonKeyIdx = ckIdx;
    UInt16 hi = GetBe16(tik + 0x1DC);
    const Byte *ck;
    if (hi == 0x3)
      ck = C3dsKeys::Instance().Find("twl", false);
    else
    {
      char nm[16];
      // Development units use the dev common key set, which our key folder
      // stores under common%uN (the common0..5 files hold retail values).
      // Find() requires a lowercase-normalized name, hence the small 'n'.
      if (devkit)
        sprintf_s(nm, "common%un", (unsigned)ckIdx);
      else
        sprintf_s(nm, "common%u", (unsigned)ckIdx);
      ck = C3dsKeys::Instance().Find(nm, devkit);
    }
    if (ck)
    {
      Byte nk[16];
      bool nkOk = true;
      _titleKeyNewOk = false;
      if (devkit || hi == 0x3)
        memcpy(nk, ck, 16);   // dev & TWL: normalkey = common/twl key directly
      else
      {
        // retail: try Old3DS keyscrambler(slot0x3DKeyX, common) first,
        // then New3DS (commonN used directly as the normal key).
        const Byte *kx = C3dsKeys::Instance().Find("slot0x3dkeyx", false);
        if (kx)
          C3dsNormalKey(nk, kx, ck);
        else
          nkOk = false;       // retail requires slot0x3DKeyX for the Old3DS path
        char nmN[16];
        sprintf_s(nmN, "common%un", (unsigned)ckIdx);
        const Byte *ckN = C3dsKeys::Instance().Find(nmN, false);
        if (ckN)
        {
          Byte ivN[16];
          memset(ivN, 0, 16);
          memcpy(ivN, tik + 0x1DC, 8);
          __declspec(align(16)) Byte dataN[16];
          memcpy(dataN, tik + 0x1BF, 16);
          AesCbc_Block(ckN, ivN, dataN, 1);
          memcpy(_titleKeyNew, dataN, 16);
          _titleKeyNewOk = true;
        }
      }
      if (nkOk)
      {
        Byte iv[16];
        memset(iv, 0, 16);
        memcpy(iv, tik + 0x1DC, 8);
        __declspec(align(16)) Byte data[16];
        memcpy(data, tik + 0x1BF, 16);
        AesCbc_Block(nk, iv, data, 1);
        memcpy(_titleKey, data, 16);
        _titleKeyOk = true;
        memcpy(_info.TitleKey, data, 16);
        _info.HasTitleKey = true;
      }
      _cryptKeyPtr = _titleKeyOk ? _titleKey : NULL;
    }
  }

  // content region: a sequence of NCCH contents
  UInt64 contentPos = base + offsetContent;
  UInt64 contentEnd = contentPos + contentSize;

  UInt32 idx = 0;
  UInt64 p = contentPos;
  while (p + 0x200 <= contentEnd)
  {
    // find the TMD content chunk for this CIA content (match by chunk index)
    bool enc = false;
    UInt64 chunkSize = 0;
    Byte ctr[16];
    memset(ctr, 0, 16);
    if (tmdSize >= 0xB06)
    {
      Byte cc[2];
      RINOK(ReadAt(base + offsetTmd + 0x1DE, cc, 2));
      UInt16 contentCount = GetBe16(cc);
      if (_info.ContentCount == 0)
      {
        _info.ContentCount = contentCount;
        Byte tv[2];
        if (ReadAt(base + offsetTmd + 0xAC, tv, 2) == S_OK)
          _info.TmdTitleVersion = GetBe16(tv);
      }
      for (unsigned c = 0; c < contentCount && tmdSize >= 0xB04 + (UInt64)(c + 1) * 0x30; c++)
      {
        Byte ch[0x30];
        RINOK(ReadAt(base + offsetTmd + 0xB04 + (UInt64)c * 0x30, ch, 0x30));
        UInt16 ci = GetBe16(ch + 4);
        UInt16 ct = GetBe16(ch + 6);
        if (_info.Content0Id == 0 && ci == 0)
        {
          _info.Content0Id = GetBe32(ch + 0);
          _info.Content0Size = GetBe64(ch + 8);
        }
        if (ci == (UInt16)idx)
        {
          enc = ((ct & 1) != 0);
          ctr[0] = ch[4];
          ctr[1] = ch[5];
          chunkSize = GetBe64(ch + 8);
          break;
        }
      }
    }

    // decrypt the content header, trying the Old3DS key first, then New3DS
    const Byte *keyPtr = _titleKeyOk ? _titleKey : NULL;
    Byte h2[0x200];
    HRESULT hr2 = S_OK;
    bool gotNcch = false;
    for (unsigned attempt = 0; attempt < 2 && !gotNcch; attempt++)
    {
      _cryptActive = (enc && keyPtr);
      _cryptKeyPtr = keyPtr;
      _cryptStart = p;
      memcpy(_cryptCtr, ctr, 16);
      _cryptPos = p;   // CBC chain starts at content start (must equal _cryptStart)
      if (_cryptActive)
        AesCbc_Start(_cryptState, keyPtr, _cryptCtr);
      hr2 = ReadDec(p, h2, 0x200);
      _cryptActive = false;
      if (hr2 != S_OK)
        break;
      if (memcmp(h2 + 0x100, "NCCH", 4) == 0)
      { gotNcch = true; break; }
      if (enc && attempt == 0 && _titleKeyNewOk)
      { keyPtr = _titleKeyNew; continue; }   // fall back to the New3DS key
      break;
    }
    if (hr2 != S_OK)
      break;

    if (!gotNcch)
    {
      // no (or mismatched) key: expose the raw ciphertext as a single file
      UInt64 rawSize = chunkSize ? MY_ALIGN_200(chunkSize) : MY_ALIGN_200(0x200);
      if (p + rawSize > contentEnd)
        rawSize = contentEnd - p;
      UString name = UString(L"Content_") + NumToUString(idx) + UString(L".cxi");
      AddItem(name, p, rawSize, false, (enc && _titleKeyOk), p, ctr, (keyPtr == _titleKeyNew));
      p += rawSize;
      idx++;
      if (p >= contentEnd)
        break;
      continue;
    }

    UInt64 csize = (UInt64)GetUi32(h2 + 0x104) * kMediaUnit;
    if (csize == 0)
      break;
    csize = MY_ALIGN_200(csize);

    UString dirPrefix = UString(L"Content_") + NumToUString(idx) + UString(L"/");

    UInt32 before = _items.Size();
    HRESULT res2;
    if (enc)
    {
      if (keyPtr)
      {
        // decrypt the whole content region into memory for fast random access
        _decActive = false;
        _decStart = p;
        _decBuf.Alloc((size_t)csize);
        {
          AesCbc_Start(_cryptState, keyPtr, _cryptCtr);
          UInt64 rpos = p;
          size_t got = 0;
          Byte *outp = _decBuf;
          const size_t kChunk = (1 << 20);
          while (got < (size_t)csize)
          {
            size_t chunk = kChunk;
            if (chunk > (size_t)csize - got)
              chunk = (size_t)csize - got;
            if (_chunkBuf.Size() < kChunk)
              _chunkBuf.Alloc(kChunk);
            Byte *cb = _chunkBuf;
            RINOK(ReadAt(rpos, cb, chunk));
            for (size_t k = 0; k + 16 <= chunk; k += 16)
              AesCbc_Step(_cryptState, cb + k, 1);
            memcpy(outp + got, cb, chunk);
            got += chunk;
            rpos += chunk;
          }
          _decActive = true;
        }
        res2 = ParseNCCH(p, dirPrefix);
        _decActive = false;
        _decBuf.Free();
      }
      else
        res2 = S_FALSE;
      if (res2 != S_OK)
        res2 = S_FALSE;
    }
    else
      res2 = ParseNCCH(p, dirPrefix);   // plaintext content: expand directly

    if (res2 == S_FALSE || _items.Size() == before)
    {
      // encrypted (without usable key) or non-expandable content: expose as a single file
      UString name = UString(L"Content_") + NumToUString(idx) + UString(L".cxi");
      AddItem(name, p, csize, false, (enc && keyPtr), p, ctr, (keyPtr == _titleKeyNew));
    }
    else
    {
      // mark items created inside this encrypted content
      for (UInt32 i = before; i < _items.Size(); i++)
        if (enc && keyPtr)
        {
          _items[i].Encrypted = true;
          _items[i].UseNewKey = (keyPtr == _titleKeyNew);
          _items[i].CryptStart = p;
          memcpy(_items[i].CryptCtr, ctr, 16);
        }
    }

    p += csize;
    idx++;
    if (p >= contentEnd)
      break;
  }

  if (metaSize != 0)
    AddItem(UString(L"meta.bin"), base + offsetMeta, metaSize, false);

  return S_OK;
}

HRESULT CHandler::ParseNcsd(UInt64 base)
{
  
  Byte hdr[0x200];
  RINOK(ReadAt(base, hdr, 0x200));
  

  if (memcmp(hdr + 0x100, "NCSD", 4) != 0)
    return S_FALSE;

  // ---- fill archive technical info (Properties dialog) ----
  _info.Clear();
  _info.Container = 2;
  _info.MediaId = GetBe64(hdr + 0x108);

  // Partition table at 0x120: 8 × (u32 offset, u32 size), media units (0x200).
  for (unsigned i = 0; i < 8; i++)
  {
    UInt32 off = GetUi32(hdr + 0x120 + i * 8);
    UInt32 size = GetUi32(hdr + 0x124 + i * 8);
    if (off == 0 || size == 0)
      continue;
    _info.NumPartitions++;
    UInt64 partBase = base + (UInt64)off * kMediaUnit;
    UString prefix = UString(L"Partition_") + NumToUString(i) + UString(L"/");
    RINOK(ParseNCCH(partBase, prefix));
  }

  return S_OK;
}

// NAND open failure reporting. reason 0: no device material anywhere;
// reason 1: material present but MBR 0x55AA could not be decrypted (mismatch).
// GUI host (7zFM, no console window) shows a warning box; console host (7z.exe)
// just gets a failing HRESULT for the CLI to print. user32 is loaded dynamically
// so the dll does not take a link-time dependency on MessageBoxW.
static HRESULT ReportNandNoDevice(int reason)
{
  if (IsGuiHost())
  {
    HMODULE u32 = LoadLibraryW(L"user32.dll");
    if (u32)
    {
      typedef int (WINAPI *PFN_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);
#pragma warning(push)
#pragma warning(disable: 4191) // FARPROC -> MessageBoxW signature (verified by name)
      PFN_MessageBoxW pMB = reinterpret_cast<PFN_MessageBoxW>(GetProcAddress(u32, "MessageBoxW"));
#pragma warning(pop)
      if (pMB)
      {
        LPCWSTR msg;
        if (reason == 0)
          msg = L"No 3DS device key material was found.\n\n"
                L"Place boot9.bin, an OTP dump (otp.mem / otp_dec.mem) and nand_cid.mem "
                L"next to nand.bin, or register this console under keystone\\ctrdevice.";
        else if (reason == 2)
          msg = L"Device material next to nand.bin is incomplete.\n\n"
                L"boot9.bin, an OTP dump (otp.mem / otp_dec.mem) and nand_cid.mem "
                L"are all required in the same folder, or register this console "
                L"under keystone\\ctrdevice.";
        else if (reason == 3)
          msg = L"Opening was cancelled.";
        else if (reason == 4)
          msg = L"Bare device material needs -unit retail|dev on the command line "
                L"(this console host cannot show the prompt).";
        else if (reason == 5)
          msg = L"Invalid device parameter. Use -unit retail|dev, -type ctr|snake, "
                L"-slot 4|5.";
        else
          msg = L"The available device material does not match this nand.bin "
                L"(CTRNAND MBR signature could not be decrypted).\n\n"
                L"Check that boot9.bin, OTP and nand_cid.mem belong to the same console.";
        UINT icon = (reason == 3) ? MB_OK | MB_ICONINFORMATION : (MB_OK | MB_ICONWARNING);
        pMB(NULL, msg, L"7-Zip CTR", icon);
      }
    }
  }
  return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
}

// Decrypt CTRNAND sector0 MBR per device/slot and return the device whose 0x55AA
// signature checks out. Honors CDeviceNand::SlotWanted (user-picked Old/New lock).
static const CDeviceNand *TryMatchDevices(const CObjectVector<CDeviceNand> &devs,
    const Byte *ctMbr, UInt64 ctrNandStart)
{
  for (unsigned di = 0; di < devs.Size(); di++)
  {
    const CDeviceNand &dv = devs[di];
    for (int trySlot = 4; trySlot <= 5; trySlot++)
    {
      if (!dv.HasSlot[trySlot])
        continue;
      if (dv.SlotWanted >= 0 && trySlot != dv.SlotWanted)
        continue;
      Byte work[0x200];
      memcpy(work, ctMbr, 0x200);
      AesCtr_Decode3ds(dv.Nk[trySlot], dv.Nonce, ctrNandStart, work, 0x200);
      if (work[0x1FE] == 0x55 && work[0x1FF] == 0xAA)
        return &dv;
    }
  }
  return NULL;
}

// NAND backup image (sysnand/nand.bin): NCSD partition table of encrypted
// system regions. Console-unique normalkeys are derived from keystone\ctrdevice
// archives (boot9 + otp + nand_cid); the matching device is found by decrypting
// the CTRNAND sector0 MBR and checking the 0x55AA signature. Each decrypted
// region becomes a virtual partition image streamed with AES-CTR on extract.
HRESULT CHandler::ParseNandNcsd(UInt64 base)
{
  
  Byte hdr[0x200];
  RINOK(ReadAt(base, hdr, 0x200));
  

  // Registered devices from keystone\ctrdevice are tried first; only when none
  // matches do we fall back to bare material beside nand.bin (which needs an
  // explicit unit/model via -unit/-type on the CLI or the GUI prompt).
  const CObjectVector<CDeviceNand> &baseDevs = CtrDevices();

  // CTRNAND region starts at 0xB930000 on both Old/New 3DS (slot0x04 Old,
  // slot0x05 New). Read the ciphertext sector once, retry per device/slot.
  const UInt64 kCtrNandStart = 0xB930000;
  Byte ctMbr[0x200];
  if (ReadAt(kCtrNandStart, ctMbr, 0x200) != S_OK)
    return S_FALSE;

  const CDeviceNand *match = TryMatchDevices(baseDevs, ctMbr, kCtrNandStart);

  // Bare-material fallback beside nand.bin, only when no registered device matched.
  CObjectVector<CDeviceNand> bareDevs;
  if (!match && !_srcDir.IsEmpty())
  {
    int st = ResolveBareProfile(_srcDir);
    if (st == kBareCancel)
      return ReportNandNoDevice(3);
    if (st == kBareMissing)
      return ReportNandNoDevice(2);
    if (st == kBareNeedParam)
      return ReportNandNoDevice(4);
    if (st == kBareBadParam)
      return ReportNandNoDevice(5);
    LoadCtrDevice(_srcDir, bareDevs);
    if (bareDevs.IsEmpty())
      return ReportNandNoDevice(2);
    match = TryMatchDevices(bareDevs, ctMbr, kCtrNandStart);
  }

  if (!match)
  {
    if (baseDevs.IsEmpty() && bareDevs.IsEmpty() && _srcDir.IsEmpty())
      return ReportNandNoDevice(0);  // no device material found anywhere
    return ReportNandNoDevice(1);    // material present, but does not decrypt this nand.bin
  }
  

  _info.Clear();
  _info.Container = 2;
  _info.MediaId = GetBe64(hdr + 0x108);

  for (unsigned i = 0; i < 8; i++)
  {
    UInt32 offSec = GetUi32(hdr + 0x120 + i * 8);
    UInt32 szSec  = GetUi32(hdr + 0x124 + i * 8);
    // A blank partition has BOTH offset and size zero; TWL part0 legitimately
    // sits at offset 0, so skipping on offSec==0 alone would drop it.
    if (offSec == 0 && szSec == 0)
      continue;
    Byte ft = hdr[0x110 + i];
    Byte ct = hdr[0x118 + i];

    bool isTwl = (ct == 1);
    bool twlReady = false;
    unsigned slot = 0;
    const char *role = "";
    if (isTwl)
    {
      role = "TWL";
      // TWL key unavailable (e.g. dev with only a plaintext otp_dec, no
      // encrypted OTP): still list the partition raw, flag it in Properties.
      twlReady = match->HasTwl;
      if (!twlReady)
        _info.TwlFailed = true;
    }
    else if (ct == 2)
    {
      if (ft == 4)            { slot = 7; role = "AGB_Save"; }
      else if (ft == 3)       { slot = 6; role = (i == 2) ? "Firm0" : "Firm1"; }
      else if (ft == 1 && (UInt64)offSec * kMediaUnit > 0xB00000)
                              { slot = 4; role = "CTRNAND"; }
    }
    else if (ct == 3)
    {
      slot = 5; role = "CTRNAND";
    }

    if (!isTwl && (slot == 0 || !match->HasSlot[slot]))
      continue;   // unknown or unsupported slot: list nothing

    _info.NumPartitions++;
    UInt64 absOff = base + (UInt64)offSec * kMediaUnit;
    UInt64 absSz  = (UInt64)szSec * kMediaUnit;
    const Byte *useKey = NULL;
    const Byte *useCtr = NULL;
    if (isTwl)
    {
      if (twlReady) { useKey = match->TwlNk; useCtr = match->TwlNonce; }
    }
    else
    {
      useKey = match->Nk[slot];
      useCtr = match->Nonce;
    }
    char nm[64];
    snprintf(nm, sizeof(nm), "Partition_%u_%s.bin", i, role);
    AddItem(UString(nm), absOff, absSz, false,
        false, 0, NULL, false,
        useKey, useCtr, absOff, absOff);
    CItem &it = _items[_items.Size() - 1];
    if (isTwl && twlReady)
      it.StreamTwl = true;
    else if (!isTwl)
      it.StreamCtr = true;

  }

  
  return _items.IsEmpty() ? S_FALSE : S_OK;
}

// Standalone Contents.cnt (SNAKE update container): "CONT" header followed by
// 256 (offset, offset_end) u32 pairs at 0xC00. Each valid entry points to a
// plaintext CIA payload; list them under a dedicated Contents/ subfolder.
// (The sibling CupList that carries title ids is unavailable to a standalone
// stream, so entries are numbered; the downstream CIA handler still decrypts.)
HRESULT CHandler::ParseCntStandalone(UInt64 base)
{
  Byte hb[0x1400];
  RINOK(ReadAt(base, hb, sizeof(hb)));
  if (memcmp(hb, "CONT", 4) != 0)
    return S_FALSE;

  _info.Clear();

  unsigned seq = 0;
  for (unsigned i = 0; i < 256; i++)
  {
    UInt32 eOff = GetUi32(hb + 0xC00 + i * 8);
    UInt32 eEnd = GetUi32(hb + 0xC00 + i * 8 + 4);
    if (eOff == 0 || eEnd <= eOff || eEnd == 0xFFFFFFFF)
      continue;
    UInt64 cOff = base + 0xC00 + (UInt64)eOff;
    UInt64 cSize = (UInt64)eEnd - eOff;
    // verify a plaintext CIA header (size_header == 0x2020); skip encrypted or
    // padding entries whose first bytes are not the CIA magic
    Byte ch[4];
    if (ReadAt(cOff, ch, 4) != S_OK || GetUi32(ch) != 0x2020)
      continue;
    // Locate the ticket segment from the CIA header, then read the plaintext
    // title id at ticket+0x1DC (1:1 with the CupList index) so items can be
    // named <titleid>.cia without reading the sibling CupList file.
    Byte ciaHdr[0x20];
    UInt64 tid = 0;
    if (ReadAt(cOff, ciaHdr, 0x20) == S_OK)
    {
      UInt32 hdrSize  = GetUi32(ciaHdr + 0x00);
      UInt32 certSize = GetUi32(ciaHdr + 0x08);
      UInt64 offCert   = ((UInt64)hdrSize  + 63) & ~(UInt64)63;
      UInt64 offTik   = offCert + (((UInt64)certSize + 63) & ~(UInt64)63);
      Byte tidRaw[8];
      if (ReadAt(cOff + offTik + 0x1DC, tidRaw, 8) == S_OK)
        tid = GetBe64(tidRaw);
    }
    UString nm;
    if (tid != 0)
      nm = UString(L"Contents/") + HexUInt64Padded(tid) + UString(L".cia");
    else
    {
      char name[48];
      snprintf(name, sizeof(name), "Contents/entry_%03u.cia", seq++);
      nm = UString(name);
    }
    AddItem(nm, cOff, cSize, false);
  }
  return S_OK;
}

// ----------------------------------------------------------------
// CDN TMD (title metadata, NUS): a standalone tmd.<n> file paired with a
// folder of index-named encrypted contents (00000000, 00000001, ...).
//
// A CDN content is AES-CBC encrypted with the per-title TitleKey, which can
// only be recovered from a ticket (.tik/.cetk) via the common key. This pack
// carries a TMD only (no ticket), so the ciphertext contents cannot be
// decrypted here; this parser lists the TMD's content records as metadata-only
// placeholders and exposes title info in the archive properties.
//
// FUTVE ticket hook (not wired yet, single-stream handler cannot reach the
// sibling folder): when a <titleid>.tik/.cetk sits next to the TMD, decrypt the
// TitleKey with the common key, AES-CBC-decrypt each content (IV = big-endian
// titleId / content-id padded), then hand the plaintext NCCH to ParseNCCH.
//
// TMD layout (all big-endian), signature data size Y depends on sig type@0:
//   0x010003 RSA4096 SHA256 -> Y = 4 + 0x200 + 0x3C = 0x240
//   0x010004 RSA2048 SHA256 -> Y = 4 + 0x100 + 0x3C = 0x140
//   0x010005 ECDSA  SHA256  -> Y = 4 + 0x3C  + 0x40 = 0x80
// Header @ Y: issuer[0x40], TitleId@+0x4C(u64), TitleType@+0x54(u32),
//   GroupId@+0x58(u16), TitleVersion@+0x9C(u16), ContentCount@+0x9E(u16).
// Chunk records @ Y+0x9C4, each 0x30: contentId(u32) index(u16) type(u16)
//   size(u64) SHA256(0x20).
// ----------------------------------------------------------------
static UInt32 TmdSigY(UInt32 sigType)
{
  switch (sigType)
  {
    case 0x010003: return 0x240;
    case 0x010005: return 0x80;
    default:       return 0x140;   // 0x010004 RSA2048 SHA256
  }
}

HRESULT CHandler::ParseTmd(UInt64 base)
{
  Byte hdr[0x200];
  RINOK(ReadAt(base, hdr, sizeof(hdr)));

  UInt32 sigType = GetBe32(hdr + 0x00);
  if (sigType != 0x010003 && sigType != 0x010004 && sigType != 0x010005)
    return S_FALSE;
  UInt32 Y = TmdSigY(sigType);
  if (Y + 0xA0 > sizeof(hdr))
    return S_FALSE;
  // issuer must start with "Root-"
  if (memcmp(hdr + Y, "Root-", 5) != 0)
    return S_FALSE;

  _info.Clear();
  _info.Container = 4;
  memcpy(_info.Issuer, hdr + Y, 0x40);
  _info.Issuer[0x40] = 0;
  // strip trailing NULs already handled by fixed buffer; trim at first NUL
  for (int i = 0; i < 0x40; i++)
    if (_info.Issuer[i] == 0) { _info.Issuer[i] = 0; break; }

  _info.TitleId        = GetBe64(hdr + Y + 0x4C);
  _info.TmdTitleType   = GetBe32(hdr + Y + 0x54);
  _info.TmdGroupId     = GetBe16(hdr + Y + 0x58);
  _info.TmdTitleVersion= GetBe16(hdr + Y + 0x9C);
  _info.ContentCount   = GetBe16(hdr + Y + 0x9E);

  // Note: no manual "Contents/" directory entry here; the GUI builds the
  // folder tree automatically from the leaf paths below (same as ExeFS/RomFS).

  UInt64 recBase = base + Y + 0x9C4;
  for (UInt16 c = 0; c < _info.ContentCount; c++)
  {
    Byte rec[0x30];
    if (ReadAt(recBase + (UInt64)c * 0x30, rec, 0x30) != S_OK)
      break;
    UInt32 cid   = GetBe32(rec + 0x00);
    UInt16 idx   = GetBe16(rec + 0x04);
    UInt16 ctype = GetBe16(rec + 0x06);
    UInt64 csize = GetBe64(rec + 0x08);

    // Metadata-only placeholder: use a non-registered extension (.content) so
    // the GUI does not try to re-open it as a 3DS container. The on-disk CDN
    // content cannot be decrypted without a ticket, so there are no embedded
    // bytes here.
    char name[64];
    snprintf(name, sizeof(name), "Contents/%08x.content", (unsigned)idx);
    AddItem(UString(name), recBase + (UInt64)c * 0x30, csize, false);
    CItem &it = _items.Back();
    it.Virtual = true;
    // type flags: 1=Encrypted, 0x4000=Optional, 0x8000=Shared
    (void)cid; (void)ctype;
  }
  return S_OK;
}

// ----------------------------------------------------------------
HRESULT CHandler::Open2(IInStream *)
{
  
  // ensure external keys (keystone\ctraes_retail / ctraes_dev, or keystone.ini
  // custom folders next to 7z.dll) are loaded
  C3dsKeys::Instance().EnsureLoaded();
  

  Byte hdr[0x200];
  HRESULT res = ReadAt(0, hdr, 0x200);
  
  if (res != S_OK || res == S_FALSE)
    return S_FALSE;

  // Standalone Contents.cnt (SNAKE update container): magic "CONT" at offset 0
  if (memcmp(hdr, "CONT", 4) == 0)
  {  return ParseCntStandalone(0); }

  // CIA: header size field == 0x2020
  if (GetUi32(hdr) == 0x2020)
  {  return ParseCia(0); }

  // NCCH / NCSD magic lives at 0x100
  if (memcmp(hdr + 0x100, "NCCH", 4) == 0)
  {  return ParseNCCH(0, UString()); }
  if (memcmp(hdr + 0x100, "NCSD", 4) == 0)
  {
    
    // NAND backup layout: partition0 is the TWL region (fstype=1, crypttype=1)
    // at offset 0; game-cartridge NCSD never carries this partition table.
    if (hdr[0x110] == 1 && hdr[0x118] == 1 &&
        GetUi32(hdr + 0x120) == 0 && GetUi32(hdr + 0x124) != 0)
    {
      
      return ParseNandNcsd(0);
    }
    
    return ParseNcsd(0);
  }

  // CDN TMD (standalone tmd.<n>): RSA sig type @0, "Root-" issuer at Y
  {
    UInt32 st = GetBe32(hdr);
    if (st == 0x010003 || st == 0x010004 || st == 0x010005)
    {
      UInt32 Y = TmdSigY(st);
      if (Y + 0x40 <= 0x200 && memcmp(hdr + Y, "Root-", 5) == 0)
        return ParseTmd(0);
    }
  }

  // Standalone FIRM (.firm: NATIVE/SAFE_MODE/TWL/AGB/homebrew): magic 'FIRM' @0.
  if (memcmp(hdr, "FIRM", 4) == 0)
  {
    _info.Clear();
    return ParseFirm(0);
  }

  // Standalone plaintext RomFS (romfs.bin / .romfs): IVFC magic @0.
  // No outer NCCH layer here, so parse as plaintext (inner=false, no keys).
  if (memcmp(hdr, "IVFC", 4) == 0)
  {
    _info.Clear();
    _info.Container = 5;
    return ParseRomFS(0, UString(), NULL, NULL, false);
  }

  // Standalone plaintext ExeFS (exefs.bin): no magic; validate the 10 entries.
  if (ValidExeFsHdr(hdr))
  {
    _info.Clear();
    _info.Container = 6;
    return ParseExeFS(0, UString(), NULL, NULL, NULL, false);
  }

  return S_FALSE;
}

Z7_COM7F_IMF(CHandler::Open(IInStream *stream, const UInt64 *, IArchiveOpenCallback *))
{
  COM_TRY_BEGIN
  Close();
  _stream = stream;
  // 7-Zip CTR: capture the source file's directory so per-device key material
  // sitting next to nand.bin can be used when keystone\ctrdevice has no match.
  _srcDir.Empty();
  // The opened stream cannot expose its own path (the core wraps it and the
  // IStreamGetProp returned is an empty shell), so the UI host publishes the
  // absolute path through a per-process environment variable before calling
  // Open. exe and dll share the process environment, so this reaches us here.
  {
    wchar_t envPath[2048];
    DWORD envN = GetEnvironmentVariableW(L"Z7CTR_SRC_PATH", envPath, 2048);
    if (envN > 0 && envN < 2048)
    {
      UString full = envPath;
      int sl = full.ReverseFind(L'\\');
      if (sl > 0)
        _srcDir = full.Left((unsigned)sl);
    }
  }
  RINOK(Open2(stream));
  // If a CIA exposed only its metadata (cert/ticket/tmd) on the first pass,
  // force a full re-parse so encrypted contents expand too.
  if (_items.Size() > 0 && _items.Size() <= 3 && _items[0].Path == UString(L"cert.bin"))
  {
    _items.Clear();
    RINOK(Open2(stream));
  }
  if (_items.Size() == 0)
    return S_FALSE;
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Close())
{
  _stream.Release();
  _items.Clear();
  _srcDir.Empty();
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream **stream))
{
  COM_TRY_BEGIN
  *stream = NULL;
  if (index >= _items.Size())
    return S_FALSE;
  const CItem &it = _items[index];
  // Only NAND partitions (CTR bulk / TWL) provide a live decrypting stream.
  // Every other item falls back to the standard extract-to-temp path.
  if (!it.StreamCtr && !it.StreamTwl)
    return S_FALSE;
  // Create through the derived type to call Init, then hold through the base
  // interface so release calls the public virtual IUnknown::Release (the class's
  // own AddRef/Release are CMyUnknownImp-private).
  CDecryptNandStream *raw = new CDecryptNandStream;
  RINOK(raw->Init(_stream, it.Offset, it.Size, it.InnerKey, it.InnerCtr, it.StreamTwl));
  CMyComPtr<ISequentialInStream> s;
  s.Attach(raw);
  *stream = s.Detach();
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::GetNumberOfItems(UInt32 *numItems))
{
  *numItems = _items.Size();
  return S_OK;
}

Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *value))
{
  COM_TRY_BEGIN
  if (index >= _items.Size())
    return E_INVALIDARG;
  NWindows::NCOM::CPropVariant prop;
  const CItem &item = _items[index];
  switch (propID)
  {
    case kpidPath: prop = item.Path; break;
    case kpidIsDir: prop = item.IsDir; break;
    case kpidSize:
    case kpidPackSize:
      if (!item.IsDir)
        prop = item.Size;
      break;
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
{
  COM_TRY_BEGIN
  NWindows::NCOM::CPropVariant prop;
  switch (propID)
  {
    case kpidFileSystem: prop = "N3DS"; break;
    case kpidExtension: prop = "3ds"; break;
    case kpidComment:
      {
        if (_info.IsTmd())
        {
          UString s = UString(L"TMD issuer: ");
          s += ReadAscii((const Byte *)_info.Issuer, 0x40);
          s += UString(L"; contents are TitleKey-AES-CBC encrypted, a ticket (.tik/.cetk) is required to decrypt");
          prop = s;
          break;
        }
        UString note;
        if (_info.TwlFailed)
          note = UString(L"TWL decryption failed: encrypted OTP dump (otp.mem/otp.bin) needed for the dev TWL key; TWL partition is listed raw.");
        C3dsKeys &k = C3dsKeys::Instance();
        k.EnsureLoaded();
        if (k.Retail() != 0 || k.Dev() != 0)
        {
          UString s = UString(L"3DS keys: retail=");
          s += NumToUString(k.Retail());
          s += UString(L", dev=");
          s += NumToUString(k.Dev());
          if (!note.IsEmpty()) { note += UString(L"; "); note += s; }
          else note = s;
        }
        if (!note.IsEmpty())
          prop = note;
        break;
      }

    // ---- technical info (mirrors ctrtool output) ----
    case kpidN3dsContainer:
      if (_info.IsCia()) prop = "CIA";
      else if (_info.IsNcsd()) prop = "NCSD";
      else if (_info.IsNcch()) prop = "NCCH";
      else if (_info.IsTmd()) prop = "TMD (CDN)";
      else if (_info.IsRomfs()) prop = "RomFS (plaintext)";
      else if (_info.IsExefs()) prop = "ExeFS (plaintext)";
      else if (_info.IsFirm()) prop = "FIRM";
      break;
    case kpidN3dsMediaId:
      if (_info.IsNcsd()) prop = HexUInt64(_info.MediaId);
      break;
    case kpidN3dsTitleId:
      if (_info.IsCia()) prop = HexUInt64(_info.TitleId);
      else if (_info.IsNcch()) prop = HexUInt64(_info.NcchTitleId);
      else if (_info.IsTmd()) prop = HexUInt64(_info.TitleId);
      break;
    case kpidN3dsProgramId:
      if (_info.IsNcch()) prop = HexUInt64(_info.ProgramId);
      break;
    case kpidN3dsTitleVer:
      {
        UInt16 v = 0;
        if (_info.IsCia() || _info.IsTmd()) v = _info.TmdTitleVersion;
        else if (_info.IsNcch()) v = _info.NcchVersion;
        if (v != 0) { UString s = UString(L"v"); s += NumToUString(v); prop = s; }
        break;
      }
    case kpidN3dsMakerCode:
      if (_info.IsNcch())
      {
        char m[3]; m[0] = (char)(_info.MakerCode >> 8); m[1] = (char)(_info.MakerCode & 0xFF); m[2] = 0;
        prop = UString(m);
      }
      break;
    case kpidN3dsProductCode:
      if (_info.IsNcch()) prop = ReadAscii((const Byte *)_info.ProductCode, 0x10);
      break;
    case kpidN3dsCommonKey:
      if (_info.IsCia()) { UString s = UString(L"0x"); s += HexUInt32(_info.CommonKeyIdx); prop = s; }
      break;
    case kpidN3dsContentCount:
      if (_info.IsCia() || _info.IsTmd()) prop = (UInt32)_info.ContentCount;
      break;
    case kpidN3dsPartitions:
      if (_info.IsNcsd()) prop = (UInt32)_info.NumPartitions;
      break;
    case kpidN3dsCiaType:
      if (_info.IsCia()) { UString s = UString(L"0x"); s += HexUInt32(_info.CiaType); prop = s; }
      break;
    case kpidN3dsCiaVersion:
      if (_info.IsCia()) { UString s = UString(L"0x"); s += HexUInt32(_info.CiaVersion); prop = s; }
      break;
    case kpidN3dsTicketId:
      if (_info.IsCia()) prop = HexUInt64(_info.TicketId);
      break;
    case kpidN3dsDeviceId:
      if (_info.IsCia()) { UString s = UString(L"0x"); s += HexUInt32(_info.DeviceId); prop = s; }
      break;
    case kpidN3dsTitleKey:
      if (_info.HasTitleKey) prop = BytesToHex(_info.TitleKey, 16);
      break;
    case kpidN3dsExefs:
      if (_info.IsNcch())
      {
        UString s = UString(L"off=0x"); s += HexUInt64(_info.ExeFsOff);
        s += UString(L" size=0x"); s += HexUInt64(_info.ExeFsSize);
        prop = s;
      }
      break;
    case kpidN3dsRomfs:
      if (_info.IsNcch())
      {
        UString s = UString(L"off=0x"); s += HexUInt64(_info.RomFsOff);
        s += UString(L" size=0x"); s += HexUInt64(_info.RomFsSize);
        prop = s;
      }
      break;
    case kpidN3dsCrypto:
      if (_info.IsNcch())
      {
        static const wchar_t *kCrypto[] = { L"None", L"Fixed", L"Secure", L"Secure (KeyY seeded)" };
        prop = kCrypto[_info.Crypto <= 3 ? _info.Crypto : 2];
      }
      break;
    case kpidN3dsContent0:
      if (_info.IsCia())
      {
        UString s = UString(L"id=0x"); s += HexUInt32(_info.Content0Id);
        s += UString(L" size=0x"); s += HexUInt64(_info.Content0Size);
        prop = s;
      }
      break;

    case kpidN3dsFirmSig:
      if (_info.IsFirm())
      {
        UString s;
        switch (_info.FirmSigState)
        {
          case 1: s = UString(L"Valid (official signature)"); break;
          case 2: s = UString(L"Sighax / homebrew signature"); break;
          case 3: s = UString(L"Corrupt / missing signature"); break;
          default: s = UString(L"Not verified (no public key loaded)"); break;
        }
        s += UString(L"; sections ");
        s += NumToUString((UInt32)_info.FirmSectionsOk);
        s += UString(L"/");
        s += NumToUString((UInt32)_info.FirmSectionsTotal);
        s += UString(L" SHA-256 ok");
        prop = s;
      }
      break;
    case kpidN3dsFirmKind:
      if (_info.IsFirm() && _info.FirmKind[0])
        prop = ReadAscii((const Byte *)_info.FirmKind, sizeof(_info.FirmKind) - 1);
      break;
    case kpidN3dsFirmEntry:
      if (_info.IsFirm())
      {
        UString s = UString(L"ARM11=0x"); s += HexUInt64(_info.FirmArm11Entry);
        s += UString(L" ARM9=0x"); s += HexUInt64(_info.FirmArm9Entry);
        prop = s;
      }
      break;
  }
  prop.Detach(value);
  return S_OK;
  COM_TRY_END
}

Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
    Int32 testMode, IArchiveExtractCallback *extractCallback))
{
  COM_TRY_BEGIN
  // Respect the caller's index selection (7zFM copy/extract of selected items).
  // A previous "extract everything" hack here made copying a single nested file
  // decompress the whole archive (very slow / appeared to hang).
  const bool allFilesMode = false;
  UInt32 numReal = numItems;
  if (allFilesMode)
    numReal = _items.Size();

  UInt64 totalSize = 0;
  UInt32 i;
  for (i = 0; i < numReal; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    if (index >= _items.Size())
      continue;
    const CItem &item = _items[index];
    if (!item.IsDir && !item.Virtual)
      totalSize += item.Size;
  }

  RINOK(extractCallback->SetTotal(totalSize));

  CByteBuffer buf;
  const size_t kBufSize = (size_t)1 << 16;
  buf.Alloc(kBufSize);

  // Pre-scan: per encrypted content, the absolute end of its last item
  // (used to decrypt each whole content once into _decBuf for fast extract).
  struct CExtContent { UInt64 start; bool useNew; Byte ctr[16]; UInt64 end; };
  CRecordVector<CExtContent> extContents;
  {
    for (i = 0; i < _items.Size(); i++)
    {
      const CItem &it = _items[i];
      if (!it.Encrypted || it.Size == 0)
        continue;
      bool found = false;
      for (unsigned c = 0; c < extContents.Size(); c++)
      {
        CExtContent &ec = extContents[c];
        if (ec.start == it.CryptStart && ec.useNew == it.UseNewKey && memcmp(ec.ctr, it.CryptCtr, 16) == 0)
        {
          UInt64 e = it.Offset + it.Size;
          if (e > ec.end) ec.end = e;
          found = true;
          break;
        }
      }
      if (!found)
      {
        CExtContent ec;
        ec.start = it.CryptStart;
        ec.useNew = it.UseNewKey;
        memcpy(ec.ctr, it.CryptCtr, 16);
        ec.end = it.Offset + it.Size;
        extContents.Add(ec);
      }
    }
  }

  UInt64 curPos = 0;
  for (i = 0; i < numReal; i++)
  {
    const UInt32 index = allFilesMode ? i : indices[i];
    if (index >= _items.Size())
    {
      RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kDataError));
      continue;
    }
    const CItem &item = _items[index];

    // Metadata-only CDN TMD content placeholder: no embedded bytes, nothing to
    // write out (the real ciphertext lives in the sibling index-named file).
    if (item.Virtual)
    {
      RINOK(extractCallback->PrepareOperation(NArchive::NExtract::NOperationResult::kOK));
      RINOK(extractCallback->SetCompleted(&curPos));
      RINOK(extractCallback->SetOperationResult(NArchive::NExtract::NOperationResult::kOK));
      continue;
    }

    Int32 opRes = NArchive::NExtract::NOperationResult::kOK;
    CMyComPtr<ISequentialOutStream> outStream;
    RINOK(extractCallback->GetStream(index, &outStream,
        testMode ? NArchive::NExtract::NAskMode::kTest : NArchive::NExtract::NAskMode::kExtract));

    if (!item.IsDir && (outStream || testMode))
    {

      if (!testMode)
      {
        if (item.StreamCtr || item.StreamTwl)
        {

          // NAND partition: bulk sequential AES-CTR; the counter runs on the
          // absolute whole-card offset (nonce = SHA256(nand_cid)[:16]). One
          // 1 MB chunk per round; report progress per chunk (the per-16-byte
          // inner branch would seek/reset-key 70M+ times and stall at 0%).
          const size_t kChunk = (size_t)1 << 20;
          UInt64 done = 0;
          UInt64 reported = 0;
          while (done < item.Size)
          {
            size_t want = kChunk;
            if (want > (size_t)(item.Size - done))
              want = (size_t)(item.Size - done);
            if (_chunkBuf.Size() < kChunk)
              _chunkBuf.Alloc(kChunk);
            Byte *cb = _chunkBuf;
            HRESULT hrS = Seek(item.Offset + done);
            if (done == 0) 
            RINOK(hrS);
            HRESULT hrR = ReadF(cb, want);
            if (done == 0) 
            RINOK(hrR);
            // counter base = absolute offset of this chunk; the decoder adds
            // offBytes/16 to the nonce.
            if (item.StreamTwl)
            {
              // TWL (slot0x03) region: everything before 0x12E00 is plaintext
              // (NCSD header), EXCEPT the MBR table at [0x1BE, 0x200) which is
              // encrypted; only from 0x12E00 onward (twln/twlp FAT volumes) the
              // DSi block-reversal AES-CTR applies. Decrypting the plaintext
              // header would corrupt it, so leave raw bytes untouched and only
              // decode the MBR subrange and the ciphertext tail.
              const UInt64 kTwlPlainEnd = 0x12E00;
              const UInt64 kMbrLo = 0x1BE, kMbrHi = 0x200;
              UInt64 segAbs = item.Offset + done;
              size_t p = 0;
              while (p < want)
              {
                UInt64 a = segAbs + p;
                size_t avail = want - p;
                if (a < kTwlPlainEnd)
                {
                  // plaintext region: raw bytes already hold the plaintext; only
                  // decrypt the overlapping MBR partition table subrange.
                  if (a < kMbrHi && a + avail > kMbrLo)
                  {
                    UInt64 s = (a > kMbrLo) ? a : kMbrLo;
                    UInt64 e = (a + avail < kMbrHi) ? a + avail : kMbrHi;
                    Byte mbr[0x42];
                    AesCtr_DecodeTwl(item.InnerKey, item.InnerCtr,
                        s, mbr, (size_t)(e - s));
                    memcpy(cb + p + (size_t)(s - a), mbr, (size_t)(e - s));
                  }
                  size_t step = (size_t)(kTwlPlainEnd - a);
                  if (step > avail) step = avail;
                  p += step;
                }
                else
                {
                  AesCtr_DecodeTwl(item.InnerKey, item.InnerCtr, a, cb + p, avail);
                  p += avail;
                }
              }
            }
            else
              AesCtr_Decode3ds(item.InnerKey, item.InnerCtr,
                  item.Offset + done, cb, want);
            HRESULT hrW = WriteStream(outStream, cb, want);
            if (done == 0) 
            RINOK(hrW);
            done += want;
            reported += want;
            RINOK(extractCallback->SetCompleted(&reported));
          }
          
        }
        else if (item.Encrypted && _titleKeyOk)
        {
          // Decrypt the whole content once into _decBuf, then emit [Offset, Offset+Size)
          // with the inner AES-CTR layer applied per 16-byte block.
          CExtContent *ec = NULL;
          for (unsigned c = 0; c < extContents.Size(); c++)
            if (extContents[c].start == item.CryptStart && extContents[c].useNew == item.UseNewKey &&
                memcmp(extContents[c].ctr, item.CryptCtr, 16) == 0)
            { ec = &extContents[c]; break; }
          if (ec && (!_decActive || _decStart != item.CryptStart || _decUseNew != item.UseNewKey ||
              memcmp(_decCtr, item.CryptCtr, 16) != 0))
          {
            _decActive = false;
            _decStart = item.CryptStart;
            _decUseNew = item.UseNewKey;
            memcpy(_decCtr, item.CryptCtr, 16);
            const Byte *xk = item.UseNewKey ? _titleKeyNew : _titleKey;
            UInt64 csize = ec->end - item.CryptStart;
            _decBuf.Alloc((size_t)csize);
            AesCbc_Start(_cryptState, xk, item.CryptCtr);
            UInt64 rpos = item.CryptStart;
            size_t got = 0;
            Byte *outp = _decBuf;
            const size_t kChunk = (1 << 20);
            while (got < (size_t)csize)
            {
              size_t chunk = kChunk;
              if (chunk > (size_t)csize - got)
                chunk = (size_t)csize - got;
              if (_chunkBuf.Size() < kChunk)
                _chunkBuf.Alloc(kChunk);
              Byte *cb = _chunkBuf;
              RINOK(Seek(rpos));
              RINOK(ReadF(cb, chunk));
              for (size_t k = 0; k + 16 <= chunk; k += 16)
                AesCbc_Step(_cryptState, cb + k, 1);
              memcpy(outp + got, cb, chunk);
              got += chunk;
              rpos += chunk;
            }
            _decActive = true;
          }
          if (_decActive && _decStart == item.CryptStart)
          {
            Byte *p0 = _decBuf + (size_t)(item.Offset - _decStart);
            if (item.HasInnerKey)
            {
              // Counter advances from the file's byte offset relative to its data
              // region (ExeFS/RomFS) start: (item.Offset - item.InnerBase), plus k.
              // (InnerOff is currently unused for this branch.)
              for (UInt64 k = 0; k < item.Size; k += 16)
              {
                UInt64 off = (item.Offset - item.InnerBase) + k;
                AesCtr_Decode3ds(item.InnerKey, item.InnerCtr, off, p0 + (size_t)k, AES_BLOCK_SIZE);
              }
            }
            RINOK(WriteStream(outStream, p0, (size_t)item.Size));
          }
          else
          {
            opRes = NArchive::NExtract::NOperationResult::kDataError;
          }
        }
        else if (item.HasInnerKey)
        {
          
          // no outer layer (standalone .cxi): read raw blocks and apply inner AES-CTR
          UInt64 end = item.Offset + item.Size;
          UInt64 emit = item.Offset;
          while (emit < end)
          {
            UInt64 alignedStart = emit & ~(UInt64)15;
            __declspec(align(16)) Byte cb[AES_BLOCK_SIZE];
            RINOK(Seek(alignedStart));
            RINOK(ReadF(cb, AES_BLOCK_SIZE));
            AesCtr_Decode3ds(item.InnerKey, item.InnerCtr,
                item.InnerOff + (alignedStart - item.InnerBase), cb, AES_BLOCK_SIZE);
            UInt64 take = (alignedStart + 16) - emit;
            if (take > end - emit)
              take = end - emit;
            RINOK(WriteStream(outStream, cb + (emit - alignedStart), (size_t)take));
            emit += take;
          }
        }
        else
        {
          
          RINOK(Seek(item.Offset));
          UInt64 remain = item.Size;
          while (remain > 0)
          {
            UInt64 want = remain;
            if (want > (UInt64)kBufSize)
              want = (UInt64)kBufSize;
            RINOK(ReadF(buf, (size_t)want));
            RINOK(WriteStream(outStream, buf, (size_t)want));
            remain -= want;
          }
        }
      }
    }

    RINOK(extractCallback->PrepareOperation(opRes));
    curPos += item.IsDir ? 0 : item.Size;
    RINOK(extractCallback->SetCompleted(&curPos));
    RINOK(extractCallback->SetOperationResult(opRes));
  }

  return S_OK;
  COM_TRY_END
}

// ----------------------------------------------------------------
// IsArc: sniff NCCH/NCSD magic at 0x100, or CIA header heuristic.
// ----------------------------------------------------------------
API_FUNC_static_IsArc N3ds_IsArc(const Byte *p, size_t size)
{
  // Standalone Contents.cnt: "CONT" magic at offset 0 (needs only 4 bytes)
  if (size >= 4 && memcmp(p, "CONT", 4) == 0)
    return k_IsArc_Res_YES;
  // Standalone FIRM: magic 'FIRM' at offset 0
  if (size >= 4 && memcmp(p, "FIRM", 4) == 0)
    return k_IsArc_Res_YES;
  if (size < 0x104)
    return k_IsArc_Res_NEED_MORE;
  if (memcmp(p + 0x100, "NCCH", 4) == 0)
    return k_IsArc_Res_YES;
  if (memcmp(p + 0x100, "NCSD", 4) == 0)
    return k_IsArc_Res_YES;
  // CIA heuristic: size_header==0x2020, type<=1, sizes reasonable
  if (GetUi32(p + 0) == 0x2020 && (GetUi32(p + 4) & 0xFFFF) <= 1 &&
      GetUi32(p + 0x10) < 0x1000 && GetUi32(p + 0x14) < 0x200000)
    return k_IsArc_Res_YES;
  // CDN TMD: RSA sig type @0, "Root-" issuer at Y (0x140 for RSA2048 SHA256)
  if (size >= 0x145)
  {
    UInt32 st = GetBe32(p);
    if ((st == 0x010003 || st == 0x010004 || st == 0x010005) &&
        memcmp(p + TmdSigY(st), "Root-", 5) == 0)
      return k_IsArc_Res_YES;
  }
  // Standalone plaintext RomFS: IVFC magic @0 (needs only 4 bytes)
  if (size >= 4 && memcmp(p, "IVFC", 4) == 0)
    return k_IsArc_Res_YES;
  // Standalone plaintext ExeFS: no magic; validate the 10 file entries (0x200 hdr)
  if (size >= 0x200 && ValidExeFsHdr(p))
    return k_IsArc_Res_YES;
  return k_IsArc_Res_NO;
}
}

REGISTER_ARC_I_NO_SIG("3DS", "3ds cci 3dz csu ncch cxi cfa app cia firm cnt bin romfs exefs tmd", NULL, 0xF6, 0, 0, N3ds_IsArc)

}}
