// N3dsHandler.cpp
// Nintendo 3DS container formats: CIA, NCSD (.3ds), NCCH (CXI/CFA), ExeFS, RomFS.
// Read-only archive handler for 7-Zip (inspired by 7-Zip ZS codec integration).

#include "StdAfx.h"

#pragma warning(disable: 4324)   // align specifier padding in CHandler

#include <stdio.h>

#include "../../../C/CpuArch.h"
#include "../../../C/Aes.h"
#include "../../../C/Sha256.h"

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
  UInt64 GetSize() const { return Size; }
};

// Archive-level technical info (NCSD / CIA / NCCH headers), shown in the
// 7zFM "Properties" dialog via IArchive::GetArchivePropertyInfo/GetArchiveProperty.
// Mirrors the fields ctrtool prints (see 3DSGuy/Project_CTR ctrtool Cci/Cia/NcchProcess).
// (Named CN3dsInfo to avoid clashing with 7-Zip's own CArcInfo used by RegisterArc.)
struct CN3dsInfo
{
  int Container;                 // 0 = none, 1 = CIA, 2 = NCSD, 3 = NCCH
  bool IsCia() const { return Container == 1; }
  bool IsNcsd() const { return Container == 2; }
  bool IsNcch() const { return Container == 3; }

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
// Loaded from <7z.dll dir>\3dskey\*.key      (retail)
//              <7z.dll dir>\3dskey_dev\*.key (developer)
// Each file holds a single key as text:  "KeyName=XXXXXXXX...XXXX" (32 hex chars).
// See https://www.3dbrew.org/wiki/AES_Registers for keyslot semantics.
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
    LoadDir(dll + UString(L"\\3dskey"), false);
    LoadDir(dll + UString(L"\\3dskey_dev"), true);
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
//   C1 = 0x1FF9E9AAC5FE0408024591DC5D52768A
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

Z7_CLASS_IMP_CHandler_IInArchive_0
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
  kpidN3dsContent0
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
  { "File System",      kpidFileSystem,        VT_BSTR }
};

IMP_IInArchive_Props
IMP_IInArchive_ArcProps_WITH_NAME

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
        UString nm = _cntDir + HexUInt64Padded(_cupTitles[i]) + UString(L".cia");
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
    bool devkit = (memcmp(tik + 0x140, "Root-CA00000004-XS00000009", 0x2A) == 0);
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
      if (devkit)
        sprintf_s(nm, "common%uN", (unsigned)ckIdx);
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
        sprintf_s(nmN, "common%uN", (unsigned)ckIdx);
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

// ----------------------------------------------------------------
HRESULT CHandler::Open2(IInStream *)
{
  // ensure external keys (3dskey / 3dskey_dev next to 7z.dll) are loaded
  C3dsKeys::Instance().EnsureLoaded();

  Byte hdr[0x200];
  HRESULT res = ReadAt(0, hdr, 0x200);
  if (res != S_OK || res == S_FALSE)
    return S_FALSE;

  // CIA: header size field == 0x2020
  if (GetUi32(hdr) == 0x2020)
    return ParseCia(0);

  // NCCH / NCSD magic lives at 0x100
  if (memcmp(hdr + 0x100, "NCCH", 4) == 0)
    return ParseNCCH(0, UString());
  if (memcmp(hdr + 0x100, "NCSD", 4) == 0)
    return ParseNcsd(0);

  return S_FALSE;
}

Z7_COM7F_IMF(CHandler::Open(IInStream *stream, const UInt64 *, IArchiveOpenCallback *))
{
  COM_TRY_BEGIN
  Close();
  _stream = stream;
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
  return S_OK;
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
        C3dsKeys &k = C3dsKeys::Instance();
        k.EnsureLoaded();
        if (k.Retail() != 0 || k.Dev() != 0)
        {
          UString s = UString(L"3DS keys: retail=");
          s += NumToUString(k.Retail());
          s += UString(L", dev=");
          s += NumToUString(k.Dev());
          prop = s;
        }
        break;
      }

    // ---- technical info (mirrors ctrtool output) ----
    case kpidN3dsContainer:
      if (_info.IsCia()) prop = "CIA";
      else if (_info.IsNcsd()) prop = "NCSD";
      else if (_info.IsNcch()) prop = "NCCH";
      break;
    case kpidN3dsMediaId:
      if (_info.IsNcsd()) prop = HexUInt64(_info.MediaId);
      break;
    case kpidN3dsTitleId:
      if (_info.IsCia()) prop = HexUInt64(_info.TitleId);
      else if (_info.IsNcch()) prop = HexUInt64(_info.NcchTitleId);
      break;
    case kpidN3dsProgramId:
      if (_info.IsNcch()) prop = HexUInt64(_info.ProgramId);
      break;
    case kpidN3dsTitleVer:
      {
        UInt16 v = 0;
        if (_info.IsCia()) v = _info.TmdTitleVersion;
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
      if (_info.IsCia()) prop = (UInt32)_info.ContentCount;
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
    if (!item.IsDir)
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

    Int32 opRes = NArchive::NExtract::NOperationResult::kOK;
    CMyComPtr<ISequentialOutStream> outStream;
    RINOK(extractCallback->GetStream(index, &outStream,
        testMode ? NArchive::NExtract::NAskMode::kTest : NArchive::NExtract::NAskMode::kExtract));

    if (!item.IsDir && (outStream || testMode))
    {
      if (!testMode)
      {
        if (item.Encrypted && _titleKeyOk)
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
  return k_IsArc_Res_NO;
}
}

REGISTER_ARC_I_NO_SIG("3DS", "3ds cta cia cxi cfa ncch", NULL, 0xF6, 0, 0, N3ds_IsArc)

}}
