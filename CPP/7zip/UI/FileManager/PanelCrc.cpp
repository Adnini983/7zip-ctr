// PanelCrc.cpp

#include "StdAfx.h"

#include "../../../Common/MyException.h"

#include "../../../Windows/FileFind.h"
#include "../../../Windows/FileIO.h"
#include "../../../Windows/FileName.h"

#include "../Common/LoadCodecs.h"

#include "../GUI/HashGUI.h"

#include "App.h"
#include "LangUtils.h"

#include "resource.h"

// ---- temporary CRC diagnostics (ASCII only) -------------------------------
static void Z7CrcLog(const char *what, const wchar_t *detail)
{
  wchar_t dir[MAX_PATH];
  DWORD n = ::GetTempPathW(MAX_PATH, dir);
  if (n == 0 || n >= MAX_PATH)
    return;
  UString path(dir);
  path += L"z7crc.log";
  HANDLE h = ::CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return;
  DWORD w = 0;
  {
    wchar_t self[MAX_PATH];
    DWORD sn = ::GetModuleFileNameW(NULL, self, MAX_PATH);
    if (sn > 0 && sn < MAX_PATH)
    {
      const wchar_t *base = self;
      for (DWORD i = 0; i < sn; i++)
        if (self[i] == L'\\' || self[i] == L'/')
          base = self + i + 1;
      char nb[512];
      const int cn = ::WideCharToMultiByte(CP_UTF8, 0, base, -1, nb, (int)sizeof(nb) - 1, NULL, NULL);
      if (cn > 1)
      {
        ::WriteFile(h, nb, (DWORD)(cn - 1), &w, NULL);
        ::WriteFile(h, " ", 1, &w, NULL);
      }
    }
  }
  ::WriteFile(h, what, (DWORD)::lstrlenA(what), &w, NULL);
  ::WriteFile(h, " | ", 3, &w, NULL);
  if (detail)
  {
    char buf[2048];
    const int n2 = ::WideCharToMultiByte(CP_UTF8, 0, detail, -1, buf, (int)sizeof(buf) - 1, NULL, NULL);
    if (n2 > 1)
      ::WriteFile(h, buf, (DWORD)(n2 - 1), &w, NULL);
  }
  ::WriteFile(h, "\r\n", 2, &w, NULL);
  ::CloseHandle(h);
}
// ---------------------------------------------------------------------------


// The panel may have been entered through a relative prefix, so never trust the
// textual name: ask the open handle for the real path (Win7+), else resolve it.
static UString GetRealPathOfOpenFile(const NWindows::NFile::NIO::CInFile &file, const FString &fallback)
{
  typedef DWORD (WINAPI *FUNC_GetFinalPathNameByHandleW)(HANDLE, LPWSTR, DWORD, DWORD);
  const HMODULE hmod = ::GetModuleHandleW(L"kernel32.dll");
  if (hmod)
  {
    #pragma warning(push)
    #pragma warning(disable: 4191)   // GetProcAddress result -> typed function pointer
    const FUNC_GetFinalPathNameByHandleW fn = (FUNC_GetFinalPathNameByHandleW)
        ::GetProcAddress(hmod, "GetFinalPathNameByHandleW");
    #pragma warning(pop)
    if (fn && file.GetHandle() != INVALID_HANDLE_VALUE)
    {
      wchar_t full[MAX_PATH * 4];
      const DWORD n = fn(file.GetHandle(), full,
          (DWORD)(sizeof(full) / sizeof(full[0])), 0 /* FILE_NAME_NORMALIZED | VOLUME_NAME_DOS */);
      if (n > 0 && n < sizeof(full) / sizeof(full[0]))
      {
        const wchar_t *p = full;
        if (n > 4 && full[0] == L'\\' && full[1] == L'\\' && full[2] == L'?' && full[3] == L'\\')
          p = full + 4;
        return UString(p);
      }
    }
  }

  {
    UString full;
    if (NWindows::NFile::NDir::MyGetFullPathName(fs2us(fallback), full))
      return full;
  }
  return fs2us(fallback);
}


using namespace NWindows;
using namespace NFile;

#ifdef Z7_EXTERNAL_CODECS
extern CExternalCodecs g_ExternalCodecs;
HRESULT LoadGlobalCodecs();
#endif

static const UInt32 kBufSize = (1 << 15);

struct CDirEnumerator
{
  bool EnterToDirs;
  FString BasePrefix;
  FString BasePrefix_for_Open;
  FStringVector FilePaths;

  CObjectVector<NFind::CEnumerator> Enumerators;
  FStringVector Prefixes;
  unsigned Index;

  CDirEnumerator(): EnterToDirs(false), Index(0) {}

  void Init();
  DWORD GetNextFile(NFind::CFileInfo &fi, bool &filled, FString &resPath);
};

void CDirEnumerator::Init()
{
  Enumerators.Clear();
  Prefixes.Clear();
  Index = 0;
}

static DWORD GetNormalizedError()
{
  const DWORD error = GetLastError();
  return (error == 0) ? (DWORD)E_FAIL : error;
}

DWORD CDirEnumerator::GetNextFile(NFind::CFileInfo &fi, bool &filled, FString &resPath)
{
  filled = false;
  resPath.Empty();
  
  for (;;)
  {
    #if defined(_WIN32) && !defined(UNDER_CE)
    bool isRootPrefix = (BasePrefix.IsEmpty() || (NName::IsSuperPath(BasePrefix) && BasePrefix[NName::kSuperPathPrefixSize] == 0));
    #endif

    if (Enumerators.IsEmpty())
    {
      if (Index >= FilePaths.Size())
        return S_OK;
      const FString &path = FilePaths[Index++];
      const int pos = path.ReverseFind_PathSepar();
      if (pos >= 0)
        resPath.SetFrom(path, (unsigned)pos + 1);

      #if defined(_WIN32) && !defined(UNDER_CE)
      if (isRootPrefix && path.Len() == 2 && NName::IsDrivePath2(path))
      {
        // we use "c:" item as directory item
        fi.ClearBase();
        fi.Name = path;
        fi.SetAsDir();
        fi.Size = 0;
      }
      else
      #endif
      if (!fi.Find(BasePrefix + path))
      {
        const DWORD error = GetNormalizedError();
        resPath = path;
        return error;
      }
    
      break;
    }
    
    bool found;
    
    if (Enumerators.Back().Next(fi, found))
    {
      if (found)
      {
        resPath = Prefixes.Back();
        break;
      }
    }
    else
    {
      const DWORD error = GetNormalizedError();
      resPath = Prefixes.Back();
      Enumerators.DeleteBack();
      Prefixes.DeleteBack();
      return error;
    }
    
    Enumerators.DeleteBack();
    Prefixes.DeleteBack();
  }
  
  resPath += fi.Name;
  
  if (EnterToDirs && fi.IsDir())
  {
    FString s = resPath;
    s.Add_PathSepar();
    Prefixes.Add(s);
    Enumerators.AddNew().SetDirPrefix(BasePrefix + s);
  }
  
  filled = true;
  return S_OK;
}



class CThreadCrc: public CProgressThreadVirt
{
  bool ResultsWereShown;
  bool WasFinished;
  UString FirstFullPath;   // absolute path of the first hashed file

  HRESULT ProcessVirt() Z7_override;
  virtual void ProcessWasFinished_GuiVirt() Z7_override;
public:
  CDirEnumerator Enumerator;
  CHashBundle Hash;
  // FString FirstFilePath;

  void SetStatus(const UString &s);
  void AddErrorMessage(DWORD systemError, const FChar *name);
  void ShowFinalResults(HWND hwnd);

  CThreadCrc():
    ResultsWereShown(false),
    WasFinished(false)
    {}
};

void CThreadCrc::ShowFinalResults(HWND hwnd)
{
  if (WasFinished)
  if (!ResultsWereShown)
  {
    ResultsWereShown = true;
    Z7CrcLog("ShowFinalResults", FirstFullPath);
    ShowHashResults(Hash, hwnd, FirstFullPath);
  }
}

void CThreadCrc::ProcessWasFinished_GuiVirt()
{
  ShowFinalResults(*this);
}

void CThreadCrc::AddErrorMessage(DWORD systemError, const FChar *name)
{
  Sync.AddError_Code_Name(HRESULT_FROM_WIN32(systemError), fs2us(Enumerator.BasePrefix + name));
  Hash.NumErrors++;
}

void CThreadCrc::SetStatus(const UString &s2)
{
  UString s = s2;
  if (!Enumerator.BasePrefix.IsEmpty())
  {
    s.Add_Space_if_NotEmpty();
    s += fs2us(Enumerator.BasePrefix);
  }
  Sync.Set_Status(s);
}

HRESULT CThreadCrc::ProcessVirt()
{
  // Hash.Init();
  
  CMyBuffer buf;
  if (!buf.Allocate(kBufSize))
    return E_OUTOFMEMORY;

  CProgressSync &sync = Sync;
  
  SetStatus(LangString(IDS_SCANNING));

  Enumerator.Init();

  FString path;
  NFind::CFileInfo fi;
  UInt64 numFiles = 0;
  UInt64 numItems = 0, numItems_Prev = 0;
  UInt64 totalSize = 0;

  for (;;)
  {
    bool filled;
    const DWORD error = Enumerator.GetNextFile(fi, filled, path);
    if (error != 0)
    {
      AddErrorMessage(error, path);
      continue;
    }
    if (!filled)
      break;
    if (!fi.IsDir())
    {
      totalSize += fi.Size;
      numFiles++;
    }
    numItems++;
    bool needPrint = false;
    // if (fi.IsDir())
    {
      if (numItems - numItems_Prev >= 100)
      {
        needPrint = true;
        numItems_Prev = numItems;
      }
    }
    /*
    else if (numFiles - numFiles_Prev >= 200)
    {
      needPrint = true;
      numFiles_Prev = numFiles;
    }
    */
    if (needPrint)
    {
      RINOK(sync.ScanProgress(numFiles, totalSize, path, fi.IsDir()))
    }
  }
  RINOK(sync.ScanProgress(numFiles, totalSize, FString(), false))
  // sync.SetNumFilesTotal(numFiles);
  // sync.SetProgress(totalSize, 0);
  // SetStatus(LangString(IDS_CHECKSUM_CALCULATING));
  // sync.SetCurFilePath(L"");
  SetStatus(L"");
 
  Enumerator.Init();

  FString tempPath;
  bool isFirstFile = true;
  UInt64 errorsFilesSize = 0;

  for (;;)
  {
    bool filled;
    DWORD error = Enumerator.GetNextFile(fi, filled, path);
    if (error != 0)
    {
      AddErrorMessage(error, path);
      continue;
    }
    if (!filled)
      break;
    
    error = 0;
    Hash.InitForNewFile();
    if (!fi.IsDir())
    {
      NIO::CInFile inFile;
      tempPath = Enumerator.BasePrefix_for_Open;
      tempPath += path;
      if (!inFile.Open(tempPath))
      {
        error = GetNormalizedError();
        AddErrorMessage(error, path);
        continue;
      }
      if (isFirstFile)
      {
        Hash.FirstFileName = fs2us(path);
        // Resolve the real path from the opened handle when available (works even
        // if the panel prefix is relative); fall back to GetFullPathName().
        FirstFullPath = GetRealPathOfOpenFile(inFile, tempPath);
        {
          UString d = L"path="; d += fs2us(path);
          d += L" temp="; d += fs2us(tempPath);
          d += L" first="; d += FirstFullPath;
          Z7CrcLog("PanelCrc first-file", d);
        }
        isFirstFile = false;
      }
      sync.Set_FilePath(fs2us(path));
      sync.Set_NumFilesCur(Hash.NumFiles);
      UInt64 progress_Prev = 0;
      for (;;)
      {
        UInt32 size;
        if (!inFile.Read(buf, kBufSize, size))
        {
          error = GetNormalizedError();
          AddErrorMessage(error, path);
          UInt64 errorSize = 0;
          if (inFile.GetLength(errorSize))
            errorsFilesSize += errorSize;
          break;
        }
        if (size == 0)
          break;
        Hash.Update(buf, size);
        if (Hash.CurSize - progress_Prev >= ((UInt32)1 << 21))
        {
          RINOK(sync.Set_NumBytesCur(errorsFilesSize + Hash.FilesSize + Hash.CurSize))
          progress_Prev = Hash.CurSize;
        }
      }
    }
    if (error == 0)
      Hash.Final(fi.IsDir(), false, fs2us(path));
    RINOK(sync.Set_NumBytesCur(errorsFilesSize + Hash.FilesSize))
  }
  RINOK(sync.Set_NumBytesCur(errorsFilesSize + Hash.FilesSize))
  sync.Set_NumFilesCur(Hash.NumFiles);
  if (Hash.NumFiles != 1)
    sync.Set_FilePath(L"");
  SetStatus(L"");

  CProgressMessageBoxPair &pair = GetMessagePair(Hash.NumErrors != 0);
  WasFinished = true;
  LangString(IDS_CHECKSUM_INFORMATION, pair.Title);
  return S_OK;
}



HRESULT CApp::CalculateCrc2(const UString &methodName)
{
  unsigned srcPanelIndex = GetFocusedPanelIndex();
  CPanel &srcPanel = Panels[srcPanelIndex];

  CRecordVector<UInt32> indices;
  srcPanel.Get_ItemIndices_OperSmart(indices);
  if (indices.IsEmpty())
    return S_OK;

  if (!srcPanel.Is_IO_FS_Folder())
  {
    CCopyToOptions options;
    options.streamMode = true;
    options.showErrorMessages = true;
    options.hashMethods.Add(methodName);
    options.NeedRegistryZone = false;

    UStringVector messages;
    return srcPanel.CopyTo(options, indices, &messages);
  }

  #ifdef Z7_EXTERNAL_CODECS

  LoadGlobalCodecs();
    
  #endif

  {
    CThreadCrc t;

    {
      UStringVector methods;
      methods.Add(methodName);
      RINOK(t.Hash.SetMethods(EXTERNAL_CODECS_VARS_G methods))
    }
    
    FOR_VECTOR (i, indices)
      t.Enumerator.FilePaths.Add(us2fs(srcPanel.GetItemRelPath(indices[i])));

    if (t.Enumerator.FilePaths.Size() == 1)
      t.Hash.MainName = fs2us(t.Enumerator.FilePaths[0]);

    UString basePrefix = srcPanel.GetFsPath();
    UString basePrefix2 = basePrefix;
    if (basePrefix2.Back() == ':')
    {
      const int pos = basePrefix2.ReverseFind_PathSepar();
      if (pos >= 0)
        basePrefix2.DeleteFrom((unsigned)(pos + 1));
    }

    t.Enumerator.BasePrefix = us2fs(basePrefix);
    t.Enumerator.BasePrefix_for_Open = us2fs(basePrefix2);

    t.Enumerator.EnterToDirs = !GetFlatMode();
    
    t.ShowCompressionInfo = false;
    
    const UString title = LangString(IDS_CHECKSUM_CALCULATING);
    
    t.MainWindow = _window;
    t.MainTitle = "7-Zip CTR"; // LangString(IDS_APP_TITLE);
    t.MainAddTitle = title;
    t.MainAddTitle.Add_Space();
    
    RINOK(t.Create(title, _window))

    t.ShowFinalResults(_window);
  }

  RefreshTitleAlways();
  return S_OK;
}

void CApp::CalculateCrc(const char *methodName)
{
  HRESULT res = CalculateCrc2(UString(methodName));
  if (res != S_OK && res != E_ABORT)
  {
    unsigned srcPanelIndex = GetFocusedPanelIndex();
    CPanel &srcPanel = Panels[srcPanelIndex];
    srcPanel.MessageBox_Error_HRESULT(res);
  }
}
