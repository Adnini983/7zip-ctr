// Agent/ArchiveFolderOpen.cpp

#include "StdAfx.h"

// #ifdef NEW_FOLDER_INTERFACE

#include "../../../Common/StringToInt.h"
#include "../../../Windows/DLL.h"
#include "../../../Windows/ResourceString.h"

#include "Agent.h"

extern HINSTANCE g_hInstance;
static const UINT kIconTypesResId = 100;

void CCodecIcons::LoadIcons(HMODULE m)
{
  IconPairs.Clear();
  UString iconTypes;
  NWindows::MyLoadString(m, kIconTypesResId, iconTypes);
  UStringVector pairs;
  SplitString(iconTypes, pairs);
  FOR_VECTOR (i, pairs)
  {
    const UString &s = pairs[i];
    int pos = s.Find(L':');
    CIconPair iconPair;
    iconPair.IconIndex = -1;
    if (pos < 0)
      pos = (int)s.Len();
    else
    {
      const UString num = s.Ptr((unsigned)pos + 1);
      if (!num.IsEmpty())
      {
        const wchar_t *end;
        iconPair.IconIndex = (int)ConvertStringToUInt32(num, &end);
        if (*end != 0)
          continue;
      }
    }
    iconPair.Ext = s.Left((unsigned)pos);
    IconPairs.Add(iconPair);
  }
}

bool CCodecIcons::FindIconIndex(const UString &ext, int &iconIndex) const
{
  iconIndex = -1;
  FOR_VECTOR (i, IconPairs)
  {
    const CIconPair &pair = IconPairs[i];
    if (ext.IsEqualTo_NoCase(pair.Ext))
    {
      iconIndex = pair.IconIndex;
      return true;
    }
  }
  return false;
}


void CArchiveFolderManager::LoadFormats()
{
  if (WasLoaded)
    return;

  LoadGlobalCodecs();

  #ifdef Z7_EXTERNAL_CODECS
  CodecIconsVector.Clear();
  FOR_VECTOR (i, g_CodecsObj->Libs)
  {
    CCodecIcons &ci = CodecIconsVector.AddNew();
    ci.LoadIcons(g_CodecsObj->Libs[i].Lib.Get_HMODULE());
  }
  #endif
  InternalIcons.LoadIcons(g_hInstance);
  WasLoaded = true;
}

/*
int CArchiveFolderManager::FindFormat(const UString &type)
{
  FOR_VECTOR (i, g_CodecsObj->Formats)
    if (type.IsEqualTo_NoCase(g_CodecsObj->Formats[i].Name))
      return (int)i;
  return -1;
}
*/

Z7_COM7F_IMF(CArchiveFolderManager::OpenFolderFile(IInStream *inStream,
    const wchar_t *filePath, const wchar_t *arcFormat,
    IFolderFolder **resultFolder, IProgress *progress))
{
  CMyComPtr<IArchiveOpenCallback> openArchiveCallback;
  if (progress)
  {
    CMyComPtr<IProgress> progressWrapper = progress;
    progressWrapper.QueryInterface(IID_IArchiveOpenCallback, &openArchiveCallback);
  }
  CAgent *agent = new CAgent();
  CMyComPtr<IInFolderArchive> archive = agent;
  
  const HRESULT res = archive->Open(inStream, filePath, arcFormat, NULL, openArchiveCallback);
  
  if (res != S_OK)
  {
    if (res != S_FALSE)
      return res;
    /* 20.01: we create folder even for Non-Open cases, if there is NonOpen_ErrorInfo information.
         So we can get error information from that IFolderFolder later. */
    if (!agent->_archiveLink.NonOpen_ErrorInfo.IsThereErrorOrWarning())
      return res;
  }
  
  agent->_progress_for_Open = progress;
  agent->_progress_ArchiveOpenCallback_for_Open = openArchiveCallback;
  {
    HRESULT hres = E_OUTOFMEMORY;
    // IInFolderArchive::BindToRootFolder() doesn't raise exceptions.
    // so try/catch is optional
    try {
      hres = archive->BindToRootFolder(resultFolder);
    } catch (...) {}
    agent->_progress_for_Open = NULL;
    agent->_progress_ArchiveOpenCallback_for_Open = NULL;
    RINOK(hres)
  }
  return res;
}

/*
HRESULT CAgent::FolderReOpen(
    IArchiveOpenCallback *openArchiveCallback)
{
  return ReOpenArchive(_archive, _archiveFilePath);
}
*/


/*
Z7_COM7F_IMF(CArchiveFolderManager::GetExtensions(const wchar_t *type, BSTR *extensions))
{
  *extensions = 0;
  int formatIndex = FindFormat(type);
  if (formatIndex <  0)
    return E_INVALIDARG;
  // Exts[0].Ext;
  return StringToBstr(g_CodecsObj.Formats[formatIndex].GetAllExtensions(), extensions);
}
*/

static void AddIconExt(const CCodecIcons &lib, UString &dest)
{
  FOR_VECTOR (i, lib.IconPairs)
  {
    dest.Add_Space_if_NotEmpty();
    dest += lib.IconPairs[i].Ext;
  }
}


Z7_COM7F_IMF(CArchiveFolderManager::GetExtensions(BSTR *extensions))
{
  *extensions = NULL;
  LoadFormats();
  UString res;
  
  #ifdef Z7_EXTERNAL_CODECS
  /*
  FOR_VECTOR (i, g_CodecsObj->Libs)
    AddIconExt(g_CodecsObj->Libs[i].CodecIcons, res);
  */
  FOR_VECTOR (i, CodecIconsVector)
    AddIconExt(CodecIconsVector[i], res);
  #endif
  
  AddIconExt(
      // g_CodecsObj->
      InternalIcons, res);

  return StringToBstr(res, extensions);
}


Z7_COM7F_IMF(CArchiveFolderManager::GetIconPath(const wchar_t *ext, BSTR *iconPath, Int32 *iconIndex))
{
  *iconPath = NULL;
  *iconIndex = 0;
  LoadFormats();

  #ifdef Z7_EXTERNAL_CODECS
  // FOR_VECTOR (i, g_CodecsObj->Libs)
  FOR_VECTOR (i, CodecIconsVector)
  {
    int ii;
    if (CodecIconsVector[i].FindIconIndex(ext, ii))
    {
      const CCodecLib &lib = g_CodecsObj->Libs[i];
      *iconIndex = ii;
      return StringToBstr(fs2us(lib.Path), iconPath);
    }
  }
  #endif

  int ii;
  if (InternalIcons.FindIconIndex(ext, ii) && ii >= 0)
  {
    FString path;
    if (NWindows::NDLL::MyGetModuleFileName(path))
    {
      *iconIndex = ii;
      return StringToBstr(fs2us(path), iconPath);
    }
  }

  // Fallback: resolve format icons that have no dedicated Fm icon from the
  // same-folder 7z.dll (its own icon table, indices match Format7zF/resource.rc).
  static const struct { const wchar_t *ext; int index; } kDllIcons[] =
  {
    { L"7z", 0 }, { L"zip", 1 }, { L"bz2", 2 }, { L"bzip2", 2 }, { L"rar", 3 },
    { L"arj", 4 }, { L"z", 5 }, { L"taz", 5 }, { L"lzh", 6 }, { L"lha", 6 },
    { L"cab", 7 }, { L"iso", 8 }, { L"split", 9 }, { L"001", 9 },
    { L"rpm", 10 }, { L"deb", 11 }, { L"cpio", 12 }, { L"tar", 13 },
    { L"gz", 14 }, { L"gzip", 14 }, { L"tgz", 14 }, { L"tpz", 14 },
    { L"wim", 15 }, { L"swm", 15 }, { L"esd", 15 }, { L"lzma", 16 },
    { L"dmg", 17 }, { L"hfs", 18 }, { L"xar", 19 }, { L"vhd", 20 },
    { L"vhdx", 20 }, { L"fat", 21 }, { L"ntfs", 22 }, { L"xz", 23 },
    { L"txz", 23 }, { L"squashfs", 24 }, { L"apfs", 25 }, { L"zst", 26 },
    { L"tzst", 26 },
    { L"3ds", 27 }, { L"cci", 28 }, { L"3dz", 29 }, { L"csu", 30 },
    { L"ncch", 31 }, { L"cxi", 32 }, { L"cfa", 33 }, { L"app", 34 },
    { L"firm", 35 }, { L"cnt", 36 }, { L"bin", 37 }, { L"tmd", 37 },
    { L"romfs", 38 },
    { L"exefs", 39 }, { L"cia", 40 }
  };
  for (unsigned k = 0; k < sizeof(kDllIcons)/sizeof(kDllIcons[0]); k++)
  {
    if (ext && _wcsicmp(ext, kDllIcons[k].ext) == 0)
    {
      FString path = NWindows::NDLL::GetModuleDirPrefix() + FTEXT("7z.dll");
      *iconIndex = kDllIcons[k].index;
      return StringToBstr(fs2us(path), iconPath);
    }
  }
  return S_OK;
}

/*
Z7_COM7F_IMF(CArchiveFolderManager::GetTypes(BSTR *types))
{
  LoadFormats();
  UString typesStrings;
  FOR_VECTOR(i, g_CodecsObj.Formats)
  {
    const CArcInfoEx &ai = g_CodecsObj.Formats[i];
    if (ai.AssociateExts.Size() == 0)
      continue;
    if (i != 0)
      typesStrings.Add_Space();
    typesStrings += ai.Name;
  }
  return StringToBstr(typesStrings, types);
}
Z7_COM7F_IMF(CArchiveFolderManager::CreateFolderFile(const wchar_t * type,
    const wchar_t * filePath, IProgress progress))
{
  return E_NOTIMPL;
}
*/

// #endif
