// KeystonePage.cpp - options page for the 3DS AES key folders (keystone.ini)

#include "StdAfx.h"

#include "KeystonePageRes.h"
#include "KeystonePage.h"

#include "BrowseDialog.h"
#include "LangUtils.h"

// Defined in Archive/N3dsHandler.cpp: drops the process-static key table and
// ctrdevice scan caches so the next access re-enumerates the keystone folders.
extern "C" void Z7CtrInvalidateKeystoneCache();

// some button-icon constants are not exposed by 7-Zip's trimmed windows headers
#ifndef BM_SETICON
#define BM_SETICON 0x00F7
#endif
#ifndef BS_ICON
#define BS_ICON 0x00000040L
#endif
#ifndef IMAGE_ICON
#define IMAGE_ICON 1
#endif

using namespace NWindows;

CKeystonePage::CKeystonePage() :
    m_IniPath(),
    m_DefaultRetail(),
    m_DefaultDev(),
    m_DefaultDevice(),
    _needSave(false),
    _initMode(true)
{
}

UString CKeystonePage::GetExeDir() const
{
  wchar_t buf[MAX_PATH] = { 0 };
  GetModuleFileNameW(NULL, buf, MAX_PATH);
  UString p(buf);
  int pos = p.ReverseFind(L'\\');
  if (pos < 0)
    return UString();
  return p.Left(pos);
}

UString CKeystonePage::ReadIni(const UString &key) const
{
  wchar_t buf[MAX_PATH] = { 0 };
  GetPrivateProfileStringW(L"Keystone", key.Ptr(), L"", buf, MAX_PATH, m_IniPath.Ptr());
  return UString(buf);
}

void CKeystonePage::WriteIni(const UString &key, const UString &value) const
{
  WritePrivateProfileStringW(L"Keystone", key.Ptr(),
      value.IsEmpty() ? NULL : value.Ptr(), m_IniPath.Ptr());
}

void CKeystonePage::ModifiedEvent()
{
  if (!_initMode)
  {
    _needSave = true;
    Changed();
  }
}

// Yellow folder icon: prefer the one shipped inside explorer.exe (icon index 0),
// fall back to the system folder icon resolved from a real directory path.
static HICON GetFolderIconSmall(const UString &dirPath)
{
  HICON hSmall = NULL;
  UINT n = ExtractIconExW(L"explorer.exe", 0, NULL, &hSmall, 1);
  if (n != 0 && hSmall)
    return hSmall;

  SHFILEINFOW sfi;
  sfi.hIcon = NULL;
  SHGetFileInfoW(dirPath.IsEmpty() ? L"C:\\" : dirPath.Ptr(), 0, &sfi, sizeof(sfi),
      SHGFI_ICON | SHGFI_SMALLICON);
  return sfi.hIcon;
}

static void SetFolderIcon(HWND dlg, int controlID, const UString &dirPath)
{
  HICON h = GetFolderIconSmall(dirPath);
  if (!h)
    return;
  HWND b = GetDlgItem(dlg, controlID);
  if (!b)
    return;
  // give the button an icon style and attach the folder icon
  LONG_PTR style = GetWindowLongPtrW(b, GWL_STYLE);
  SetWindowLongPtrW(b, GWL_STYLE, style | BS_ICON);
  SendMessageW(b, BM_SETICON, (WPARAM)IMAGE_ICON, (LPARAM)h);
}

void CKeystonePage::BrowsePath(NWindows::NControl::CDialogChildControl &edit, const UString &title)
{
  UString cur;
  edit.GetText(cur);
  UString result;
  LPCWSTR start = cur.IsEmpty() ? L"" : cur.Ptr();
  if (MyBrowseForFolder(*this, title, start, result))
    edit.SetText(result);
}

void CKeystonePage::OpenFolder(NWindows::NControl::CDialogChildControl &edit, const UString &fallback)
{
  UString cur;
  edit.GetText(cur);
  UString target = cur;
  if (target.IsEmpty())
    target = fallback;
  if (!target.IsEmpty())
    ShellExecuteW(NULL, L"open", target.Ptr(), NULL, NULL, SW_SHOWNORMAL);
}

void CKeystonePage::ResetDefaults()
{
  m_RetailPath.SetText(m_DefaultRetail);
  m_DevPath.SetText(m_DefaultDev);
  m_DevicePath.SetText(m_DefaultDevice);
  ModifiedEvent();
}

bool CKeystonePage::OnInit()
{
  _initMode = true;
  _needSave = false;

  UString exeDir = GetExeDir();
  m_IniPath = exeDir + UString(L"\\keystone.ini");
  m_DefaultRetail = exeDir + UString(L"\\keystone\\ctraes_retail");
  m_DefaultDev    = exeDir + UString(L"\\keystone\\ctraes_dev");
  m_DefaultDevice = exeDir + UString(L"\\keystone\\ctrdevice");

  #ifdef Z7_LANG
  LangSetDlgItemText(*this, IDT_KEYSTONE_RETAIL_LABEL, IDT_KEYSTONE_RETAIL_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_DEV_LABEL, IDT_KEYSTONE_DEV_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_DEVICE_LABEL, IDT_KEYSTONE_DEVICE_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_RESET, IDT_KEYSTONE_RESET);
  LangSetDlgItemText(*this, IDB_KEY_REBUILD_CACHE, IDT_KEYSTONE_REBUILD_CACHE);
  #endif

  SetFolderIcon(*this, IDB_KEY_RETAIL_OPEN, exeDir);
  SetFolderIcon(*this, IDB_KEY_DEV_OPEN, exeDir);
  SetFolderIcon(*this, IDB_KEY_DEVICE_OPEN, exeDir);

  m_RetailPath.Init(*this, IDE_KEY_RETAIL_PATH);
  m_DevPath.Init(*this, IDE_KEY_DEV_PATH);
  m_DevicePath.Init(*this, IDE_KEY_DEVICE_PATH);

  UString r = ReadIni(L"RetailCTRAESKeyDir");
  UString d = ReadIni(L"DevCTRAESKeyDir");
  UString dv = ReadIni(L"DeviceDataDir");
  m_RetailPath.SetText(r.IsEmpty() ? m_DefaultRetail : r);
  m_DevPath.SetText(d.IsEmpty() ? m_DefaultDev : d);
  m_DevicePath.SetText(dv.IsEmpty() ? m_DefaultDevice : dv);

  _initMode = false;
  return CPropertyPage::OnInit();
}

LONG CKeystonePage::OnSetActive()
{
  return CPropertyPage::OnSetActive();
}

bool CKeystonePage::OnCommand(unsigned code, unsigned itemID, LPARAM lParam)
{
  if (code == EN_CHANGE &&
      (itemID == IDE_KEY_RETAIL_PATH || itemID == IDE_KEY_DEV_PATH ||
       itemID == IDE_KEY_DEVICE_PATH))
  {
    ModifiedEvent();
    return true;
  }
  return CPropertyPage::OnCommand(code, itemID, lParam);
}

bool CKeystonePage::OnButtonClicked(unsigned buttonID, HWND buttonHWND)
{
  switch (buttonID)
  {
    case IDB_KEY_RETAIL_BROWSE:
      BrowsePath(m_RetailPath, LangString(IDT_KEYSTONE_BROWSE_RETAIL));
      return true;
    case IDB_KEY_DEV_BROWSE:
      BrowsePath(m_DevPath, LangString(IDT_KEYSTONE_BROWSE_DEV));
      return true;
    case IDB_KEY_RETAIL_OPEN:
      OpenFolder(m_RetailPath, m_DefaultRetail);
      return true;
    case IDB_KEY_DEV_OPEN:
      OpenFolder(m_DevPath, m_DefaultDev);
      return true;
    case IDB_KEY_DEVICE_BROWSE:
      BrowsePath(m_DevicePath, LangString(IDT_KEYSTONE_BROWSE_DEVICE));
      return true;
    case IDB_KEY_DEVICE_OPEN:
      OpenFolder(m_DevicePath, m_DefaultDevice);
      return true;
    case IDB_KEY_REBUILD_CACHE:
      // Force the key table and ctrdevice scan to re-read from disk on next access.
      Z7CtrInvalidateKeystoneCache();
      return true;
    case IDB_KEY_RESET:
      ResetDefaults();
      return true;
  }
  return CPropertyPage::OnButtonClicked(buttonID, buttonHWND);
}

LONG CKeystonePage::OnApply()
{
  if (_needSave)
  {
    UString r, d, dv;
    m_RetailPath.GetText(r);
    m_DevPath.GetText(d);
    m_DevicePath.GetText(dv);
    // identical to the built-in default -> clear the key so the default applies
    WriteIni(L"RetailCTRAESKeyDir", r.Compare(m_DefaultRetail) == 0 ? UString() : r);
    WriteIni(L"DevCTRAESKeyDir",    d.Compare(m_DefaultDev)    == 0 ? UString() : d);
    WriteIni(L"DeviceDataDir",      dv.Compare(m_DefaultDevice)== 0 ? UString() : dv);
    _needSave = false;
  }
  return PSNRET_NOERROR;
}
