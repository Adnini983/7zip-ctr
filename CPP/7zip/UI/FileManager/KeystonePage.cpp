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
    m_DefaultFirm(),
    _needSave(false),
    _initMode(true),
    _hFolderIcon(NULL)
{
}

CKeystonePage::~CKeystonePage()
{
  // The buttons only borrow this icon; it is ours to free once the dialog is gone.
  if (_hFolderIcon)
  {
    DestroyIcon(_hFolderIcon);
    _hFolderIcon = NULL;
  }
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

// Folder icon for the four "browse" buttons. The previous version attached the
// icon through ExtractIconExW() and never owned the handle, which is what made
// the options dialog crash (heap corruption 0xc0000374 in ntdll). This version
// asks the shell for a private copy (SHGFI_USEFILEATTRIBUTES does not touch the
// disk) and keeps ownership here, so it is destroyed exactly once, in the page
// destructor, after the buttons are gone.
static HICON LoadFolderIconSmall()
{
  SHFILEINFOW sfi;
  sfi.hIcon = NULL;
  if (SHGetFileInfoW(L"folder", FILE_ATTRIBUTE_DIRECTORY, &sfi, sizeof(sfi),
        SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES) && sfi.hIcon)
    return sfi.hIcon;

  HICON hSmall = NULL;
  if (ExtractIconExW(L"explorer.exe", 0, NULL, &hSmall, 1) != 0 && hSmall)
    return hSmall;
  return NULL;
}

void CKeystonePage::ApplyFolderIcons()
{
  if (!_hFolderIcon)
    _hFolderIcon = LoadFolderIconSmall();
  if (!_hFolderIcon)
    return;

  // The right-hand buttons ("open this folder in Explorer"); the left-hand ones
  // keep their "..." caption and need no icon.
  const int ids[] = { IDB_KEY_RETAIL_OPEN, IDB_KEY_DEV_OPEN,
                      IDB_KEY_DEVICE_OPEN, IDB_KEY_FIRM_OPEN };
  for (unsigned i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
  {
    HWND b = GetDlgItem(*this, ids[i]);
    if (!b)
      continue;
    LONG_PTR style = GetWindowLongPtrW(b, GWL_STYLE);
    SetWindowLongPtrW(b, GWL_STYLE, style | BS_ICON);
    // a style change only takes effect after a frame refresh
    SetWindowPos(b, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    SendMessageW(b, BM_SETICON, (WPARAM)IMAGE_ICON, (LPARAM)_hFolderIcon);
    ::InvalidateRect(b, NULL, TRUE);
  }
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
  m_FirmPath.SetText(m_DefaultFirm);
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
  m_DefaultFirm   = exeDir + UString(L"\\keystone\\pubkey");

  #ifdef Z7_LANG
  LangSetDlgItemText(*this, IDT_KEYSTONE_RETAIL_LABEL, IDT_KEYSTONE_RETAIL_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_DEV_LABEL, IDT_KEYSTONE_DEV_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_DEVICE_LABEL, IDT_KEYSTONE_DEVICE_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_FIRM_LABEL, IDT_KEYSTONE_FIRM_LABEL);
  LangSetDlgItemText(*this, IDT_KEYSTONE_RESET, IDT_KEYSTONE_RESET);
  LangSetDlgItemText(*this, IDB_KEY_REBUILD_CACHE, IDT_KEYSTONE_REBUILD_CACHE);
  #endif

  m_RetailPath.Init(*this, IDE_KEY_RETAIL_PATH);
  m_DevPath.Init(*this, IDE_KEY_DEV_PATH);
  m_DevicePath.Init(*this, IDE_KEY_DEVICE_PATH);
  m_FirmPath.Init(*this, IDE_KEY_FIRM_PATH);

  UString r = ReadIni(L"RetailCTRAESKeyDir");
  UString d = ReadIni(L"DevCTRAESKeyDir");
  UString dv = ReadIni(L"DeviceDataDir");
  UString fp = ReadIni(L"FirmPubKeyDir");
  m_RetailPath.SetText(r.IsEmpty() ? m_DefaultRetail : r);
  m_DevPath.SetText(d.IsEmpty() ? m_DefaultDev : d);
  m_DevicePath.SetText(dv.IsEmpty() ? m_DefaultDevice : dv);
  m_FirmPath.SetText(fp.IsEmpty() ? m_DefaultFirm : fp);

  _initMode = false;
  ApplyFolderIcons();
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
       itemID == IDE_KEY_DEVICE_PATH || itemID == IDE_KEY_FIRM_PATH))
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
    case IDB_KEY_FIRM_BROWSE:
      BrowsePath(m_FirmPath, LangString(IDT_KEYSTONE_BROWSE_FIRM));
      return true;
    case IDB_KEY_FIRM_OPEN:
      OpenFolder(m_FirmPath, m_DefaultFirm);
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
    UString r, d, dv, fp;
    m_RetailPath.GetText(r);
    m_DevPath.GetText(d);
    m_DevicePath.GetText(dv);
    m_FirmPath.GetText(fp);
    // identical to the built-in default -> clear the key so the default applies
    WriteIni(L"RetailCTRAESKeyDir", r.Compare(m_DefaultRetail) == 0 ? UString() : r);
    WriteIni(L"DevCTRAESKeyDir",    d.Compare(m_DefaultDev)    == 0 ? UString() : d);
    WriteIni(L"DeviceDataDir",      dv.Compare(m_DefaultDevice)== 0 ? UString() : dv);
    WriteIni(L"FirmPubKeyDir",      fp.Compare(m_DefaultFirm)  == 0 ? UString() : fp);
    _needSave = false;
  }
  return PSNRET_NOERROR;
}
