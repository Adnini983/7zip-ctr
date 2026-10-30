// KeystonePage.h - options page to choose the 3DS AES key folders
// (retail / devkit), persisted to keystone.ini next to the program.

#ifndef ZIP7_INC_KEYSTONE_PAGE_H
#define ZIP7_INC_KEYSTONE_PAGE_H

#include "../../../Windows/Control/PropertyPage.h"

class CKeystonePage : public NWindows::NControl::CPropertyPage
{
  NWindows::NControl::CDialogChildControl m_RetailPath;
  NWindows::NControl::CDialogChildControl m_DevPath;
  NWindows::NControl::CDialogChildControl m_DevicePath;

  UString m_IniPath;        // resolved keystone.ini location
  UString m_DefaultRetail;  // built-in default (absolute, resolved)
  UString m_DefaultDev;
  UString m_DefaultDevice;

  bool _needSave;
  bool _initMode;

public:
  CKeystonePage();

private:
  UString GetExeDir() const;
  UString ReadIni(const UString &key) const;
  void WriteIni(const UString &key, const UString &value) const;
  void BrowsePath(NWindows::NControl::CDialogChildControl &edit, const UString &title);
  void OpenFolder(NWindows::NControl::CDialogChildControl &edit, const UString &fallback);
  void ResetDefaults();
  void ModifiedEvent();

  virtual bool OnInit() Z7_override;
  virtual LONG OnSetActive() Z7_override;
  virtual bool OnCommand(unsigned code, unsigned itemID, LPARAM lParam) Z7_override;
  virtual bool OnButtonClicked(unsigned buttonID, HWND buttonHWND) Z7_override;
  virtual LONG OnApply() Z7_override;
};

#endif
