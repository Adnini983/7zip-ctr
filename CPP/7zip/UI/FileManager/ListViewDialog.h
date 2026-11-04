// ListViewDialog.h

#ifndef ZIP7_INC_LISTVIEW_DIALOG_H
#define ZIP7_INC_LISTVIEW_DIALOG_H

#include "../../../Windows/Control/Dialog.h"
#include "../../../Windows/Control/ListView.h"

#include "ListViewDialogRes.h"
#include "../../../Common/MyVector.h"
#include "../../../Common/MyString.h"

struct CListHashEntry
{
  UString Name;              // "SHA-256" / "SHA-1"
  Byte Digest[64];
  unsigned Size;             // 20 or 32
};

class CListViewDialog: public NWindows::NControl::CModalDialog
{
  NWindows::NControl::CListView _listView;
  virtual void OnOK() Z7_override;
  virtual bool OnInit() Z7_override;
  virtual bool OnSize(WPARAM wParam, int xSize, int ySize) Z7_override;
  virtual bool OnNotify(UINT controlID, LPNMHDR header) Z7_override;
  void CopyToClipboard();
  void DeleteItems();
  void ShowItemInfo();
  void OnEnter();
  void WriteHashFile();
  void CompareHashFile();
  virtual bool OnButtonClicked(unsigned buttonID, HWND buttonHWND) Z7_override;
public:
  UString Title;
  
  bool SelectFirst;
  bool DeleteIsAllowed;
  bool StringsWereChanged;
  
  UStringVector Strings;
  UStringVector Values;
  
  int FocusedItemIndex;
  unsigned NumColumns;

  // when set, two extra buttons appear that write / compare GodMode9 style
  // <file>.sha (32 raw bytes) and <file>.sha1 (20 raw bytes) checksum files
  bool HashActions;
  UString HashFilePath;
  CObjectVector<CListHashEntry> HashEntries;

  INT_PTR Create(HWND wndParent = NULL) { return CModalDialog::Create(IDD_LISTVIEW, wndParent); }

  CListViewDialog():
    SelectFirst(false),
    DeleteIsAllowed(false),
    StringsWereChanged(false),
    FocusedItemIndex(-1),
    NumColumns(1),
    HashActions(false)
    {}
};

#endif
