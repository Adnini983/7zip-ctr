// ListViewDialog.cpp

#include "StdAfx.h"

#include "../../../Windows/Clipboard.h"

#include "EditDialog.h"
#include "ListViewDialog.h"
#include "RegistryUtils.h"

#include "../../../Windows/FileName.h"
#include "../../../Windows/FileIO.h"

#ifdef Z7_LANG
#include "LangUtils.h"
#endif

using namespace NWindows;

static const unsigned kOneStringMaxSize = 1024;


static void ListView_GetSelected(NControl::CListView &listView, CUIntVector &vector)
{
  vector.Clear();
  int index = -1;
  for (;;)
  {
    index = listView.GetNextSelectedItem(index);
    if (index < 0)
      break;
    vector.Add((unsigned)index);
  }
}


bool CListViewDialog::OnInit()
{
  #ifdef Z7_LANG
  LangSetDlgItems(*this, NULL, 0);
  #endif
  _listView.Attach(GetItem(IDL_LISTVIEW));

  if (NumColumns > 1)
  {
    LONG_PTR style = _listView.GetStyle();
    style &= ~(LONG_PTR)LVS_NOCOLUMNHEADER;
    _listView.SetStyle(style);
  }

  CFmSettings st;
  st.Load();

  DWORD exStyle = 0;
  
  if (st.SingleClick)
    exStyle |= LVS_EX_ONECLICKACTIVATE | LVS_EX_TRACKSELECT;

  exStyle |= LVS_EX_FULLROWSELECT;
  if (exStyle != 0)
    _listView.SetExtendedListViewStyle(exStyle);


  SetText(Title);

  const int kWidth = 400;
  
  LVCOLUMN columnInfo;
  columnInfo.mask = LVCF_FMT | LVCF_WIDTH | LVCF_SUBITEM;
  columnInfo.fmt = LVCFMT_LEFT;
  columnInfo.iSubItem = 0;
  columnInfo.cx = kWidth;
  columnInfo.pszText = NULL; // (TCHAR *)(const TCHAR *)""; // "Property"

  if (NumColumns > 1)
  {
    columnInfo.cx = 100;
    /*
    // Windows always uses LVCFMT_LEFT for first column.
    // if we need LVCFMT_RIGHT, we can create dummy column and then remove it

    // columnInfo.mask |= LVCF_TEXT;
    _listView.InsertColumn(0, &columnInfo);
  
    columnInfo.iSubItem = 1;
    columnInfo.fmt = LVCFMT_RIGHT;
    _listView.InsertColumn(1, &columnInfo);
    _listView.DeleteColumn(0);
    */
  }
  // else
    _listView.InsertColumn(0, &columnInfo);

  if (NumColumns > 1)
  {
    // columnInfo.fmt = LVCFMT_LEFT;
    columnInfo.cx = kWidth - columnInfo.cx;
    columnInfo.iSubItem = 1;
    // columnInfo.pszText = NULL; // (TCHAR *)(const TCHAR *)""; // "Value"
    _listView.InsertColumn(1, &columnInfo);
  }


  UString s;
  
  FOR_VECTOR (i, Strings)
  {
    _listView.InsertItem(i, Strings[i]);

    if (NumColumns > 1 && i < Values.Size())
    {
      s = Values[i];
      if (s.Len() > kOneStringMaxSize)
      {
        s.DeleteFrom(kOneStringMaxSize);
        s += " ...";
      }
      s.Replace(L"\r\n", L" ");
      s.Replace(L"\n", L" ");
      _listView.SetSubItem(i, 1, s);
    }
  }

  if (SelectFirst && Strings.Size() > 0)
    _listView.SetItemState_FocusedSelected(0);

  _listView.SetColumnWidthAuto(0);
  if (NumColumns > 1)
    _listView.SetColumnWidthAuto(1);
  StringsWereChanged = false;

  if (!HashActions)
  {
    ShowItem(IDB_LISTVIEW_WRITE, false);
    ShowItem(IDB_LISTVIEW_COMPARE, false);
  }
  else
  {
    #ifdef Z7_LANG
    LangSetDlgItemText(*this, IDB_LISTVIEW_WRITE, IDT_LISTVIEW_WRITE);
    LangSetDlgItemText(*this, IDB_LISTVIEW_COMPARE, IDT_LISTVIEW_COMPARE);
    #endif
  }

  NormalizeSize();
  return CModalDialog::OnInit();
}

bool CListViewDialog::OnSize(WPARAM /* wParam */, int xSize, int ySize)
{
  int mx, my;
  GetMargins(8, mx, my);
  int bx1, bx2, by;
  GetItemSizes(IDCANCEL, bx1, by);
  GetItemSizes(IDOK, bx2, by);
  int y = ySize - my - by;
  int x = xSize - mx - bx1;

  /*
  RECT rect;
  GetClientRect(&rect);
  rect.top = y - my;
  InvalidateRect(&rect);
  */
  InvalidateRect(NULL);

  MoveItem(IDCANCEL, x, y, bx1, by);
  MoveItem(IDOK, x - mx - bx2, y, bx2, by);

  if (HashActions)
  {
    int wx, wy, w2, h2;
    GetItemSizes(IDB_LISTVIEW_WRITE, wx, wy);
    GetItemSizes(IDB_LISTVIEW_COMPARE, w2, h2);
    MoveItem(IDB_LISTVIEW_WRITE, mx, y, wx, by);
    MoveItem(IDB_LISTVIEW_COMPARE, mx + wx + mx, y, w2, by);
  }
  /*
  if (wParam == SIZE_MAXSHOW || wParam == SIZE_MAXIMIZED || wParam == SIZE_MAXHIDE)
    mx = 0;
  */
  _listView.Move(mx, my, xSize - mx * 2, y - my * 2);
  return false;
}


extern bool g_LVN_ITEMACTIVATE_Support;

void CListViewDialog::CopyToClipboard()
{
  CUIntVector indexes;
  ListView_GetSelected(_listView, indexes);
  UString s;
  
  FOR_VECTOR (i, indexes)
  {
    unsigned index = indexes[i];
    s += Strings[index];
    if (NumColumns > 1 && index < Values.Size())
    {
      const UString &v = Values[index];
      // if (!v.IsEmpty())
      {
        s += ": ";
        s += v;
      }
    }
    // if (indexes.Size() > 1)
    {
      s +=
        #ifdef _WIN32
          "\r\n"
        #else
          "\n"
        #endif
        ;
    }
  }
  
  ClipboardSetText(*this, s);
}


void CListViewDialog::ShowItemInfo()
{
  CUIntVector indexes;
  ListView_GetSelected(_listView, indexes);
  if (indexes.Size() != 1)
    return;
  unsigned index = indexes[0];

  CEditDialog dlg;
  if (NumColumns == 1)
    dlg.Text = Strings[index];
  else
  {
    dlg.Title = Strings[index];
    if (index < Values.Size())
      dlg.Text = Values[index];
  }
  
  #ifdef _WIN32
  if (dlg.Text.Find(L'\r') < 0)
    dlg.Text.Replace(L"\n", L"\r\n");
  #endif

  dlg.Create(*this);
}


void CListViewDialog::DeleteItems()
{
  for (;;)
  {
    const int index = _listView.GetNextSelectedItem(-1);
    if (index < 0)
      break;
    StringsWereChanged = true;
    _listView.DeleteItem((unsigned)index);
    if ((unsigned)index < Strings.Size())
      Strings.Delete((unsigned)index);
    if ((unsigned)index < Values.Size())
      Values.Delete((unsigned)index);
  }
  const int focusedIndex = _listView.GetFocusedItem();
  if (focusedIndex >= 0)
    _listView.SetItemState_FocusedSelected(focusedIndex);
  _listView.SetColumnWidthAuto(0);
}


void CListViewDialog::OnEnter()
{
  if (IsKeyDown(VK_MENU)
      || NumColumns > 1)
  {
    ShowItemInfo();
    return;
  }
  OnOK();
}

bool CListViewDialog::OnNotify(UINT /* controlID */, LPNMHDR header)
{
  if (header->hwndFrom != _listView)
    return false;
  switch (header->code)
  {
    case LVN_ITEMACTIVATE:
      if (g_LVN_ITEMACTIVATE_Support)
      {
        OnEnter();
        return true;
      }
      break;
    case NM_DBLCLK:
    case NM_RETURN: // probabably it's unused
      if (!g_LVN_ITEMACTIVATE_Support)
      {
        OnEnter();
        return true;
      }
      break;

    case LVN_KEYDOWN:
    {
      LPNMLVKEYDOWN keyDownInfo = LPNMLVKEYDOWN(header);
      switch (keyDownInfo->wVKey)
      {
        case VK_DELETE:
        {
          if (!DeleteIsAllowed)
            return false;
          DeleteItems();
          return true;
        }
        case 'A':
        {
          if (IsKeyDown(VK_CONTROL))
          {
            _listView.SelectAll();
            return true;
          }
          break;
        }
        case VK_INSERT:
        case 'C':
        {
          if (IsKeyDown(VK_CONTROL))
          {
            CopyToClipboard();
            return true;
          }
          break;
        }
      }
    }
  }
  return false;
}

static bool WriteRawFile(const UString &path, const Byte *data, unsigned size)
{
  HANDLE h = ::CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
      FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD written = 0;
  const BOOL ok = ::WriteFile(h, data, size, &written, NULL);
  ::CloseHandle(h);
  return ok && written == size;
}

static bool ReadRawFile(const UString &path, Byte *data, unsigned size, unsigned &got)
{
  got = 0;
  HANDLE h = ::CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  DWORD n = 0;
  const BOOL ok = ::ReadFile(h, data, size, &n, NULL);
  ::CloseHandle(h);
  got = n;
  return ok && n == size;
}

static bool FileExistsOnDisk(const UString &path)
{
  const DWORD attr = ::GetFileAttributesW(path);
  return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static UString HashMsg(UInt32 langID, const wchar_t *fallback)
{
  #ifdef Z7_LANG
  {
    const UString s = LangString(langID);
    if (!s.IsEmpty())
      return s;
  }
  #endif
  return UString(fallback);
}

void CListViewDialog::WriteHashFile()
{
  if (HashFilePath.IsEmpty() || HashEntries.IsEmpty())
    return;

  UString report;
  FOR_VECTOR (i, HashEntries)
  {
    const CListHashEntry &e = HashEntries[i];
    if (e.Size != 20 && e.Size != 32)
      continue;
    UString path = HashFilePath;
    path += (e.Size == 20) ? L".sha1" : L".sha";

    if (FileExistsOnDisk(path))
    {
      UString q = HashMsg(IDT_LISTVIEW_OVERWRITE, L"Overwrite?");
      q.Add_LF();
      q += path;
      if (::MessageBoxW(*this, q, L"7-Zip", MB_YESNO | MB_ICONQUESTION) != IDYES)
        continue;
    }

    if (WriteRawFile(path, e.Digest, e.Size))
    {
      report += HashMsg(IDT_LISTVIEW_WRITTEN, L"Written: ");
      report += path;
    }
    else
    {
      report += HashMsg(IDT_LISTVIEW_FAILED, L"Failed: ");
      report += path;
    }
    report.Add_LF();
  }

  if (!report.IsEmpty())
    ::MessageBoxW(*this, report, L"7-Zip", MB_OK | MB_ICONINFORMATION);
}

void CListViewDialog::CompareHashFile()
{
  if (HashFilePath.IsEmpty() || HashEntries.IsEmpty())
    return;

  UString report;
  FOR_VECTOR (i, HashEntries)
  {
    const CListHashEntry &e = HashEntries[i];
    if (e.Size != 20 && e.Size != 32)
      continue;
    UString path = HashFilePath;
    path += (e.Size == 20) ? L".sha1" : L".sha";

    Byte buf[64];
    unsigned got = 0;
    if (!ReadRawFile(path, buf, e.Size, got) || got != e.Size)
    {
      report += HashMsg(IDT_LISTVIEW_MISSING, L"Missing / unreadable: ");
      report += path;
    }
    else if (memcmp(buf, e.Digest, e.Size) == 0)
    {
      report += HashMsg(IDT_LISTVIEW_MATCH, L"OK: ");
      report += path;
    }
    else
    {
      report += HashMsg(IDT_LISTVIEW_MISMATCH, L"MISMATCH: ");
      report += path;
    }
    report.Add_LF();
  }

  if (!report.IsEmpty())
    ::MessageBoxW(*this, report, L"7-Zip", MB_OK | MB_ICONINFORMATION);
}

bool CListViewDialog::OnButtonClicked(unsigned buttonID, HWND buttonHWND)
{
  switch (buttonID)
  {
    case IDB_LISTVIEW_WRITE:
      WriteHashFile();
      return true;
    case IDB_LISTVIEW_COMPARE:
      CompareHashFile();
      return true;
  }
  return CModalDialog::OnButtonClicked(buttonID, buttonHWND);
}

void CListViewDialog::OnOK()
{
  FocusedItemIndex = _listView.GetFocusedItem();
  CModalDialog::OnOK();
}
