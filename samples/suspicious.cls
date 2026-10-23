Attribute VB_Name = "ThisWorkbook"
' Harmless test sample: opens Notepad when the workbook opens.
' mraptor flags it because it auto-runs (Workbook_Open) and executes a program (Shell).
Private Sub Workbook_Open()
    Shell "notepad.exe"
End Sub
