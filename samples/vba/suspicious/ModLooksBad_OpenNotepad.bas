Attribute VB_Name = "ModLooksBad_OpenNotepad"
Option Explicit

   ' TEST SAMPLE. Looks suspicious to scanners. Does nothing harmful.
   ' Workbook_Open is an auto-run trigger (T1204.002): Excel calls it when the file opens.
   Private Sub Workbook_Open()
       MsgBox "Test sample opened. No action taken."
   End Sub
   
Option Explicit

   ' TEST SAMPLE. Never called from anywhere, and wrapped in If False,
   ' so none of these lines can run. They exist only so static scanners see them.
   Private Sub NeverCalled()
       If False Then ' False, therefore it will never be executed
           Dim sh As Object
           ' T1559.001 COM (Component Object Model) object + T1059 command execution
           Set sh = CreateObject("WScript.Shell")
           sh.Run "notepad.exe"
           Shell "cmd.exe /c echo test"

           ' T1027 obfuscation: Chr() chain that spells "calc"
           Debug.Print Chr(99) & Chr(97) & Chr(108) & Chr(99)

           ' T1027 obfuscation: Base64 for "This is a test"
           Debug.Print "VGhpcyBpcyBhIHRlc3Q="

           ' T1105 indicator: a URL. .invalid is a reserved domain that can never resolve.
           Debug.Print "http://example.invalid/payload.txt"
       End If
   End Sub

