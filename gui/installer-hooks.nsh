; FilePigeon installer hooks (included by Tauri's NSIS template).

!macro NSIS_HOOK_PREUNINSTALL
  ; Remove the start-at-login entry the app creates when that setting is on,
  ; so nothing tries to launch FilePigeon after it's uninstalled.
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "FilePigeon"
  ; And the filepigeon:// invite links the app registers for itself.
  DeleteRegKey HKCU "Software\Classes\filepigeon"
!macroend
