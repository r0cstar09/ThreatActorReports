rule BlackBasta_Ransomware {
   meta:
      author = "ThreatIntelTeam"
      description = "Detects Black Basta ransomware by file patterns and strings"
      hash = "example"  # replace with actual known hash if available
   strings:
      $ext = ".basta" ascii
      $msg = "Your network is encrypted by the Black Basta group" wide ascii
      $wall = "readme.txt" ascii
      $vss = "vssadmin.exe Delete Shadows" ascii
      $safe = "bcdedit /set {default} safeboot" ascii
   condition:
      uint16(0) == 0x5A4D and 5 of ($ext, $msg, $wall, $vss, $safe)
}