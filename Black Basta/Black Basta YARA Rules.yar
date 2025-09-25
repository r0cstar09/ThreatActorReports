rule Ransomware_BlackBasta {
  meta:
    description = "Detects Black Basta ransomware by strings"
  strings:
    $s1 = "Your network is encrypted by the Black Basta group" ascii
    $s2 = ".basta" wide ascii  // extension
    $s3 = "vssadmin.exe delete shadows" ascii  // behavior
  condition:
    ($s1 or $s2) and $s3
}