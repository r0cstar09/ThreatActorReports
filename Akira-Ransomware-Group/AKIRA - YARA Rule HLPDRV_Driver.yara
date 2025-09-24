rule Akira_HLPDRV_Driver {
    meta:
        author = "GuidePoint GRIT"
        description = "Detects Akira's malicious hlpdrv.sys driver"
        sha256 = "bd1f381e5a3db22e88776b7873d4d2835e9a1ec620571d2b1da0c58f81c84a56"
    strings:
        $svc = "HlpDrv" ascii wide
        $dev = "\\Device\\KMHLPDRV" ascii wide
        $reg = "SYSTEM\\CurrentControlSet\\Services\\HlpDrv" wide
        $pdb = "hlpdrv.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and pe.is_pe and pe.number_of_sections == 6 and
        3 of ($svc, $dev, $reg, $pdb)
}