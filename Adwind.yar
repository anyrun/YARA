rule Adwind_Hunt {
    meta:
        author = "ANY.RUN"
        family = "Adwind"
        description = "Detects Adwind, use with caution, may have False Positives"
        date = "2024-04-26"
    strings:
        $s1 = "META-INF/MANIFEST.MF" ascii
        $class = /[Il]{5,20}\/[Il]{5,20}\/[Il]{5,20}.class/
    condition:
        int16(0) == 0x4B50 
        and all of ($s*) 
        and #class > 100
}
