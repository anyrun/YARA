rule Agniane
{
    meta:
        author = "Any.RUN"
        reference = "https://twitter.com/MalGamy12/status/1703004559440769332"
        description = "Detects Agniane Stealer"
        date = "2023-09-20"
        hash1 = "abce9c19df38717374223d0c45ce2d199f77371e18f9259b9b145fe8d5a978af"

    strings:
        $x1 = "Agniane Stealer" wide nocase
        $x2 = "obj\\Release\\Agniane.pdb" ascii fullword

        $s1 = "System.Data.SQLite" wide
        $s2 = "Start collecting cookies from browsers" wide
        $s3 = "Start collecting files from Desktop and Documents" wide
        $s4 = "We start collecting a Telegram and Kotatogram sessions" wide
        $s5 = "Collection of cookies is complete. Total cookie lines:" wide
        $s6 = "ExecLogging" ascii fullword
        $s7 = "Execution Log.txt" wide fullword

    condition:
        uint16(0) == 0x5A4D and filesize < 600KB
            and
        (
            any of ($x*)
                or
            5 of ($s*)
        )

}