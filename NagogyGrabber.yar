rule NagogyGrabber {
    meta:
        author = "Any.RUN"
        reference = "https://twitter.com/MalGamy12/status/1698367753919357255"
        description = "Detects Nagogy Grabber"
        date = "2023-04-04"

        hash1 = "1518a876c87c9189c2fcb29a524aa11bfdc7e6e5d0cac9cc40cd0af1b96b34ae"
        hash2 = "1e828b39b97fa746b4efcb4ceb35c03cabc6134e7d4e3a3cf96e572ddbd465b1"
        hash3 = "28569be03334e7c36e560c9a5a5f18ee3e952274475a8bd00f60c11b2abc4368"
        hash4 = "53fe973fd9a5be2154cf2d21344f3698a192ab238b11995aba8da6ccf9e26f32"
        hash5 = "81f575f131240ba1f4eeabfb721e6e45ef3a560473fe2ac5e9e4917dcc7bf785"
        hash6 = "b41e7a3da1d450dc770072a5c2761af441509e17b7fb704d86fb0049fdade071"
        hash7 = "c78835281b827762c4df1b3d771f81b091743f6d49db03766cc911ddc970586a"

    strings:
        //  _ __   __ _  __ _  ___   __ _ _   _
        // | '_ \ / _` |/ _` |/ _ \ / _` | | | |
        // | | | | (_| | (_| | (_) | (_| | |_| |
        // |_| |_|\__,_|\__, |\___/ \__, |\__, |
        //              |___/       |___/ |___/
        //                  _     _
        //   __ _ _ __ __ _| |__ | |__   ___ _ __
        //  / _` | '__/ _` | '_ \| '_ \ / _ \ '__|
        // | (_| | | | (_| | |_) | |_) |  __/ |
        //  \__, |_|  \__,_|_.__/|_.__/ \___|_|
        //  |___/
        $x1 = {
            20 00 20 00 5f 00 20 00 5f 00 5f 00 20 00 20 00 20 00 5f 00 5f 00
            20 00 5f 00 20 00 20 00 5f 00 5f 00 20 00 5f 00 20 00 20 00 5f 00
            5f 00 5f 00 20 00 20 00 20 00 5f 00 5f 00 20 00 5f 00 20 00 5f 00
            20 00 20 00 20 00 5f 00 20 00 20 00 20 00 0a
        }

        $x2 = "Nagogy grabber - DreamyOak" fullword ascii

        $s1 = "https://discord.com/api/v6/auth/login" fullword ascii
        $s2 = "httpdebuggerui.exe" fullword ascii
        $s3 = "df5serv.exe" fullword ascii
        $s4 = "qemu-ga.exe" fullword ascii
        $s5 = "joeboxcontrol.exe" fullword ascii
        $s6 = "ksdumper.exe" fullword ascii
        $s7 = "SELECT origin_url, action_url, username_value, password_value, date_created, times_used FROM logins" fullword ascii
        $s8 = "Action URL: " fullword ascii
        $s9 = "D:\\NT3X" fullword ascii
        $s10 = "wmic csproduct get uuid" fullword ascii
        $s11 = "====================IP INFO====================" fullword wide

    condition:
        (uint16(0) == 0x5a4d and 1 of ($x*) and filesize < 20MB) or all of ($s*)
}
