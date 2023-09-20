rule Exela
{
    meta:
        author = "Any.RUN"
        reference = "https://twitter.com/MalGamy12/status/1703704904039047273"
        description = "Detects Exela Stealer"
        date = "2023-09-20"
        hash1 = "bf5d70ca2faf355d86f4b40b58032f21e99c3944b1c5e199b9bb728258a95c1b"
        hash2 = "e9e59ca2c8e786f92e81134f088ea08c53fc4c8c252871613ccc51b473814633"

    strings:
        $x1 = "Exela Stealer" wide nocase
        $x2 = "Exela\\Exela\\obj\\Release\\Exela.pdb" ascii fullword

        $s1 = "discord.com/api/webhooks" wide
        $s2 = "wifi.txt" wide
        $s3 = "network.txt" wide
        $s4 = "Autofills.txt" wide
        $s5 = "Downloads.txt" wide
        $s6 = "Cookies.txt" wide
        $s7 = "Passwords.txt" wide
        $s8 = "Cards.txt" wide
        $s9 = "Mutex already exist." wide
        $s10 = "All User Profile\\s*: (.*)" wide    
        $s11 = "Key Content\\s*: (.*)" wide

    condition:
        uint16(0) == 0x5A4D and filesize < 400KB
            and
        (
            any of ($x*)
                or
            all of ($s*)
        )

}