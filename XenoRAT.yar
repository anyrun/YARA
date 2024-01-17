rule XenoRAT {
   meta:
      description = "Detects XenoRAT"
      author = "Any.Run"
      reference = "https://github.com/moom825/xeno-rat"
      date = "2024-01-13"
      
      hash1 = "AA28B0FF8BADF57AAEEACD82F0D8C5FBBD28008449A3075D8A4DA63890232418"
      hash2 = "34AB005B549534DBA9A83D9346E1618A18ECEE2C99A93079551634F9480B2B79"
      hash3 = "99C24686E9AC15EC6914D314A1D72DD9A1EBECE08FD1B8A75E00373051E82079"
      
      url1 = "https://app.any.run/tasks/ca9ee9db-760f-40cb-b1ad-5210cc2b972e"
      url2 = "https://app.any.run/tasks/4bf50208-0a9d-4c39-9a53-82a417ebac4d"
      url3 = "https://app.any.run/tasks/efcd6fc0-75a4-4628-b367-9a17e4254834"

   strings:
      $x1 = "xeno rat client" ascii wide
      $x2 = "xeno_rat_client" ascii
      $x3 = "%\\XenoManager\\" fullword wide
      $x4 = "XenoUpdateManager" fullword wide
      $x5 = "RecvAllAsync_ddos_unsafer" ascii

      $s1 = "SELECT * FROM AntivirusProduct" fullword wide
      $s2 = "SELECT * FROM Win32_OperatingSystem" fullword wide
      $s3 = "WindowsUpdate" fullword wide
      $s4 = "HWID" fullword ascii
      $s5 = "AddToStartupNonAdmin" ascii
      $s6 = "CreateSubSock" ascii
      $s7 = "Badapplexe Executor from github important" fullword wide
      $s8 = "mutex_string" fullword ascii
      $s9 = "_EncryptionKey" fullword ascii
      $s10 = "/query /v /fo csv" fullword wide
      $s11 = "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>" wide
      $s12 = "/C choice /C Y /N /D Y /T 3 & Del \"" fullword wide
      

   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      (1 of ($x*) or 7 of them)
}


rule XenoRAT_server {
   meta:
      description = "Detects XenoRAT server"
      author = "Any.Run"
      reference = "https://github.com/moom825/xeno-rat"
      date = "2024-01-17"
      
      hash1 = "020D6667BE8E017E0B432B228A9097CFFE9E5CA248EECAF566151E4E2BD7195B" 
      hash2 = "B61E4D30AF50474AED593EC748E4A88875A7B492A319EDC2FD44B9F51B094769"
           
      url1 = "https://app.any.run/tasks/95ab175f-88d8-4e9e-9283-8e0fe2a7335c"
      url2 = "https://app.any.run/tasks/b6ad1585-e5e8-49f5-bc36-7fd91e8c9fd8"
      
   strings:
      $x1 = "The name of this tool is xeno-rat. Why is it called that? Well, to be honest, it just sounded nice." ascii fullword
      $x2 = "xeno_rat_server" ascii
      $x3 = "xeno rat server" ascii wide
      $x4 = "Xeno-rat: Created by moom825" wide fullword

      $s1 = "C:\\Windows\\System32\\rundll32.exe shell32.dll,#61" fullword wide
      $s2 = "Hvnc_Load" fullword ascii
      $s3 = "KeyLogger_Load" fullword ascii
      $s4 = "Live Microphone" fullword wide
      $s5 = "Windir + Disk Cleanup" fullword wide
      $s6 = "Uac Bypass" fullword wide
      $s7 = "Current Password: 1234" fullword wide
      $s8 = "plugins\\Hvnc.dll" fullword wide
      $s9 = "hidden_desktop" fullword wide
      $s10 = "moom825" ascii
      
      
   condition:
      uint16(0) == 0x5a4d and
      (1 of ($x*) or 7 of ($s*))
}


