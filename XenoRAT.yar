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
      (1 of ($x*) or 1 of them)
}

