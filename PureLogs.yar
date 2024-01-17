rule PureLogs {
	meta:
		family = "PureLogs"
		date = "2023-12-14"
		author = "ANY.RUN"
		description = "Detects PureLogs"
		
	strings:
	
		$dll = "ClassLibrary1.dll" wide fullword
		
		$dll0 = "Rijndael" wide fullword
		$dll1 = "TripleDES" wide fullword
		$dll2 = "protobuf-net" ascii fullword
		$dll3 = "TripleDESCryptoServiceProvider" ascii fullword
		$dll4 = "MD5CryptoServiceProvider" ascii fullword
		$dll5 = "GZipStream" ascii fullword
		$dll6 = "get_Jpeg" ascii fullword
		
		$name_class = "PlgCore" ascii fullword
		
		$chunk0 = {02 28 ?? ?? 00 06 74 ?? ?? 00 02 0A 06 6f ?? ?? 00 06 80 ?? ?? 00 04 06 6f ?? ?? 00 06 2C 16 06 6f ?? ?? 00 06 80 ?? ?? 00 04 06 6f ?? ?? 00 06 80 ?? ?? 00 04}
		$chunk1 = {06 73 ?? ?? 00 06 25 14 fe ?? ?? 02 00 06 73 ?? ?? 00 0A 7d ?? ?? 00 04 06 28 ?? ?? 00 06 6f ?? ?? 00 06}
	
	condition:
	uint16(0) == 0x5a4d and all of them	
}


