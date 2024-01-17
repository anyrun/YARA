rule PureCrypter {
	meta:
		family = "PureCrypter"
		date = "2023-11-28"
		author = "ANY.RUN"
        	description = "Detects PureCrypter"
	
	strings:
	
		$dll0 = "Rijndael" wide fullword
		$dll1 = "protobuf-net" ascii fullword
		$dll2 = "MD5CryptoServiceProvider" ascii fullword
		$dll3 = "GZipStream" ascii fullword
		
		$s1 = "#Powered by SmartAssembly" ascii 
		$s2 = "aspnet_wp.exe" wide fullword
		$s3 = "w3wp.exe" wide fullword
		$s4 = "{11111-22222-40001-00002}" wide fullword
		$s5 = "{11111-22222-40001-00001}" wide fullword
		$s6 = "ResourceManager" ascii
		
		$chunk = {73 ?? ?? 00 06 28 ?? ?? 00 06 28 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 28 ?? ?? 00 06 73 ?? ?? 00 06 28 ?? ?? 00 06 2A}
		
	condition:
	 uint16(0) == 0x5a4d and 3 of ($s*) 
	 	and 
	 (
	 	3 of ($dll*) 
	 		or 
	 	($chunk and 4 of ($dll*))
	 )
		
}

