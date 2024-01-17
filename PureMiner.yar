rule PureMiner {
	meta:
		family = "PureMiner"
		date = "2023-12-20"
		author = "ANY.RUN"
		description = "Detects PureMiner"
	
	strings:
	
	//PureMalware
	
		$dll0 = "Rijndael" wide fullword
		$dll1 = "TripleDES" wide fullword
		$dll2 = "protobuf-net" ascii fullword
		$dll3 = "TripleDESCryptoServiceProvider" ascii fullword
		$dll4 = "MD5CryptoServiceProvider" ascii fullword
		$dll5 = "GZipStream" ascii fullword
	
	//PureMiner
	
		$dll6 = "Microsoft.Win32.TaskScheduler" ascii
		
		$s0 = "hardware" ascii
		$s1 = "Sensors" ascii
		$s2 = "Voltage" ascii
		$s3 = "pciBusId" ascii
		$s4 = "Power" ascii
		$s5 = "memoryInfo" ascii
		$s6 = "devicee" ascii
		$s7 = "versionInfo" ascii
		$s8 = "performanceStatus" ascii
		$s9 = "iAdapterIndex" ascii
		$s10 = "MIXED_TARGET_TYPES" fullword ascii 
		$s11 = "TEMPERATURE_CPU" fullword ascii 
		$s12 = "TEMPERATURE_GFX" fullword ascii 
		$s13 = "TEMPERATURE_VRMVDD" fullword ascii
		$s14 = "TEMPERATURE_MEM" fullword ascii 
		$s15 = "TEMPERATURE_VRMVDD1" fullword ascii 
		$s16 = "TEMPERATURE_SOC" fullword ascii 
		$s17 = "TEMPERATURE_VRSOC" fullword ascii 
		$s18 = "TEMPERATURE_EDGE" fullword ascii 
		$s19 = "TEMPERATURE_VRVDDC" fullword ascii 
		$s20 = "TEMPERATURE_VRMVDD0" fullword ascii 
      
	condition:
	    
	uint16(0) == 0x5a4d and 5 of ($dll*) and 15 of ($s*)
		
}



