import "dotnet"

rule FakeCheck
{
	meta:
		author = "Any.RUN"
		reference = "https://twitter.com/MalGamy12/status/1701121339061358907"
		description = "Detects FakeCheck Stealer"
		date = "2023-09-11"
		hash1 = "012063e0b7b4f7f3ce50574797112f95492772a9b75fc3d0934a91cc60faa240"

	strings:
		$x1 = "D:\\MyProjects\\SelfTraining\\Csharp\\ReconApp-Final\\ReconApp\\obj\\x64\\Release\\alg.pdb" ascii fullword
		$x2 = "https://tosals.ink/uEH5J.html" wide fullword

		// mistake in "Volume"
		$a1 = "System Volumn Information" wide fullword
		$a2 = "Fatal error" wide fullword
		$a3 = "Please reinstall .net 3.5 first!" wide fullword

		$s1 = "\\AppData\\Local\\Comms" fullword wide
		$s2 = "\\AppData\\Local\\D3DSCache" fullword wide
		$s3 = "\\AppData\\Local\\OneDrive" fullword wide
		$s4 = "\\AppData\\Local\\Packages" fullword wide
		$s5 = "Content-Disposition: form-data; name=\"file\"; filename=\"{1}\"" fullword wide
		$s6 = "Program Files (x86)\\AhnLab" fullword wide
		$s7 = "Total size of drive : {0}" fullword wide
		$s8 = "Available space to current user : {0}" fullword wide

	condition:
		dotnet.is_dotnet and
		/*
		//// for yara version < 4.2.0 ////
		//// don't forget: import "pe" ////
		uint16(0) == 0x5a4d and
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
		pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size != 0 and
		*/
		(
			any of ($x*) or
			2 of ($a*) or
			7 of ($s*)
		)
}
