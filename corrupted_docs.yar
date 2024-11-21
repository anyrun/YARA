rule corrupted_docs
{
    meta:
	description = "Detects corrupted docs"
	author = "ANY.RUN"
	date = "2024-11-21"

    strings:
	$bytes = {50 4B 03 04 14} //Original PK signature

    condition:
	uint32(0)== 0x90c34b50 //Fake PK signature
	and $bytes
}
