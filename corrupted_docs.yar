rule corrupted_docs
{
    meta:
        description = "Detects corrupted docs with self-repair mechanisms"
        author = "ANY.RUN"
        date = "2024-11-21"

        hash1 = "f967b0af99a2dd9f2819e27234e866990b0e330303f85c11fcb98d2577f583a2"
        hash2 = "436a5d522698a7669a40b797905226e1c84a4511a7aa295ca3d5eef6d7226c1a"
        hash3 = "a7bab58b509ea23c462cc13aa5b0db6e92554837e82122853f678c505511f94a"

        url1 = "https://app.any.run/tasks/b4f1a0c7-06bd-4cf7-91b6-2e6cdd0ce6e7"
        url2 = "https://app.any.run/tasks/1b1af07e-923a-4977-8bd5-72997b120360"
        url3 = "https://app.any.run/tasks/14438327-c26b-44ec-a0d0-587cb29ae810"

    strings:
        $bytes = {50 4B 03 04 14} //Original PK signature

    condition:
        uint32(0)== 0x90c34b50 //Fake PK signature
        and $bytes
}
