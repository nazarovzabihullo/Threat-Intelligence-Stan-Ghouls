/*
   YARA Rule: APT_StanGhouls_NetSupport_Campaign
   Author: Nazarov Zabihullo (@Nazarov_Zabihullo)
   Description: Detects artifacts, scripts, and configurations associated with Stan Ghouls (Bloody Wolf) NetSupport RAT campaign targeting Uzbekistan.
   Reference: https://securelist.com/stan-ghouls-in-uzbekistan/118738/
   Date: 2026-10-14
   TLP: CLEAR
*/

rule APT_StanGhouls_NetSupport_Artifacts {
    meta:
        author = "Nazarov Zabihullo"
        description = "Detects Stan Ghouls persistence scripts, decoy PDF references, and NetSupport config markers"
        date = "2026-10-14"
        reference = "https://thehackernews.com/2025/11/bloody-wolf-expands-java-based.html"
        threat_actor = "Stan Ghouls / Bloody Wolf"
        malware_family = "NetSupport RAT"
        tlp = "CLEAR"
        hash_jar = "95db93454ec1d581311c832122d21b20"
        hash_lure_pdf = "7556e2f5a8f7d7531f28508f718cb83d"

    strings:
        // Lure document artifact
        $decoy_pdf = "E-SUD_705306256_ljro_varaqasi.pdf" ascii wide nocase
        
        // Persistence script artifacts
        $bat_startup = "SoliqUZ_Run.bat" ascii wide nocase
        $bat_run = "run.bat" ascii wide nocase
        $bat_install = "bat_install.bat" ascii wide nocase
        
        // NetSupport core components
        $ns_client = "client32.exe" ascii wide nocase
        $ns_ini = "client32.ini" ascii wide nocase
        $ns_lic = "NSM.lic" ascii wide nocase
        $ns_dll1 = "PCICHEK.DLL" ascii wide nocase
        $ns_dll2 = "HTCTL32.DLL" ascii wide nocase

        // Persistence commands / registry
        $reg_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $schtask_cmd = "schtasks /TN malicious /TR run.bat /SC ONLOGON" ascii wide nocase

    condition:
        $decoy_pdf or
        $bat_startup or
        $schtask_cmd or
        (2 of ($bat_*) and 2 of ($ns_*)) or
        (3 of ($ns_*) and $reg_key)
}

rule APT_StanGhouls_NetSupport_ClientConfig {
    meta:
        author = "Nazarov Zabihullo"
        description = "Detects NetSupport client32.ini configuration tied to Stan Ghouls C2 infrastructure"
        date = "2026-10-14"
        tlp = "CLEAR"
        hash_ini_a = "edfb8d26fa34436f2e92d5be1cb5901b"
        hash_ini_b = "3e86f6fc7ed037f3c9560cc59aa7aacc"
        hash_ini_c = "ae4d6812f5638d95a82b3fa3d4f92861"

    strings:
        $sec_header = "[Client]" ascii wide nocase
        $c2_param = "Gateway=" ascii wide nocase
        $c2_domain1 = "xoomep1.com" ascii wide nocase
        $c2_domain2 = "xoomep2.com" ascii wide nocase
        $c2_domain3 = "golden-scalen.com" ascii wide nocase
        $c2_port = "1935" ascii wide

    condition:
        $sec_header and $c2_param and (any of ($c2_domain*) or $c2_port)
}
