from typing import List, Optional

GENERIC_HEURISTIC_ID = 4

SIGNATURE_ATTACK_IDS = {
    "InjectionInterProcess": ["T1055"],
    "process_creation_suspicious_location": ["T1106"],
    "infostealer_browser": ["T1552.001"],
    "recon_fingerprint": ["T1082"],
    "enumerates_running_processes": ["T1057"],
    "process_interest": ["T1057"],
    # Yes I understand that these two are essentially the same
    "injection_createremotethread": ["T1055"],
    "InjectionCreateRemoteThread": ["T1055"],
    "stealth_hidden_extension": ["T1562.006"],
    "dropper": ["T1129"],
    "network_cnc_https_generic": ["T1573"],
    "office_cve2017_11882": ["T1203"],
    "powershell_network_connection": ["T1059.004"],
    "wmi_create_process": ["T1047"],
    "wmi_script_process": ["T1047"],
    "powershell_variable_obfuscation": ["T1059.004"],
    "office_macro_autoexecution": ["T1059.004"],
    "persistence_autorun": ["T1547.001"],
    "persistence_autorun_tasks": ["T1543"],
    "office_martian_children": ["T1059"],
    "office_cve2017_11882_network": ["T1203"],
    "infostealer_ftp": ["T1552.001"],
    "infostealer_im": ["T1005"],
    "spawns_dev_util": ["T1127"],
    "uses_windows_utilities_to_create_scheduled_task": ["T1053"],
    "windows_defender_powershell": ["T1562.001"],
    "pe_compile_timestomping": ["T1070.006"],
    "creates_largekey": ["T1112"],
    "registry_credential_store_access": ["T1003"],
    "powershell_command_suspicious": ["T1059.004"],
    "infostealer_cookies": ["T1539"],
    "infostealer_mail": ["T1005"],
    "recon_programs": ["T1518"],
    "antivm_generic_cpu": ["T1012"],
    "infostealer_bitcoin": ["T1005"],
}

SIGNATURE_TO_CATEGORY = {
    "InjectionInterProcess": "Defense Evasion",
    "process_creation_suspicious_location": "Execution",
    "infostealer_browser": "Credential Access",
    "recon_fingerprint": "Discovery",
    "enumerates_running_processes": "Discovery",
    "process_interest": "Discovery",
    # Yes I understand that these two are essentially the same
    "injection_createremotethread": "Defense Evasion",
    "InjectionCreateRemoteThread": "Defense Evasion",
    "stealth_hidden_extension": "Defense Evasion",
    "dropper": "Execution",
    "network_cnc_https_generic": "Command And Control",
    "office_cve2017_11882": "Execution",
    "powershell_network_connection": "Execution",
    "wmi_create_process": "Execution",
    "wmi_script_process": "Execution",
    "powershell_variable_obfuscation": "Execution",
    "office_macro_autoexecution": "Execution",
    "persistence_autorun": "Persistence",
    "persistence_autorun_tasks": "Persistence",
    "office_martian_children": "Execution",
    "office_cve2017_11882_network": "Execution",
    "infostealer_ftp": "Credential Access",
    "infostealer_im": "Collection",
    "spawns_dev_util": "Defense Evasion",
    "uses_windows_utilities_to_create_scheduled_task": "Execution",
    "windows_defender_powershell": "Defense Evasion",
    "pe_compile_timestomping": "Defense Evasion",
    "creates_largekey": "Defense Evasion",
    "registry_credential_store_access": "Credential Access",
    "powershell_command_suspicious": "Execution",
    "infostealer_cookies": "Credential Access",
    "infostealer_mail": "Collection",
    "recon_programs": "Discovery",
    "antivm_generic_cpu": "Discovery",
    "infostealer_bitcoin": "Collection",
}

CATEGORY_TO_HEUR_ID = {
    "Command And Control": 5,
    "Credential Access": 6,
    "Defense Evasion": 7,
    "Discovery": 8,
    "Execution": 9,
    "Persistence": 10,
    "Collection": 11,
}


def get_heur_id_for_signature_name(sig_name: str) -> Optional[int]:
    category = SIGNATURE_TO_CATEGORY.get(sig_name)
    if not category:
        return GENERIC_HEURISTIC_ID
    else:
        return CATEGORY_TO_HEUR_ID[category]


def get_attack_ids_for_signature_name(sig_name: str) -> List[str]:
    return SIGNATURE_ATTACK_IDS.get(sig_name, [])
