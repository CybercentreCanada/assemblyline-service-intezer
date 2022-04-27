from ipaddress import ip_address, ip_network, IPv4Network
import json
import re
from requests import HTTPError
from typing import Any, Dict, List, Optional, Union

from intezer_sdk.api import IntezerApi
from intezer_sdk.consts import OnPremiseVersion, BASE_URL, API_VERSION
from signatures import get_attack_ids_for_signature_name, get_heur_id_for_signature_name, GENERIC_HEURISTIC_ID

from assemblyline.common.net_static import TLDS_ALPHA_BY_DOMAIN
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import DOMAIN_REGEX, IP_REGEX, FULL_URI, URI_PATH, DOMAIN_ONLY_REGEX

from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

global_safelist: Optional[Dict[str, Dict[str, List[str]]]] = None

# Custom regex for finding uris in a text blob
URL_REGEX = re.compile(
    "(?:(?:(?:[A-Za-z]*:)?//)?(?:\S+(?::\S*)?@)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?)(?:[/?#][^\s,\\\\]*)?")


UNINTERESTING_ANALYSIS_KEYS = [
    "analysis_url",
    "is_private",
    "sha256",
    "verdict",
    "analysis_id",
    "family_id",
]
UNINTERESTING_SUBANALYSIS_KEYS = [
    "source",
    "file_type",
    "md5",
    "sha1",
    "sha256",
    "size_in_bytes",
    "ssdeep",
]
UNINTERESTING_FAMILY_KEYS = ["family_id"]

MALICIOUS = "malicious"
KNOWN_MALICIOUS = "known_malicious"
MALICIOUS_VERDICTS = [MALICIOUS, KNOWN_MALICIOUS]
SUSPICIOUS = "suspicious"
UNKNOWN = "unknown"
TRUSTED = "trusted"
INTERESTING_VERDICTS = [MALICIOUS, KNOWN_MALICIOUS, SUSPICIOUS]
UNINTERESTING_VERDICTS = [UNKNOWN, TRUSTED]

IP = "ip"
DOMAIN = "domain"
NETWORK_IOC_TYPES = [IP, DOMAIN]

FAMILIES_TO_NOT_TAG = ["application", "library"]
MALICIOUS_FAMILY_TYPES = ["malware"]
SUSPICIOUS_FAMILY_TYPES = ["administration_tool", "installer", "packer"]

TTP_SEVERITY_TRANSLATION = {
    1: 10,
    2: 100,
    3: 250
}

FALSE_POSITIVE_DOMAINS_FOUND_IN_PATHS = ["microsoft.net"]

SILENT_SIGNATURES = ["enumerates_running_processes"]


class IntezerDynamic(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self.log.debug("Initializing the IntezerDynamic service...")
        self.client: Optional[IntezerApi] = None

    def start(self) -> None:
        global global_safelist
        self.log.debug("IntezerDynamic service started...")
        self.client = IntezerApi(
            api_version=self.config.get("api_version", API_VERSION),
            api_key=self.config["api_key"],
            base_url=self.config.get("base_url", BASE_URL),
            on_premise_version=OnPremiseVersion.V21_11 if self.config["is_on_premise"] else None
        )
        try:
            global_safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")

    def stop(self) -> None:
        self.log.debug("IntezerDynamic service ended...")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        so = SandboxOntology()

        sha256 = request.sha256

        main_api_result = self.client.get_latest_analysis(
            file_hash=sha256, private_only=self.config["private_only"]
        )

        if not main_api_result:
            # TODO: Make dynamic
            # resp = self.client.analyze_by_file(request.file_path, request.file_name)

            request.result = result
            return

        analysis_id = main_api_result["analysis_id"]

        main_kv_section = ResultKeyValueSection("IntezerDynamic analysis report")
        processed_main_api_result = self.process_details(
            main_api_result.copy(), UNINTERESTING_ANALYSIS_KEYS
        )
        main_kv_section.update_items(processed_main_api_result)
        if "family_name" in main_api_result:
            main_kv_section.add_tag(
                "attribution.family", main_api_result["family_name"]
            )

        self.set_heuristic_by_verdict(main_kv_section, main_api_result["verdict"])

        file_verdict_map = {}
        self.process_iocs(analysis_id, file_verdict_map, main_kv_section)
        self.process_ttps(analysis_id, main_kv_section)

        try:
            sub_analyses = self.client.get_sub_analyses_by_id(analysis_id)
        except HTTPError as e:
            self.log.debug(
                f"Unable to get sub_analyses for SHA256 {sha256} due to {e}"
            )
            sub_analyses = []

        can_we_get_strings = True
        can_we_download_files = True
        process_path_set = set()
        command_line_set = set()
        for sub in sub_analyses:
            sub_analysis_id = sub["sub_analysis_id"]
            code_reuse = self.client.get_sub_analysis_code_reuse_by_id(
                analysis_id, sub_analysis_id
            )

            if code_reuse:
                families = code_reuse.pop("families", None)
            else:
                families = []
            extraction_info = sub.pop("extraction_info", None)
            # Processes is only present when the sample has undergone dynamic execution
            if extraction_info and "processes" not in extraction_info:
                extraction_info = None

            if not families and not extraction_info:
                # Otherwise, boring!
                continue

            if can_we_get_strings:
                # TODO: This may be not useful in Assemblyline's context
                try:
                    strings = self.client.get_strings_by_id(analysis_id, sub_analysis_id)
                    print(strings)
                except HTTPError as e:
                    # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
                    self.log.debug(
                        f"Unable to get strings for SHA256 {sub['sha256']} due to {e}"
                    )
                    strings = None
                    can_we_get_strings = False

            try:
                capabilities = self.client.get_sub_analysis_capabilities_by_id(analysis_id, sub_analysis_id)
                print(capabilities)
            except HTTPError as e:
                self.log.debug(
                    f"Unable to get capabilities for SHA256 {sub['sha256']} due to {e}"
                )

            extraction_method = sub["source"].replace("_", " ")

            if extraction_method != "root":
                title_text = f"Subanalysis report for {sub['sha256']}, extracted via {extraction_method}"
            else:
                title_text = f"Subanalysis report for {sub['sha256']}"

            sub_kv_section = ResultKeyValueSection(title_text)

            metadata = self.client.get_sub_analysis_metadata_by_id(
                analysis_id, sub_analysis_id
            )
            processed_subanalysis = self.process_details(
                metadata.copy(), UNINTERESTING_SUBANALYSIS_KEYS
            )
            sub_kv_section.update_items(processed_subanalysis)
            main_kv_section.add_subsection(sub_kv_section)

            if code_reuse:
                code_reuse_kv_section = ResultKeyValueSection(
                    "Code reuse detected"
                )
                code_reuse_kv_section.update_items(code_reuse)
                sub_kv_section.add_subsection(code_reuse_kv_section)

            if families:
                family_section = ResultTableSection("Family Details")
                for family in families:
                    processed_family = self.process_details(
                        family.copy(), UNINTERESTING_FAMILY_KEYS
                    )
                    family_section.add_row(TableRow(**processed_family))
                    if family["family_type"] not in FAMILIES_TO_NOT_TAG:
                        family_section.add_tag("attribution.family", family["family_name"])

                    # Overwrite value if not malicious
                    if family["family_type"] in MALICIOUS_FAMILY_TYPES and (sub["sha256"] not in file_verdict_map or file_verdict_map[sub["sha256"]] != MALICIOUS):
                        file_verdict_map[sub["sha256"]] = MALICIOUS

                    # Only overwrite value if value is not already malicious
                    elif family["family_type"] in SUSPICIOUS_FAMILY_TYPES and (sub["sha256"] not in file_verdict_map or file_verdict_map[sub["sha256"]] not in MALICIOUS_VERDICTS):
                        file_verdict_map[sub["sha256"]] = SUSPICIOUS

                sub_kv_section.add_subsection(family_section)

            if extraction_info:
                for item in extraction_info["processes"]:
                    p = so.create_process(
                        pid=item["process_id"],
                        image=item["process_path"],
                        ppid=item["parent_process_id"],
                    )
                    process_path_set.add(item["process_path"])
                    so.add_process(p)

                    if item["process_path"] != item["module_path"]:
                        self.log.debug(
                            f"Investigate! process_path: {item['process_path']} != module_path: {item['module_path']}"
                        )
                        process_path_set.add(item["module_path"])
                        command_line = f"{item['process_path']} {item['module_path']}"
                        command_line_set.add(command_line)
                        so.update_process(
                            command_line=command_line,
                            pid=item["process_id"],
                            start_time=float("-inf")
                        )

            if sub["sha256"] != sha256:
                self.set_heuristic_by_verdict(
                    sub_kv_section, file_verdict_map.get(sub["sha256"])
                )

                if can_we_download_files:
                    try:
                        self.client.download_file_by_sha256(
                            sub["sha256"], self.working_directory
                        )
                        path = f"{self.working_directory}/{sub['sha256']}.sample"
                        request.add_extracted(
                            path,
                            f"{sub['sha256']}.sample",
                            f"Extracted via {extraction_method}",
                        )
                    except HTTPError as e:
                        # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
                        self.log.debug(
                            f"Unable to download file for SHA256 {sub['sha256']} due to {e}"
                        )
                        can_we_download_files = False

        process_tree_section = so.get_process_tree_result_section()
        for process_path in process_path_set:
            process_tree_section.add_tag("dynamic.process.file_name", process_path)
        for command_line in command_line_set:
            process_tree_section.add_tag("dynamic.process.command_line", command_line)
        if process_tree_section.body:
            main_kv_section.add_subsection(process_tree_section)

        result.add_section(main_kv_section)
        request.result = result

    @staticmethod
    def process_details(
        details: Dict[str, str], uninteresting_keys: List[str]
    ) -> Dict[str, str]:
        """
        This method removes uninteresting details from a given dictionary
        :param details: The dictionary possibly containing uninteresting details
        :param uninteresting_keys: A list of keys for uninteresting details
        :return: A dictionary only containing interesting information
        """
        for key in list(details.keys()):
            if key in uninteresting_keys:
                details.pop(key, None)
        return details

    def set_heuristic_by_verdict(
        self, result_section: ResultSection, verdict: Optional[str]
    ) -> None:
        """
        This method sets the heuristic of the result section based on the verdict
        :param result_section: The result section that will have its heuristic set
        :param verdict: The verdict of the file
        :return: None
        """
        if not verdict:
            return

        if (
            verdict not in INTERESTING_VERDICTS
            and verdict not in UNINTERESTING_VERDICTS
        ):
            self.log.debug(f"{verdict} was spotted. Is this useful?")
        elif verdict in MALICIOUS_VERDICTS:
            result_section.set_heuristic(1)
        elif verdict == SUSPICIOUS:
            result_section.set_heuristic(2)
        elif verdict == TRUSTED:
            self.log.debug("The verdict was TRUSTED. Can we do something with this?")

    def process_iocs(
        self,
        analysis_id: str,
        file_verdict_map: Dict[str, str],
        parent_result_section: ResultSection,
    ) -> None:
        """
        This method retrieves and parses IOCs for an analysis
        :param analysis_id: The ID for the analysis which we will be retrieving
        :param file_verdict_map: A map of sha256s representing a file's
        contents, and the verdict for that file
        :param parent_result_section: The result section that the network
        result section will be added to, if applicable
        :return: None
        """
        try:
            iocs = self.client.get_iocs(analysis_id)
        except HTTPError as e:
            # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
            self.log.debug(
                f"Unable to retrieve IOCs for analysis ID {analysis_id} due to {e}"
            )
            iocs = {"files": [], "network": []}

        file_iocs = iocs["files"]
        network_iocs = iocs["network"]

        if file_iocs:
            for file in file_iocs:
                file_verdict_map[file["sha256"]] = file["verdict"]

        if network_iocs:
            network_section = ResultTextSection("Network Communication Observed")
            for network in network_iocs:
                ioc = network["ioc"]
                type = network["type"]
                if type == IP:
                    network_section.add_tag("network.dynamic.ip", ioc)
                elif type == DOMAIN:
                    network_section.add_tag("network.dynamic.domain", ioc)
                elif type not in NETWORK_IOC_TYPES:
                    self.log.debug(
                        f"The network IOC type of {type} is not in {NETWORK_IOC_TYPES}. Network item: {network}"
                    )
                network_section.add_line(f"IOC: {ioc}")
            parent_result_section.add_section(network_section)

    def process_ttps(
        self,
        analysis_id: str,
        parent_result_section: ResultSection,
    ) -> None:
        """
        This method retrieves and parses TTPs for an analysis
        :param analysis_id: The ID for the analysis which we will be retrieving
        :param file_verdict_map: A map of sha256s representing a file's
        contents, and the verdict for that file
        :param parent_result_section: The result section that the network
        result section will be added to, if applicable
        :return: None
        """
        # Note: These TTPs are essentially signatures
        try:
            ttps = self.client.get_dynamic_ttps(analysis_id)
        except HTTPError as e:
            # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
            self.log.debug(
                f"Unable to retrieve TTPs for analysis ID {analysis_id} due to {e}"
            )
            ttps = []

        if not ttps:
            return

        sigs_res = ResultSection("Signatures")
        for ttp in ttps:
            sig_name = ttp['name']
            sig_res = ResultTextSection(f"Signature: {sig_name}")
            sig_res.add_line(ttp['description'])

            heur_id = get_heur_id_for_signature_name(sig_name)
            if heur_id == GENERIC_HEURISTIC_ID:
                self.log.debug(f"{sig_name} does not have a category assigned to it")

            sig_res.set_heuristic(heur_id)
            sig_res.heuristic.add_signature_id(sig_name, TTP_SEVERITY_TRANSLATION[ttp['severity']])

            for aid in get_attack_ids_for_signature_name(sig_name):
                sig_res.heuristic.add_attack_id(aid)

            if sig_name in SILENT_SIGNATURES:
                sigs_res.add_subsection(sig_res)
                continue

            ioc_table = ResultTableSection("IOCs found in signature marks")

            for item in ttp['data']:
                # Assuming that all items are single key value pairs,
                key = next((key for key in item.keys()), "")
                if not key:
                    continue
                value = item[key]
                if not value:
                    continue

                if key in ["IP"] and not add_tag(sig_res, "network.dynamic.ip", value):
                    _extract_iocs_from_text_blob(value, ioc_table)
                elif key in ["command", "cmdline"]:
                    _ = add_tag(sig_res, "dynamic.process.command_line", value)
                    _extract_iocs_from_text_blob(value, ioc_table)
                elif key in ["DeletedFile", "file", "binary", "copy", "service path", "office_martian"]:
                    _ = add_tag(sig_res, "dynamic.process.file_name", value)
                elif key in ["http_request", "url", "suspicious_request", "network_http", "request", "http_downloadurl"]:
                    _extract_iocs_from_text_blob(value, ioc_table)
                elif key in ["key"]:
                    _ = add_tag(sig_res, "dynamic.registry_key", value)
                elif key in ["domain"]:
                    _ = add_tag(sig_res, "network.dynamic.domain", value)
                else:
                    pass
                if len(value) > 512:
                    value = value[:512] + "..."
                sig_res.add_line(f"\t{key}: {value}")

            if ioc_table.body:
                sig_res.add_subsection(ioc_table)

            sigs_res.add_subsection(sig_res)

        if sigs_res.subsections:
            parent_result_section.add_subsection(sigs_res)


def _extract_iocs_from_text_blob(
        blob: str, result_section: ResultTableSection, so_sig: SandboxOntology.Signature = None) -> None:
    """
    This method searches for domains, IPs and URIs used in blobs of text and tags them
    :param blob: The blob of text that we will be searching through
    :param result_section: The result section that that tags will be added to
    :param so_sig: The signature for the Sandbox Ontology
    :return: None
    """
    if not blob:
        return
    blob = blob.lower()
    ips = set(re.findall(IP_REGEX, blob))
    # There is overlap here between regular expressions, so we want to isolate domains that are not ips
    domains = set(re.findall(DOMAIN_REGEX, blob)) - ips
    # There is overlap here between regular expressions, so we want to isolate uris that are not domains
    uris = set(re.findall(URL_REGEX, blob)) - domains - ips
    for ip in ips:
        if add_tag(result_section, "network.dynamic.ip", ip):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="ip", ioc=ip))
            elif json.dumps({"ioc_type": "ip", "ioc": ip}) not in result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="ip", ioc=ip))
            if so_sig:
                so_sig.add_subject(ip=ip)
    for domain in domains:
        # File names match the domain and URI regexes, so we need to avoid tagging them
        # Note that get_tld only takes URLs so we will prepend http:// to the domain to work around this
        if domain in FALSE_POSITIVE_DOMAINS_FOUND_IN_PATHS:
            continue
        tld = next((tld.lower() for tld in TLDS_ALPHA_BY_DOMAIN if domain.lower().endswith(f".{tld}".lower())), None)
        if tld is None:
            continue
        if add_tag(result_section, "network.dynamic.domain", domain):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="domain", ioc=domain))
            elif json.dumps({"ioc_type": "domain", "ioc": domain}) not in result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="domain", ioc=domain))
            if so_sig:
                so_sig.add_subject(domain=domain)

    for uri in uris:
        if add_tag(result_section, "network.dynamic.uri", uri):
            if not result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="uri", ioc=uri))
            elif json.dumps({"ioc_type": "uri", "ioc": uri}) not in result_section.section_body.body:
                result_section.add_row(TableRow(ioc_type="uri", ioc=uri))
            if so_sig:
                so_sig.add_subject(uri=uri)
        if "//" in uri:
            uri = uri.split("//")[1]
        for uri_path in re.findall(URI_PATH, uri):
            if add_tag(result_section, "network.dynamic.uri_path", uri_path):
                if not result_section.section_body.body:
                    result_section.add_row(TableRow(ioc_type="uri_path", ioc=uri_path))
                elif json.dumps({"ioc_type": "uri_path", "ioc": uri_path}) not in result_section.section_body.body:
                    result_section.add_row(TableRow(ioc_type="uri_path", ioc=uri_path))

def add_tag(
        result_section: ResultSection, tag: str, value: Union[Any, List[Any]]) -> bool:
    """
    This method adds the value(s) as a tag to the ResultSection. Can take a list of values or a single value.
    :param result_section: The ResultSection that the tag will be added to
    :param tag: The tag type that the value will be tagged under
    :param value: The value, a single item or a list, that will be tagged under the tag type
    :return: Tag was successfully added
    """
    tags_were_added = False
    if not value:
        return tags_were_added
    if type(value) == list:
        for item in value:
            # If one tag is added, then return True
            tags_were_added = _validate_tag(result_section, tag, item) or tags_were_added
    else:
        tags_were_added = _validate_tag(result_section, tag, value)
    return tags_were_added

def _validate_tag(result_section: ResultSection, tag: str, value: Any) -> bool:
    """
    This method validates the value relative to the tag type before adding the value as a tag to the ResultSection.
    :param result_section: The ResultSection that the tag will be added to
    :param tag: The tag type that the value will be tagged under
    :param value: The item that will be tagged under the tag type
    :return: Tag was successfully added
    """
    reg_to_match: Optional[str] = None
    if "domain" in tag:
        reg_to_match = DOMAIN_ONLY_REGEX
    elif "uri_path" in tag:
        reg_to_match = URI_PATH
    elif "uri" in tag:
        reg_to_match = FULL_URI
    elif "ip" in tag:
        if not is_ip(value):
            return False
        reg_to_match = IP_REGEX
    if reg_to_match and not re.match(reg_to_match, value):
        return False

    if not is_safelisted(value, [tag], global_safelist):
        # if "uri" is in the tag, let's try to extract its domain/ip and tag it.
        if "uri" in tag:
            # First try to get the domain
            domain = re.search(DOMAIN_REGEX, value)
            if domain:
                domain = domain.group()
                if domain in FALSE_POSITIVE_DOMAINS_FOUND_IN_PATHS:
                    pass
                else:
                    tld = next((tld.lower()
                                for tld in TLDS_ALPHA_BY_DOMAIN if domain.lower().endswith(f".{tld}".lower())), None)
                    if tld is None:
                        pass
                    elif not is_safelisted(value, ["network.dynamic.domain"], global_safelist):
                        result_section.add_tag("network.dynamic.domain", safe_str(domain))
            # Then try to get the IP
            ip = re.search(IP_REGEX, value)
            if ip:
                ip = ip.group()
                if not is_safelisted(value, ["network.dynamic.ip"], global_safelist):
                    result_section.add_tag("network.dynamic.ip", safe_str(ip))

            if value not in [domain, ip]:
                result_section.add_tag(tag, safe_str(value))
        else:
            result_section.add_tag(tag, safe_str(value))

        return True

def is_safelisted(
        value: str, tags: List[str],
        safelist: Dict[str, Dict[str, List[str]]],
        substring: bool = False) -> bool:
    """
    Safelists of data that may come up in analysis that is "known good", and we can ignore in the Assemblyline report.
    This method determines if a given value has any safelisted components
    See README section on Assemblyline System Safelist on how to integrate the safelist found in al_config/system_safelist.yaml
    :param value: The value to be checked if it has been safelisted
    :param tags: The tags which will be used for grabbing specific values from the safelist
    :param safelist: The safelist containing matches and regexs
    :param substring: A flag that indicates if we should check if the value is contained within the match
    :return: A boolean indicating if the value has been safelisted
    """
    if not value or not tags or not safelist:
        return False

    if not any(key in safelist for key in ["match", "regex"]):
        return False

    safelist_matches = safelist.get("match", {})
    safelist_regexes = safelist.get("regex", {})

    for tag in tags:
        if tag in safelist_matches:
            for safelist_match in safelist_matches[tag]:
                if value.lower() == safelist_match.lower():
                    return True
                elif substring and safelist_match.lower() in value.lower():
                    return True

        if tag in safelist_regexes:
            for safelist_regex in safelist_regexes[tag]:
                if re.match(safelist_regex, value, re.IGNORECASE):
                    return True

    return False

def is_ip(val: str) -> bool:
    """
    This method safely handles if a given string represents an IP
    :param val: the given string
    :return: a boolean representing if the given string represents an IP
    """
    try:
        ip_address(val)
        return True
    except ValueError:
        # In the occasional circumstance, a sample with make a call
        # to an explicit IP, which breaks the way that AL handles
        # domains
        pass
    return False
