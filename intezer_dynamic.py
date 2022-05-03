from http import HTTPStatus
from requests import HTTPError
from time import sleep, time
from typing import Dict, List, Optional

from intezer_sdk.api import IntezerApi
from intezer_sdk.errors import UnsupportedOnPremiseVersion
from intezer_sdk.consts import OnPremiseVersion, BASE_URL, API_VERSION, AnalysisStatusCode
from signatures import get_attack_ids_for_signature_name, get_heur_id_for_signature_name, GENERIC_HEURISTIC_ID

from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import extract_iocs_from_text_blob, SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from assemblyline_v4_service.common.tag_helper import add_tag

global_safelist: Optional[Dict[str, Dict[str, List[str]]]] = None

UNINTERESTING_ANALYSIS_KEYS = [
    "analysis_url",
    "is_private",
    "sha256",
    "verdict",
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

SILENT_SIGNATURES = ["enumerates_running_processes"]
COMMAND_LINE_KEYS = ["command", "cmdline", "Commandline executed"]
FILE_KEYS = ["DeletedFile", "file", "binary", "copy", "service path", "office_martian", "File executed"]
REGISTRY_KEYS = ["key", "regkey", "regkeyval"]
URL_KEYS = ["http_request", "url", "suspicious_request", "network_http", "request", "http_downloadurl", "uri"]
IP_KEYS = ["IP"]
DOMAIN_KEYS = ["domain"]

DEFAULT_ANALYSIS_TIMEOUT = 180
DEFAULT_POLLING_PERIOD = 5

COMPLETED_STATUSES = [AnalysisStatusCode.FINISH.value, AnalysisStatusCode.FAILED.value, "succeeded"]


class ALIntezerApi(IntezerApi):
    # Overriding the class method to handle if the URL is GONE
    def get_latest_analysis(self,
                            file_hash: str,
                            private_only: bool = False,
                            **additional_parameters) -> Optional[dict]:
        try:
            return IntezerApi.get_latest_analysis(
                self=self,
                file_hash=file_hash,
                private_only=private_only,
                additional_parameters=additional_parameters
            )
        except HTTPError as e:
            if str(HTTPStatus.GONE.value) in repr(e) or HTTPStatus.GONE.name in repr(e):
                return None
            else:
                raise


class IntezerDynamic(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self.log.debug("Initializing the IntezerDynamic service...")
        self.client: Optional[ALIntezerApi] = None

    def start(self) -> None:
        global global_safelist
        self.log.debug("IntezerDynamic service started...")

        if self.config.get("base_url") != BASE_URL and not self.config["is_on_premise"]:
            self.log.warning(f"You are using a base url that is not {BASE_URL}, yet you do not have the 'is_on_premise' parameter set to true. Are you sure?")

        self.client = ALIntezerApi(
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

        analysis_id = request.get_param('analysis_id')
        if not analysis_id:
            main_api_result = self.client.get_latest_analysis(
                file_hash=sha256, private_only=self.config["private_only"]
            )
        else:
            main_api_result = {"analysis_id": analysis_id, "verdict": None}

        if not main_api_result:
            self.log.debug(f"SHA256 {sha256} is not on the system.")

            start_time = time()
            analysis_id = self.client.analyze_by_file(file_path=request.file_path, file_name=request.file_name)
            status = AnalysisStatusCode.QUEUED

            analysis_timeout = self.config.get("analysis_period_in_seconds", DEFAULT_ANALYSIS_TIMEOUT)
            polling_period = self.config.get("polling_period_in_seconds", DEFAULT_POLLING_PERIOD)

            while status not in COMPLETED_STATUSES or time() - start_time > analysis_timeout:
                sleep(polling_period)
                resp = self.client.get_file_analysis_response(analysis_id, ignore_not_found=False)
                status = resp.json()["status"]

            if status == AnalysisStatusCode.FAILED.value:
                self.log.warning(f"{sha256} caused Intezer to crash")
                request.result = result
                return

            main_api_result = self.client.get_latest_analysis(
                file_hash=sha256, private_only=self.config["private_only"]
            )

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

            if families and not any(family["reused_gene_count"] > 1 for family in families):
                # Most likely a false positive
                continue

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

        # Setting heuristic here to avoid FPs
        if main_kv_section.subsections:
            self.set_heuristic_by_verdict(main_kv_section, main_api_result["verdict"])

        if main_kv_section.subsections or main_kv_section.heuristic:
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
            parent_result_section.add_subsection(network_section)

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
        except UnsupportedOnPremiseVersion as e:
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

                if key in IP_KEYS and not add_tag(sig_res, "network.dynamic.ip", value, global_safelist):
                    extract_iocs_from_text_blob(value, ioc_table)
                elif key in COMMAND_LINE_KEYS:
                    _ = add_tag(sig_res, "dynamic.process.command_line", value, global_safelist)
                    extract_iocs_from_text_blob(value, ioc_table)
                elif key in FILE_KEYS:
                    _ = add_tag(sig_res, "dynamic.process.file_name", value, global_safelist)
                elif key in URL_KEYS:
                    extract_iocs_from_text_blob(value, ioc_table)
                elif key in REGISTRY_KEYS:
                    _ = add_tag(sig_res, "dynamic.registry_key", value, global_safelist)
                elif key in DOMAIN_KEYS:
                    _ = add_tag(sig_res, "network.dynamic.domain", value, global_safelist)
                else:
                    pass
                if len(value) > 512:
                    value = value[:512] + "..."
                if not sig_res.body:
                    sig_res.add_line(f"\t{key}: {value}")
                elif sig_res.body and f"\t{key}: {value}" not in sig_res.body:
                    sig_res.add_line(f"\t{key}: {value}")

            if ioc_table.body:
                sig_res.add_subsection(ioc_table)

            sigs_res.add_subsection(sig_res)

        if sigs_res.subsections:
            parent_result_section.add_subsection(sigs_res)
