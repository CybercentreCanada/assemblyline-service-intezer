from requests import HTTPError
from typing import Dict, List, Optional

from intezer_sdk.api import IntezerApi

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    ProcessItem,
    Result,
    ResultKeyValueSection,
    ResultSection,
    ResultProcessTreeSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)


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
SUSPICIOUS = "suspicious"
UNKNOWN = "unknown"
TRUSTED = "trusted"
INTERESTING_VERDICTS = [MALICIOUS, SUSPICIOUS]
UNINTERESTING_VERDICTS = [UNKNOWN, TRUSTED]

IP = "ip"
DOMAIN = "domain"
NETWORK_IOC_TYPES = [IP, DOMAIN]


class IntezerStatic(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self.log.debug("Initializing the IntezerStatic service...")
        self.client: Optional[IntezerApi] = None

    def start(self) -> None:
        self.log.debug("IntezerStatic service started...")
        self.client = IntezerApi(
            api_version=self.config["api_version"],
            api_key=self.config["api_key"],
            base_url=self.config["base_url"],
        )

    def stop(self) -> None:
        self.log.debug("IntezerStatic service ended...")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        so = SandboxOntology()

        sha256 = request.sha256

        main_api_result = self.client.get_latest_analysis(
            file_hash=sha256, private_only=self.config["private_only"]
        )

        if not main_api_result:
            request.result = result
            return

        analysis_id = main_api_result["analysis_id"]

        main_kv_section = ResultKeyValueSection("IntezerStatic analysis report")
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

        # TODO: Waiting for https://github.com/intezer/analyze-python-sdk/issues/43 to be resolved
        # strings = self.client.get_strings_by_id(analysis_id, sub_analysis_id)

        sub_analyses = self.client.get_sub_analyses_by_id(analysis_id)
        can_we_download_files = True
        process_path_set = set()
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

            if not code_reuse and not families and not extraction_info:
                # Otherwise, boring!
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
                    if family["family_type"] != "application":
                        family_section.add_tag("attribution.family", family["family_name"])
                sub_kv_section.add_subsection(family_section)

            if extraction_info:
                for item in extraction_info["processes"]:
                    p = so.create_process(
                        pid=item["process_id"],
                        image=item["process_path"],
                        ppid=item["parent_process_id"],
                    )
                    so.add_process(p)
                    process_path_set.add(item["process_path"])
                    if item["process_path"] != item["module_path"]:
                        self.log.debug(
                            f"Investigate! process_path: {item['process_path']} != module_path: {item['module_path']}"
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
        elif verdict == MALICIOUS:
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
