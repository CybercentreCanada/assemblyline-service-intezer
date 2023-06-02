from enum import Enum
from http import HTTPStatus
from time import sleep, time
from typing import Any, Dict, List, Optional, Set

from assemblyline.common.str_utils import truncate
from assemblyline.odm.models.ontology.results.process import Process as ProcessModel
from assemblyline_service_utilities.common.dynamic_service_helper import (
    MIN_TIME,
    OntologyResults,
    Process,
    extract_iocs_from_text_blob,
)
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from assemblyline_v4_service.common.task import MaxExtractedExceeded
from intezer_sdk.api import IntezerApi
from intezer_sdk.consts import API_VERSION, BASE_URL, AnalysisStatusCode, OnPremiseVersion
from intezer_sdk.errors import ServerError, UnsupportedOnPremiseVersion
from requests import ConnectionError, HTTPError
from safe_families import SAFE_FAMILIES
from signatures import GENERIC_HEURISTIC_ID, get_attack_ids_for_signature_name, get_heur_id_for_signature_name

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

FAMILIES_TO_NOT_TAG = ["application", "library"]
MALICIOUS_FAMILY_TYPES = ["malware"]
FAMILY_TYPES_OF_INTEREST = ["administration_tool", "packer"]

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

COMPLETED_STATUSES = [AnalysisStatusCode.FINISH.value, AnalysisStatusCode.FAILED.value, "succeeded"]

CANNOT_EXTRACT_ARCHIVE = "Cannot extract archive"
NOT_AVAILABLE = "Not Available"

# Defaults
DEFAULT_ANALYSIS_TIMEOUT = 180
DEFAULT_POLLING_PERIOD = 5
DEFAULT_MIN_MALWARE_GENES = 5


# From the user-guide
class Verdicts(Enum):
    # Trusted
    KNOWN_TRUSTED = "known_trusted"
    TRUSTED = "trusted"
    PROBABLY_TRUSTED = "probably_trusted"
    KNOWN_LIBRARY = "known_library"
    LIBRARY = "library"
    TRUSTED_VERDICTS = [KNOWN_TRUSTED, TRUSTED, PROBABLY_TRUSTED, KNOWN_LIBRARY, LIBRARY]

    # Malicious
    KNOWN_MALICIOUS = "known_malicious"
    MALICIOUS = "malicious"
    MALICIOUS_VERDICTS = [MALICIOUS, KNOWN_MALICIOUS]

    # Suspicious
    ADMINISTRATION_TOOL = "administration_tool"
    KNOWN_ADMINISTRATION_TOOL = "known_administration_tool"
    PACKED = "packed"
    SCRIPT = "script"
    SUSPICIOUS = "suspicious"
    SUSPICIOUS_VERDICTS = [ADMINISTRATION_TOOL, KNOWN_ADMINISTRATION_TOOL, PACKED, SCRIPT, SUSPICIOUS]

    # Of Interest
    FAMILY_TYPE_OF_INTEREST = "interesting"
    PROBABLY_PACKED = "probably_packed"
    FAMILY_TYPE_OF_INTEREST_VERDICTS = [FAMILY_TYPE_OF_INTEREST, PROBABLY_PACKED]

    # Unknown
    UNIQUE = "unique"
    NO_GENES = "no_genes"
    ALMOST_NO_GENES = "almost_no_genes"
    INCONCLUSIVE = "inconclusive"
    INSTALLER = "installer"
    NO_CODE = "no_code"
    UNKNOWN = "unknown"
    UNKNOWN_VERDICTS = [UNIQUE, NO_GENES, ALMOST_NO_GENES, INCONCLUSIVE, INSTALLER, NO_CODE, UNKNOWN]

    # Not supported
    FILE_TYPE_NOT_SUPPORTED = "file_type_not_supported"
    NO_NATIVE_CODE = "non_native_code"
    CORRUPTED_FILE = "corrupted_file"
    NOT_SUPPORTED = "not_supported"
    NOT_SUPPORTED_VERDICTS = [FILE_TYPE_NOT_SUPPORTED, NOT_SUPPORTED, NO_NATIVE_CODE, CORRUPTED_FILE]

    # Neutral
    NEUTRAL = "neutral"
    NEUTRAL_VERDICTS = [NEUTRAL]

    INTERESTING_VERDICTS = MALICIOUS_VERDICTS + SUSPICIOUS_VERDICTS + FAMILY_TYPE_OF_INTEREST_VERDICTS
    UNINTERESTING_VERDICTS = NEUTRAL_VERDICTS + NOT_SUPPORTED_VERDICTS + UNKNOWN_VERDICTS + TRUSTED_VERDICTS


class NetworkIOCTypes(Enum):
    IP = "ip"
    DOMAIN = "domain"
    TYPES = [IP, DOMAIN]


class ALIntezerApi(IntezerApi):
    def set_logger(self, log):
        self.log = log

    def set_retry_forever(self, retry_forever: bool):
        self.retry_forever: bool = retry_forever

    # Overriding the class method to handle if the URL is GONE
    def get_latest_analysis(self,
                            file_hash: str,
                            private_only: bool = False,
                            **additional_parameters) -> Optional[Dict]:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_latest_analysis(
                    self=self,
                    file_hash=file_hash,
                    private_only=private_only,
                    **additional_parameters
                )
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to get the latest analysis for SHA256 {file_hash} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                # Occasionally an analysis fails, and HTTPError.GONE is raised
                if str(HTTPStatus.GONE.value) in repr(e) or HTTPStatus.GONE.name in repr(e):
                    self.log.debug(
                        f"Unable to get the latest analysis for SHA256 {file_hash} due to '{e}'."
                    )
                    return None
                # This issue can occur with certain private accounts on the public instance of analyze.intezer.com as
                # per https://github.com/CybercentreCanada/assemblyline-service-intezer/issues/31
                elif str(HTTPStatus.NOT_FOUND.value) in repr(e) or HTTPStatus.NOT_FOUND.name in repr(e):
                    self.log.debug(
                        f"Unable to get the latest analysis for SHA256 {file_hash} due to '{e}'."
                    )
                    return None
                else:
                    if not logged:
                        self.log.error(
                            "The intezer web service is most likely down. "
                            f"Indicator: Unable to get the latest analysis for SHA256 {file_hash} due to '{e}'."
                        )
                        logged = True
                    if self.retry_forever:
                        sleep(5)
                        continue
                    else:
                        raise

    # Overriding the class method to handle if the HTTPError exists
    def get_iocs(self, analysis_id: str) -> Dict[str, List[Dict[str, str]]]:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_iocs(self=self, analyses_id=analysis_id)
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to retrieve IOCs for analysis ID {analysis_id} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
                if str(HTTPStatus.FORBIDDEN.value) in repr(e) or HTTPStatus.FORBIDDEN.name in repr(e):
                    self.log.debug(
                        f"Unable to retrieve IOCs for analysis ID {analysis_id} due to '{e}'."
                    )
                    return {"files": [], "network": []}
                # This issue can occur with certain private accounts on the public instance of analyze.intezer.com as
                # per https://github.com/CybercentreCanada/assemblyline-service-intezer/issues/31
                elif str(HTTPStatus.NOT_FOUND.value) in repr(e) or HTTPStatus.NOT_FOUND.name in repr(e):
                    self.log.debug(
                        f"Unable to retrieve IOCs for analysis ID {analysis_id} due to '{e}'."
                    )
                    return {"files": [], "network": []}
                else:
                    if not logged:
                        self.log.error(
                            "The intezer web service is most likely down. "
                            f"Indicator: Unable to retrieve IOCs for analysis ID {analysis_id} due to '{e}'."
                        )
                        logged = True
                    if self.retry_forever:
                        sleep(5)
                        continue
                    else:
                        raise

    # Overriding the class method to handle if the HTTPError or UnsupportedOnPremiseVersion exists
    def get_dynamic_ttps(self, analysis_id: str) -> List[Dict[str, str]]:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_dynamic_ttps(self=self, analyses_id=analysis_id)
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to retrieve TTPs for analysis ID {analysis_id} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
                if str(HTTPStatus.FORBIDDEN.value) in repr(e) or HTTPStatus.FORBIDDEN.name in repr(e):
                    self.log.debug(
                        f"Unable to retrieve TTPs for analysis ID {analysis_id} due to '{e}'."
                    )
                    return []
                # This issue can occur with certain private accounts on the public instance of analyze.intezer.com as
                # per https://github.com/CybercentreCanada/assemblyline-service-intezer/issues/31
                elif str(HTTPStatus.NOT_FOUND.value) in repr(e) or HTTPStatus.NOT_FOUND.name in repr(e):
                    self.log.debug(
                        f"Unable to retrieve TTPs for analysis ID {analysis_id} due to '{e}'."
                    )
                    return []
                else:
                    if not logged:
                        self.log.error(
                            "The intezer web service is most likely down. "
                            f"Indicator: Unable to retrieve TTPs for analysis ID {analysis_id} due to '{e}'."
                        )
                        logged = True
                    if self.retry_forever:
                        sleep(5)
                        continue
                    else:
                        raise
            except UnsupportedOnPremiseVersion as e:
                self.log.debug(
                    f"Unable to retrieve TTPs for analysis ID {analysis_id} due to '{e}'."
                )
                return []

    # Overriding the class method to handle if the HTTPError exists
    def get_sub_analyses_by_id(self, analysis_id: str) -> List[Dict[str, Any]]:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_sub_analyses_by_id(self=self, analysis_id=analysis_id)
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to get sub_analyses for analysis ID {analysis_id} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                self.log.debug(
                    f"Unable to get sub_analyses for analysis ID {analysis_id} due to '{e}'."
                )
                return []

    # Overriding the class method to handle if the network connection cannot be made
    def get_sub_analysis_code_reuse_by_id(self, analysis_id: str, sub_analysis_id: str) -> Optional[Dict[str, Any]]:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_sub_analysis_code_reuse_by_id(
                    self=self, composed_analysis_id=analysis_id, sub_analysis_id=sub_analysis_id
                )
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to get sub_analyses code re-use for analysis ID {analysis_id} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                self.log.debug(
                    f"Unable to get sub_analyses code re-use for analysis ID {analysis_id} due to '{e}'."
                )
                return None

    # Overriding the class method to handle if the network connection cannot be made
    def get_sub_analysis_metadata_by_id(self, analysis_id: str, sub_analysis_id: str) -> Dict[str, Any]:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_sub_analysis_metadata_by_id(
                    self=self, composed_analysis_id=analysis_id, sub_analysis_id=sub_analysis_id
                )
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to get sub_analyses metadata for analysis ID {analysis_id} and sub-analysis ID {sub_analysis_id} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                self.log.debug(
                    f"Unable to get sub_analyses metadata for analysis ID {analysis_id} and sub-analysis ID {sub_analysis_id} due to '{e}'."
                )
                return {}

    # Overriding the class method to handle if the HTTPError exists
    def download_file_by_sha256(self, sha256: str, dir_path: str) -> bool:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                IntezerApi.download_file_by_sha256(
                    self=self, sha256=sha256, path=dir_path
                )
                return True
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to download file for SHA256 {sha256} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except HTTPError as e:
                # If you have a community account with analyze.intezer.com, you will get a 403 FORBIDDEN on this endpoint.
                if str(HTTPStatus.FORBIDDEN.value) in repr(e) or HTTPStatus.FORBIDDEN.name in repr(e):
                    self.log.debug(
                        f"Unable to download file for SHA256 {sha256} due to '{e}'."
                    )
                    return False
                # This issue can occur with certain private accounts on the public instance of analyze.intezer.com as
                # per https://github.com/CybercentreCanada/assemblyline-service-intezer/issues/31
                elif str(HTTPStatus.NOT_FOUND.value) in repr(e) or HTTPStatus.NOT_FOUND.name in repr(e):
                    self.log.debug(
                        f"Unable to download file for SHA256 {sha256} due to '{e}'."
                    )
                    return False
                else:
                    if not logged:
                        self.log.error(
                            "The intezer web service is most likely down. "
                            f"Indicator: Unable to download file for SHA256 {sha256} due to '{e}'."
                        )
                        logged = True
                    if self.retry_forever:
                        sleep(5)
                        continue
                    else:
                        raise
            except FileExistsError as e:
                # Duplicate file
                self.log.debug(
                    f"Unable to download file for SHA256 {sha256} due to '{e}'."
                )
                return False

    # Overriding the class method to handle if the ServerError exists
    def analyze_by_file(self, sha256: str, file_path: str, file_name: str, verify_file_support: bool) -> str:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.analyze_by_file(
                    self=self, file_path=file_path, file_name=file_name, verify_file_support=verify_file_support)
            except ConnectionError as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to analyze file for SHA256 {sha256} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise
            except ServerError as e:
                # If you submit a file that Intezer doesn't support, you will get a 415 UNSUPPORTED_MEDIA_TYPE on this endpoint.
                if str(HTTPStatus.UNSUPPORTED_MEDIA_TYPE.value) in repr(e) or HTTPStatus.UNSUPPORTED_MEDIA_TYPE.name in repr(e):
                    self.log.debug(
                        f"Unable to analyze file for SHA256 {sha256} due to '{e}'."
                    )
                    return Verdicts.FILE_TYPE_NOT_SUPPORTED.value
                elif str(HTTPStatus.INTERNAL_SERVER_ERROR.value) in repr(e) or HTTPStatus.INTERNAL_SERVER_ERROR.name in repr(e):
                    self.log.debug(
                        f"Unable to analyze file for SHA256 {sha256} due to '{e}'."
                    )
                    return AnalysisStatusCode.FAILED.value
                elif CANNOT_EXTRACT_ARCHIVE in repr(e):
                    self.log.warning(
                        f"Unable to extract archive for SHA256 {sha256}, possibly because it is password-protected.")
                    return Verdicts.FILE_TYPE_NOT_SUPPORTED.value
                # If you submit a file that is too big for Intezer, you will get a 413 REQUEST_ENTITY_TOO_LARGE on this endpoint.
                elif str(HTTPStatus.REQUEST_ENTITY_TOO_LARGE.value) in repr(e) or HTTPStatus.REQUEST_ENTITY_TOO_LARGE.name in repr(e):
                    self.log.debug(
                        f"Unable to analyze file for SHA256 {sha256} due to '{e}'."
                    )
                    return Verdicts.FILE_TYPE_NOT_SUPPORTED.value
                else:
                    if not logged:
                        self.log.error(
                            "The intezer web service is most likely down. "
                            f"Indicator: Unable to analyze file for SHA256 {sha256} due to '{e}'."
                        )
                        logged = True
                    if self.retry_forever:
                        sleep(5)
                        continue
                    else:
                        raise

    # Overriding the class method to handle if the ServerError exists
    def get_file_analysis_response(self, analysis_id: str, ignore_not_found: bool = False) -> str:
        # We will try to connect with the REST API... NO MATTER WHAT
        logged = False
        while True:
            try:
                return IntezerApi.get_file_analysis_response(
                    self=self, analyses_id=analysis_id, ignore_not_found=ignore_not_found)
            except (ConnectionError, HTTPError) as e:
                if not logged:
                    self.log.error(
                        "The intezer web service is most likely down. "
                        f"Indicator: Unable to get analysis response for analysis ID {analysis_id} due to '{e}'."
                    )
                    logged = True
                if self.retry_forever:
                    sleep(5)
                    continue
                else:
                    raise


class Intezer(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self.log.debug("Initializing the Intezer service...")
        self.client: Optional[ALIntezerApi] = None

    def start(self) -> None:
        global global_safelist
        self.log.debug("Intezer service started...")

        if self.config.get("base_url") != BASE_URL and not self.config["is_on_premise"]:
            self.log.warning(
                f"You are using a base url that is not {BASE_URL}, yet you do not have the 'is_on_premise' parameter set to true. Are you sure?")

        self.client = ALIntezerApi(
            api_version=self.config.get("api_version", API_VERSION),
            api_key=self.config["api_key"],
            base_url=self.config.get("base_url", BASE_URL),
            on_premise_version=OnPremiseVersion.V21_11 if self.config["is_on_premise"] else None
        )
        self.client.set_logger(self.log)
        self.client.set_retry_forever(self.config.get("retry_forever", False))
        try:
            global_safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")

    def stop(self) -> None:
        self.log.debug("Intezer service ended...")

    def execute(self, request: ServiceRequest) -> None:
        sha256 = request.sha256
        result = Result()

        # First, let's get the analysis metadata, if it exists on the system
        main_api_result_from_retrieval = self._get_analysis_metadata(request.get_param('analysis_id'), sha256)

        if not main_api_result_from_retrieval:
            self.log.debug(f"{sha256} is not on the system.")
            if self.config.get("allow_dynamic_submit", True) and request.get_param("dynamic_submit"):
                main_api_result_from_submission = self._submit_file_for_analysis(request, sha256)
                if not main_api_result_from_submission:
                    request.result = result
                    return
                else:
                    main_api_result = main_api_result_from_submission
            else:
                self.log.debug(
                    f"The user has requested that {sha256} not be sent to the system for analysis. Exiting...")
                request.result = result
                return
        else:
            self.log.debug(f"{sha256} was found on the system.")
            main_api_result = main_api_result_from_retrieval

        verdict = main_api_result.get("verdict")
        if verdict in Verdicts.NOT_SUPPORTED_VERDICTS.value:
            self.log.debug(f"Unsupported file type: {request.file_type}")
            request.result = result
            return
        elif verdict == AnalysisStatusCode.FAILED.value:
            self.log.warning("The Intezer server is not feeling well :(")
            request.result = result
            return
        elif verdict in Verdicts.TRUSTED_VERDICTS.value:
            self.log.debug(f"The verdict was {verdict}. No need to report it.")
            request.result = result
            return

        analysis_id = main_api_result["analysis_id"]

        # Setup the main result section
        main_kv_section = ResultKeyValueSection("Intezer analysis report")
        processed_main_api_result = self._process_details(
            main_api_result.copy(), UNINTERESTING_ANALYSIS_KEYS
        )
        main_kv_section.update_items(processed_main_api_result)
        if "family_name" in main_api_result and main_api_result["family_name"] != NOT_AVAILABLE:
            # Tag both, ask forgiveness later
            main_kv_section.add_tag(
                "attribution.implant", main_api_result["family_name"]
            )
            main_kv_section.add_tag(
                "attribution.actor", main_api_result["family_name"]
            )

        # This file-verdict map will be used later on to assign heuristics to sub-analyses
        file_verdict_map = {}
        self._process_iocs(analysis_id, file_verdict_map, main_kv_section)
        if not self.config["is_on_premise"]:
            self._process_ttps(analysis_id, main_kv_section)
        self._handle_subanalyses(request, sha256, analysis_id, file_verdict_map, main_kv_section)

        # Setting heuristic here to avoid FPs. An analysis should not require sub_analyses to get a heuristic
        # assigned. A caveat to this is that the parent analysis has an unknown verdict but the sub-analysis of the
        # same file hash yields a different verdict.
        if verdict == "unknown" and file_verdict_map.get(sha256, "unknown") != "unknown":
            verdict = file_verdict_map[sha256]
        self._set_heuristic_by_verdict(main_kv_section, verdict)

        if main_kv_section.subsections or main_kv_section.heuristic:
            result.add_section(main_kv_section)
        request.result = result

    def _get_analysis_metadata(self, analysis_id: str, sha256: str) -> Dict[str, str]:
        """
        This method handles the logic of determining what metadata we want to
        retrieve (for the hash or for the analysis_id)
        :param request: The service request object
        :param sha256: The hash of the given file
        :return: A dictionary representing the analysis metadata
        """
        # NOTE: If a user requests a certain analysis id, then the submitted file will be ignored
        if not analysis_id:
            return self.client.get_latest_analysis(
                file_hash=sha256, private_only=self.config["private_only"]
            )
        else:
            return {"analysis_id": analysis_id, "verdict": None}

    def _submit_file_for_analysis(self, request: ServiceRequest, sha256: str) -> Dict[str, str]:
        """
        This method handles the logic for submitting a file for analysis and polling for the result
        :param request: The service request object
        :param sha256: The hash of the given file
        :return: None
        """
        self.log.debug(f"Submitting {sha256} for analysis...")
        start_time = time()

        # Send the file
        analysis_id = self.client.analyze_by_file(
            sha256=sha256, file_path=request.file_path, file_name=request.file_name, verify_file_support=True)
        if analysis_id in [Verdicts.FILE_TYPE_NOT_SUPPORTED.value, AnalysisStatusCode.FAILED.value]:
            return {"verdict": analysis_id}

        status = AnalysisStatusCode.QUEUED

        analysis_timeout = self.config.get("analysis_period_in_seconds", DEFAULT_ANALYSIS_TIMEOUT)
        polling_period = self.config.get("polling_period_in_seconds", DEFAULT_POLLING_PERIOD)

        elapsed_time = time() - start_time
        while status not in COMPLETED_STATUSES and elapsed_time < analysis_timeout:
            sleep(polling_period)
            resp = self.client.get_file_analysis_response(analysis_id, ignore_not_found=False)
            status = resp.json()["status"]
            self.log.debug(f"{sha256} is being analyzed. Current status: {status}")
            elapsed_time = time() - start_time

        if elapsed_time > analysis_timeout:
            self.log.warning(
                f"Intezer was unable to scan the file {sha256} within the analysis timeout. Scan was stuck in '{status}'.")

        if status == AnalysisStatusCode.FAILED.value:
            self.log.warning(f"{sha256} caused Intezer to crash.")
            return {}

        return self.client.get_latest_analysis(
            file_hash=sha256, private_only=self.config["private_only"]
        )

    @staticmethod
    def _process_details(
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

            # Subanalysis indicators as of v22.1 are now a list of dictionaries containing "classification" and "name" keys
            # We only want the value of the "name" key
            elif key == "indicators" and isinstance(details[key], list) and all(isinstance(item, dict) for item in details[key]):
                for index, item in enumerate(details[key]):
                    details[key][index] = item["name"]

            # Rename reused_gene_count key to reused_code_count
            elif key == "reused_gene_count":
                details["reused_code_count"] = details.pop(key)

        return details

    def _set_heuristic_by_verdict(
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
            verdict not in Verdicts.INTERESTING_VERDICTS.value
            and verdict not in Verdicts.UNINTERESTING_VERDICTS.value
        ):
            self.log.debug(f"{verdict} was spotted. Is this useful?")
        elif verdict in Verdicts.MALICIOUS_VERDICTS.value:
            result_section.set_heuristic(1)
        elif verdict in Verdicts.SUSPICIOUS_VERDICTS.value:
            result_section.set_heuristic(2)
        elif verdict in Verdicts.FAMILY_TYPE_OF_INTEREST_VERDICTS.value:
            result_section.set_heuristic(3)

    def _process_iocs(
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
        iocs = self.client.get_iocs(analysis_id)
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
                if type == NetworkIOCTypes.IP.value:
                    network_section.add_tag("network.dynamic.ip", ioc)
                elif type == NetworkIOCTypes.DOMAIN.value:
                    network_section.add_tag("network.dynamic.domain", ioc)
                elif type not in NetworkIOCTypes.TYPES.value:
                    self.log.debug(
                        f"The network IOC type of {type} is not in {NetworkIOCTypes.TYPES.value}. Network item: {network}"
                    )
                network_section.add_line(f"IOC: {ioc}")
            parent_result_section.add_subsection(network_section)

    def _process_ttps(
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
        ttps = self.client.get_dynamic_ttps(analysis_id)

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
            self._process_ttp_data(ttp['data'], sig_res, ioc_table)

            if ioc_table.body:
                sig_res.add_subsection(ioc_table)

            sigs_res.add_subsection(sig_res)

        if sigs_res.subsections:
            parent_result_section.add_subsection(sigs_res)

    def _process_ttp_data(
            self, ttp_data: List[Dict[str, str]],
            sig_res: ResultSection, ioc_table: ResultTableSection) -> None:
        """
        This method handles the processing of signature marks
        :param ttp_data: The marks for the signature
        :param sig_res: The result section for the signature
        :param ioc_table: The result section table where the data is going to go
        :return: None
        """
        for item in ttp_data:
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
            value = truncate(value, 512)
            if not sig_res.body:
                sig_res.add_line(f"\t{key}: {value}")
            elif sig_res.body and f"\t{key}: {value}" not in sig_res.body:
                sig_res.add_line(f"\t{key}: {value}")

    def _handle_subanalyses(self, request: ServiceRequest, sha256: str, analysis_id: str,
                            file_verdict_map: Dict[str, str],
                            parent_section: ResultSection) -> None:
        """
        This method handles the subanalyses for a given analysis ID
        :param request: The service request object
        :param sha256: The hash of the given file
        :param analysis_id: The ID for the analysis which we will be retrieving
        :param file_verdict_map: A map of sha256s representing a file's
        contents, and the verdict for that file
        :param parent_result_section: The result section that the network
        result section will be added to, if applicable
        :return: None
        """
        so = OntologyResults()

        # This boolean is used to determine if we should try to download another file
        can_we_download_files = True

        # These sets will be used as we work through the process trees
        process_path_set = set()
        command_line_set = set()

        # Now let's get into the subanalyses for this sample
        sub_analyses = self.client.get_sub_analyses_by_id(analysis_id)

        for sub in sub_analyses:
            sub_analysis_id = sub["sub_analysis_id"]

            # Get the extraction info, which is basically the details of how the subanalysis object came to be
            extraction_info = sub.pop("extraction_info", None)

            # Processes is only present when the sample has undergone dynamic execution
            if extraction_info and "processes" not in extraction_info:
                extraction_info = None

            code_reuse = self.client.get_sub_analysis_code_reuse_by_id(
                analysis_id, sub_analysis_id
            )

            if code_reuse:
                families = code_reuse.pop("families", [])
            else:
                families = []

            if not families and not extraction_info:
                # Otherwise, boring!
                continue

            if families and not any(family["reused_gene_count"] > 1 for family in families):
                # Most likely a false positive
                continue

            ###
            # If we have gotten to this point, then the sub analysis is worth reporting
            ###

            extraction_method = sub["source"].replace("_", " ")

            if extraction_method != "root":
                sub_kv_section = ResultKeyValueSection(
                    f"Subanalysis report for {sub['sha256']}, extracted via {extraction_method}")
            else:
                sub_kv_section = ResultKeyValueSection(f"Subanalysis report for {sub['sha256']}")

            metadata = self.client.get_sub_analysis_metadata_by_id(
                analysis_id, sub_analysis_id
            )
            processed_subanalysis = self._process_details(
                metadata.copy(), UNINTERESTING_SUBANALYSIS_KEYS
            )
            sub_kv_section.update_items(processed_subanalysis)
            parent_section.add_subsection(sub_kv_section)

            if code_reuse:
                code_reuse_kv_section = ResultKeyValueSection(
                    "Code reuse detected"
                )
                code_reuse_kv_section.update_items(code_reuse)
                sub_kv_section.add_subsection(code_reuse_kv_section)

            sub_sha256 = sub["sha256"]
            if families:
                self._process_families(families, sub_sha256, file_verdict_map, sub_kv_section)

            if extraction_info:
                self._process_extraction_info(extraction_info["processes"], process_path_set, command_line_set, so)

            # Setting a heuristic here or downloading the file would be redundant if the hash matched the original file
            if sub_sha256 != sha256:
                self._set_heuristic_by_verdict(
                    sub_kv_section, file_verdict_map.get(sub_sha256)
                )

                if self.config.get("download_subfiles", True):
                    if can_we_download_files or self.config.get("try_to_download_every_file", False):
                        file_was_downloaded = self.client.download_file_by_sha256(
                            sub_sha256, self.working_directory
                        )
                        if file_was_downloaded:
                            path = f"{self.working_directory}/{sub_sha256}.sample"
                            try:
                                request.add_extracted(
                                    path,
                                    f"{sub_sha256}.sample",
                                    f"Extracted via {extraction_method}",
                                )
                                self.log.debug(f"Added {sub_sha256}.sample as an extracted file.")
                            except MaxExtractedExceeded as e:
                                self.log.debug(f"Skipped adding {sub_sha256}.sample as an extracted file due to {e}.")
                                can_we_download_files = False
                        else:
                            can_we_download_files = False

        process_tree_section = so.get_process_tree_result_section()
        for process_path in process_path_set:
            process_tree_section.add_tag("dynamic.process.file_name", process_path)
        for command_line in command_line_set:
            process_tree_section.add_tag("dynamic.process.command_line", command_line)
        if process_tree_section.body:
            parent_section.add_subsection(process_tree_section)

    def _process_families(
            self, families: List[Dict[str, str]],
            sub_sha256: str, file_verdict_map: Dict[str, str],
            parent_section: ResultSection) -> None:
        """
        This method handles the "families" list, cutting out boring details and assigning verdicts
        :param families: A list of details for families
        :param sub_sha256: The hash of the sub analysis file
        :param file_verdict_map: A map of sha256s representing a file's
        contents, and the verdict for that file
        :param parent_section: The result section that the network
        :return: None
        """
        family_section = ResultTableSection("Family Details")
        family_section.set_column_order(["family_name", "family_type", "reused_code_count"])
        for family in families:
            processed_family = self._process_details(
                family.copy(), UNINTERESTING_FAMILY_KEYS
            )
            family_section.add_row(TableRow(**processed_family))
            family_type = family["family_type"]
            family_name = family["family_name"]
            # TODO: Do not tag these sub families, for the time being at least
            # if family_type not in FAMILIES_TO_NOT_TAG:
            #     family_section.add_tag("attribution.family", family["family_name"])

            # Overwrite value if not malicious
            if family_type in MALICIOUS_FAMILY_TYPES:
                reused_gene_count = family["reused_gene_count"]
                if sub_sha256 not in file_verdict_map or file_verdict_map[sub_sha256] != Verdicts.MALICIOUS.value:
                    # We want to avoid false positives by ensuring that we have a reasonable amount of malware genes
                    if reused_gene_count >= self.config.get("min_malware_genes", DEFAULT_MIN_MALWARE_GENES):
                        file_verdict_map[sub_sha256] = Verdicts.MALICIOUS.value

                # We also want to track the number of reused malware genes via heuristic 12
                if family_section.heuristic is None:
                    family_section.set_heuristic(12)
                if reused_gene_count < 5:
                    family_section.heuristic.add_signature_id("less_than_5")
                elif reused_gene_count >= 5 and reused_gene_count < 10:
                    family_section.heuristic.add_signature_id("between_5_and_10")
                elif reused_gene_count >= 10 and reused_gene_count < 25:
                    family_section.heuristic.add_signature_id("between_10_and_25")
                elif reused_gene_count >= 25 and reused_gene_count < 50:
                    family_section.heuristic.add_signature_id("between_25_and_50")
                elif reused_gene_count >= 50:
                    family_section.heuristic.add_signature_id("50_or_more")

            # Only overwrite value if value is not already malicious
            elif family_type in FAMILY_TYPES_OF_INTEREST and family_name not in SAFE_FAMILIES[family_type] and (sub_sha256 not in file_verdict_map or file_verdict_map[sub_sha256] not in Verdicts.MALICIOUS_VERDICTS.value):
                file_verdict_map[sub_sha256] = Verdicts.FAMILY_TYPE_OF_INTEREST.value

        if family_section.body:
            parent_section.add_subsection(family_section)

    def _process_extraction_info(
            self, processes: List[Dict[str, Any]],
            process_path_set: Set[str],
            command_line_set: Set[str],
            so: OntologyResults) -> None:
        """
        This method handles the processing of the extraction info process details
        :param processes: A list of processes
        :param process_path_set: A set containing process paths
        :param command_line_set: A set containing command lines
        :param so: the sandbox ontology object
        :return: None
        """
        for item in processes:
            command_line = None
            if item["process_path"] != item["module_path"]:
                self.log.debug(
                    f"Investigate! process_path: {item['process_path']} != module_path: {item['module_path']}"
                )
                command_line = f"{item['process_path']} {item['module_path']}"
                process_path_set.add(item["module_path"])
                command_line_set.add(command_line)

            p = so.get_process_by_pid_and_time(item["process_id"], MIN_TIME)
            if p:
                p.update(command_line=command_line)
            else:
                p_oid = ProcessModel.get_oid(
                    {
                        "pid": item["process_id"],
                        "ppid": item["parent_process_id"],
                        "image": item["process_path"],
                        "command_line": command_line,
                    }
                )
                p = so.create_process(
                    pid=item["process_id"],
                    image=item["process_path"],
                    ppid=item["parent_process_id"],
                    objectid=OntologyResults.create_objectid(
                        tag=Process.create_objectid_tag(item["process_path"],),
                        ontology_id=p_oid,
                        service_name="IntezerStatic"
                    ),
                    command_line=command_line,
                    start_time=MIN_TIME
                )
                so.add_process(p)
            process_path_set.add(item["process_path"])
