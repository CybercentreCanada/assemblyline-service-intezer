from multiprocessing import Process
import os
import pytest
from requests import ConnectionError, HTTPError
import requests_mock
import shutil

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name='intezer_dynamic',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
        safelist_config={
            "enabled": False,
            "hash_types": ['sha1', 'sha256'],
            "enforce_safelist_service": False
        }
    ),
]


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        result_heuristic_equality = this.heuristic.attack_ids == that.heuristic.attack_ids and \
            this.heuristic.frequency == that.heuristic.frequency and \
            this.heuristic.heur_id == that.heuristic.heur_id and \
            this.heuristic.score == that.heuristic.score and \
            this.heuristic.score_map == that.heuristic.score_map and \
            this.heuristic.signatures == that.heuristic.signatures

        if not result_heuristic_equality:
            print("The heuristics are not equal:")
            if this.heuristic.attack_ids != that.heuristic.attack_ids:
                print("The attack_ids are different:")
                print(f"{this.heuristic.attack_ids}")
                print(f"{that.heuristic.attack_ids}")
            if this.heuristic.frequency != that.heuristic.frequency:
                print("The frequencies are different:")
                print(f"{this.heuristic.frequency}")
                print(f"{that.heuristic.frequency}")
            if this.heuristic.heur_id != that.heuristic.heur_id:
                print("The heur_ids are different:")
                print(f"{this.heuristic.heur_id}")
                print(f"{that.heuristic.heur_id}")
            if this.heuristic.score != that.heuristic.score:
                print("The scores are different:")
                print(f"{this.heuristic.score}")
                print(f"{that.heuristic.score}")
            if this.heuristic.score_map != that.heuristic.score_map:
                print("The score_maps are different:")
                print(f"{this.heuristic.score_map}")
                print(f"{that.heuristic.score_map}")
            if this.heuristic.signatures != that.heuristic.signatures:
                print("The signatures are different:")
                print(f"{this.heuristic.signatures}")
                print(f"{that.heuristic.signatures}")

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        print("The heuristics are not equal:")
        if this.heuristic:
            print(f"{this.heuristic.__dict__}")
        else:
            print("this.heuristic is None")
        if that.heuristic:
            print(f"{that.heuristic.__dict__}")
        else:
            print("that.heuristic is None")
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
        this.body == that.body and \
        this.body_format == that.body_format and \
        this.classification == that.classification and \
        this.depth == that.depth and \
        len(this.subsections) == len(that.subsections) and \
        this.title_text == that.title_text and \
        this.tags == that.tags and \
        this.auto_collapse == that.auto_collapse

    if not current_section_equality:
        print("The current sections are not equal:")
        if not result_heuristic_equality:
            print("The result heuristics are not equal")
        if this.body != that.body:
            print("The bodies are different:")
            print(f"{this.body}")
            print(f"{that.body}")
        if this.body_format != that.body_format:
            print("The body formats are different:")
            print(f"{this.body_format}")
            print(f"{that.body_format}")
        if this.classification != that.classification:
            print("The classifications are different:")
            print(f"{this.classifications}")
            print(f"{that.classifications}")
        if this.depth != that.depth:
            print("The depths are different:")
            print(f"{this.depths}")
            print(f"{that.depths}")
        if len(this.subsections) != len(that.subsections):
            print("The number of subsections are different:")
            print(f"{len(this.subsections)}")
            print(f"{len(that.subsections)}")
        if this.title_text != that.title_text:
            print("The title texts are different:")
            print(f"{this.title_text}")
            print(f"{that.title_text}")
        if this.tags != that.tags:
            print("The tags are different:")
            print(f"{this.tags}")
            print(f"{that.tags}")
        if this.auto_collapse != that.auto_collapse:
            print("The auto_collapse settings are different:")
            print(f"{this.auto_collapse}")
            print(f"{that.auto_collapse}")
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def intezer_dynamic_class_instance():
    create_tmp_manifest()
    try:
        from intezer_dynamic import IntezerDynamic
        yield IntezerDynamic()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_completed_process_instance():
    class DummyCompletedProcess:
        def __init__(self):
            self.stdout = b"blah\nblah"
    yield DummyCompletedProcess()


@pytest.fixture
def dummy_get_response_class():
    class DummyGetResponse:
        def __init__(self, text):
            self.text = text

        def json(self):
            return {"status": self.text}
    yield DummyGetResponse


@pytest.fixture
def dummy_api_interface_class():
    class DummyApiInterface:
        @staticmethod
        def get_safelist():
            return []
    return DummyApiInterface


@pytest.fixture
def dummy_request_class():

    class DummyRequest():
        def __init__(self):
            self.file_path = "blah"
            self.file_name = "blah"
            self.extracted = []

        def add_extracted(self, path, name, description):
            self.extracted.append({"path": path, "name": name, "description": description})

    yield DummyRequest


@pytest.fixture
def dummy_al_intezer_api_instance(mocker):
    from intezer_dynamic import ALIntezerApi
    from assemblyline.common import log
    from logging import getLogger, DEBUG
    log.init_logging("assemblyline", log_level=DEBUG)

    al_intezer_api = ALIntezerApi(
            api_version="v2-0",
            api_key="sample_api_key",
            base_url="https://analyze.intezer.com/api/",
            on_premise_version=False
        )
    al_intezer_api.set_logger(getLogger("assemblyline"))
    mocker.patch.object(al_intezer_api, "_set_access_token", return_value=True)
    yield al_intezer_api


class TestIntezerDynamic:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(intezer_dynamic_class_instance):
        assert intezer_dynamic_class_instance.client is None

    @staticmethod
    def test_start(intezer_dynamic_class_instance, dummy_api_interface_class, mocker):
        from intezer_dynamic import ALIntezerApi
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()
        assert isinstance(intezer_dynamic_class_instance.client, ALIntezerApi)
        assert True

    @staticmethod
    def test_stop(intezer_dynamic_class_instance):
        intezer_dynamic_class_instance.stop()
        assert True

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, intezer_dynamic_class_instance, dummy_api_interface_class, dummy_get_response_class, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from json import loads
        from intezer_dynamic import ALIntezerApi

        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()

        service_task = ServiceTask(sample)
        task = Task(service_task)
        task.service_config = {
            "analysis_id": "",
        }
        intezer_dynamic_class_instance._task = task
        service_request = ServiceRequest(task)
        intezer_dynamic_class_instance.config["private_only"] = False

        mocker.patch.object(ALIntezerApi, "get_latest_analysis", return_value={"analysis_id": "blah"})
        mocker.patch.object(ALIntezerApi, "analyze_by_file", return_value="blah")
        mocker.patch.object(ALIntezerApi, "get_iocs", return_value={"files": [], "network": []})
        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps", return_value=[])
        mocker.patch.object(ALIntezerApi, "get_sub_analyses_by_id", return_value=[])

        # Actually executing the sample
        intezer_dynamic_class_instance.execute(service_request)

        # Code coverage
        task.service_config = {
            "analysis_id": "blah",
        }
        intezer_dynamic_class_instance._task = task
        service_request = ServiceRequest(task)
        intezer_dynamic_class_instance.execute(service_request)

        task.service_config = {"analysis_id": ""}
        intezer_dynamic_class_instance.config["is_on_premise"] = False
        mocker.patch.object(ALIntezerApi, "get_latest_analysis", return_value={"verdict": "not_supported"})
        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps", return_value=[])
        intezer_dynamic_class_instance.execute(service_request)

        mocker.patch.object(ALIntezerApi, "get_latest_analysis", return_value={"verdict": "failed"})
        intezer_dynamic_class_instance.execute(service_request)

        mocker.patch.object(ALIntezerApi, "get_latest_analysis", return_value={"verdict": "trusted"})
        intezer_dynamic_class_instance.execute(service_request)

    @staticmethod
    def test_get_analysis_metadata(intezer_dynamic_class_instance, dummy_api_interface_class, mocker):
        from intezer_dynamic import ALIntezerApi
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()

        analysis_metadata = {"analysis_id": "blah", "verdict": "malicious"}
        mocker.patch.object(ALIntezerApi, "get_latest_analysis", return_value=analysis_metadata)
        assert intezer_dynamic_class_instance._get_analysis_metadata("", "blah") == analysis_metadata
        assert intezer_dynamic_class_instance._get_analysis_metadata(
            "blah", "blah") == {"analysis_id": "blah", "verdict": None}

    @staticmethod
    def test_submit_file_for_analysis(
            intezer_dynamic_class_instance, dummy_request_class, dummy_get_response_class, dummy_api_interface_class,
            mocker):
        from intezer_sdk.api import IntezerApi
        from intezer_sdk.errors import ServerError
        from intezer_dynamic import ALIntezerApi
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()

        mocker.patch.object(ALIntezerApi, "analyze_by_file", return_value="blah")
        mocker.patch.object(ALIntezerApi, "get_file_analysis_response",
                            return_value=dummy_get_response_class("succeeded"))
        mocker.patch.object(ALIntezerApi, "get_latest_analysis", return_value={})
        mocker.patch("intezer_dynamic.sleep")
        assert intezer_dynamic_class_instance._submit_file_for_analysis(dummy_request_class(), "blah") == {}

        mocker.patch.object(ALIntezerApi, "get_file_analysis_response", return_value=dummy_get_response_class("failed"))
        assert intezer_dynamic_class_instance._submit_file_for_analysis(dummy_request_class(), "blah") == {}

        mocker.patch.object(IntezerApi, "analyze_by_file", side_effect=ServerError(
            415, dummy_get_response_class("blah")))
        assert intezer_dynamic_class_instance._submit_file_for_analysis(dummy_request_class(), "blah") == {}

        mocker.patch.object(IntezerApi, "analyze_by_file", side_effect=ServerError(
            500, dummy_get_response_class("blah")))
        assert intezer_dynamic_class_instance._submit_file_for_analysis(dummy_request_class(), "blah") == {}

        mocker.patch("intezer_dynamic.time", return_value=float("inf"))
        assert intezer_dynamic_class_instance._submit_file_for_analysis(dummy_request_class(), "blah") == {}

    @staticmethod
    @pytest.mark.parametrize("details, uninteresting_keys, expected_output",
                             [
                                 ({}, [], {}),
                                 ({"a": "b"}, [], {"a": "b"}),
                                 ({"a": "b"}, ["a"], {}),
                             ]
                             )
    def test_process_details(details, uninteresting_keys, expected_output):
        from intezer_dynamic import IntezerDynamic
        assert IntezerDynamic._process_details(details, uninteresting_keys) == expected_output

    @staticmethod
    def test_set_heuristic_by_verdict(intezer_dynamic_class_instance):
        from assemblyline_v4_service.common.result import ResultSection
        result_section = ResultSection("blah")
        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, None)
        assert result_section.heuristic is None

        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, "blah")
        assert result_section.heuristic is None

        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, "trusted")
        assert result_section.heuristic is None

        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, "malicious")
        assert result_section.heuristic.heur_id == 1

        result_section = ResultSection("blah")
        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, "known_malicious")
        assert result_section.heuristic.heur_id == 1

        result_section = ResultSection("blah")
        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, "suspicious")
        assert result_section.heuristic.heur_id == 2

        result_section = ResultSection("blah")
        intezer_dynamic_class_instance._set_heuristic_by_verdict(result_section, "interesting")
        assert result_section.heuristic.heur_id == 3

    @staticmethod
    def test_process_iocs(intezer_dynamic_class_instance, dummy_api_interface_class, mocker):
        from intezer_dynamic import ALIntezerApi
        from intezer_sdk.api import IntezerApi
        from assemblyline_v4_service.common.result import ResultSection
        from requests import HTTPError
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()
        parent_res_sec = ResultSection("blah")
        file_verdict_map = {}

        mocker.patch.object(ALIntezerApi, "get_iocs", return_value={"files": [], "network": []})
        intezer_dynamic_class_instance._process_iocs("blah", file_verdict_map, parent_res_sec)
        assert parent_res_sec.subsections == []
        assert file_verdict_map == {}

        mocker.patch.object(IntezerApi, "get_iocs", side_effect=HTTPError("FORBIDDEN"))
        intezer_dynamic_class_instance._process_iocs("blah", file_verdict_map, parent_res_sec)
        assert parent_res_sec.subsections == []
        assert file_verdict_map == {}

        mocker.patch.object(
            ALIntezerApi, "get_iocs",
            return_value={"files": [{"sha256": "blah", "verdict": "malicious"}],
                          "network": [{"ioc": "1.1.1.1", "type": "ip"},
                                      {"ioc": "blah.com", "type": "domain"}]})
        intezer_dynamic_class_instance._process_iocs("blah", file_verdict_map, parent_res_sec)
        correct_res_sec = ResultSection("Network Communication Observed")
        correct_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        correct_res_sec.add_tag("network.dynamic.domain", "blah.com")
        correct_res_sec.add_line("IOC: 1.1.1.1")
        correct_res_sec.add_line("IOC: blah.com")
        assert check_section_equality(parent_res_sec.subsections[0], correct_res_sec)
        assert file_verdict_map == {"blah": "malicious"}

    @staticmethod
    def test_process_ttps(intezer_dynamic_class_instance, dummy_api_interface_class, mocker):
        from intezer_dynamic import ALIntezerApi
        from intezer_sdk.api import IntezerApi
        from intezer_sdk.errors import UnsupportedOnPremiseVersion
        from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow
        from requests import HTTPError
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()
        parent_res_sec = ResultSection("blah")

        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps", return_value=[])
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        assert parent_res_sec.subsections == []

        mocker.patch.object(IntezerApi, "get_dynamic_ttps", side_effect=HTTPError("FORBIDDEN"))
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        assert parent_res_sec.subsections == []

        mocker.patch.object(IntezerApi, "get_dynamic_ttps", side_effect=UnsupportedOnPremiseVersion())
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        assert parent_res_sec.subsections == []

        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps",
                            return_value=[{"name": "blah", "description": "blah", "data": [], "severity": 1}]
                            )
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        correct_res_sec = ResultSection("Signature: blah", "blah")
        correct_res_sec.set_heuristic(4)
        correct_res_sec.heuristic.add_signature_id("blah", 10)
        assert check_section_equality(parent_res_sec.subsections[0].subsections[0], correct_res_sec)

        parent_res_sec = ResultSection("blah")
        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps", return_value=[
                            {"name": "InjectionInterProcess", "description": "blah", "data": [], "severity": 1}])
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        correct_res_sec = ResultSection("Signature: InjectionInterProcess", "blah")
        correct_res_sec.set_heuristic(7)
        correct_res_sec.heuristic.add_signature_id("InjectionInterProcess", 10)
        correct_res_sec.heuristic.add_attack_id("T1055")
        assert check_section_equality(parent_res_sec.subsections[0].subsections[0], correct_res_sec)

        parent_res_sec = ResultSection("blah")
        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps", return_value=[
                            {"name": "enumerates_running_processes", "description": "blah", "data": [{"wow": "print me!"}], "severity": 1}])
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        correct_res_sec = ResultSection("Signature: enumerates_running_processes", "blah")
        correct_res_sec.set_heuristic(8)
        correct_res_sec.heuristic.add_signature_id("enumerates_running_processes", 10)
        correct_res_sec.heuristic.add_attack_id("T1057")
        assert check_section_equality(parent_res_sec.subsections[0].subsections[0], correct_res_sec)

        parent_res_sec = ResultSection("blah")
        mocker.patch.object(ALIntezerApi, "get_dynamic_ttps",
                            return_value=[
                                {
                                    "name": "blah",
                                    "description": "blah",
                                    "data":
                                    [
                                        {"IP": "blah 2.2.2.2 blah"},
                                    ],
                                    "severity": 1
                                }
                            ]
                            )
        intezer_dynamic_class_instance._process_ttps("blah", parent_res_sec)
        correct_res_sec = ResultSection("Signature: blah", "blah")
        correct_res_sec.add_line("\tIP: blah 2.2.2.2 blah")
        correct_res_sec.set_heuristic(4)
        correct_res_sec.heuristic.add_signature_id("blah", 10)
        correct_ioc_res_sec = ResultTableSection("IOCs found in signature marks")
        correct_ioc_res_sec.add_row(TableRow(ioc_type="ip", ioc="2.2.2.2"))
        correct_ioc_res_sec.add_tag("network.dynamic.ip", "2.2.2.2")
        correct_res_sec.add_subsection(correct_ioc_res_sec)
        assert check_section_equality(parent_res_sec.subsections[0].subsections[0], correct_res_sec)

    @staticmethod
    def test_process_ttp_data(intezer_dynamic_class_instance):
        from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow
        sig_res = ResultSection("blah")
        ioc_table = ResultTableSection("blah")

        intezer_dynamic_class_instance._process_ttp_data(
            [
                {"wow": "print me!"},
                {"a": ""},
                {"IP": "1.1.1.1"},
                {"IP": "blah 2.2.2.2 blah"},
                {"command": "do bad thing"},
                {"DeletedFile": "blah.exe"},
                {"key": "HKEY\\Registry\\Key\\Path"},
                {"http_request": "http://blah.com/blah"},
                {"domain": "blah.ca"},
                {"domain": "blah.ca"},
                {"b": "blah"*150},
            ], sig_res, ioc_table,
        )
        correct_res_sec = ResultSection("blah")
        correct_res_sec.add_lines(
            ["\twow: print me!", "\tIP: 1.1.1.1", "\tIP: blah 2.2.2.2 blah", "\tcommand: do bad thing",
             "\tDeletedFile: blah.exe", "\tkey: HKEY\\Registry\\Key\\Path", "\thttp_request: http://blah.com/blah",
             "\tdomain: blah.ca",
             "\tb: blahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblahblah..."])
        correct_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        correct_res_sec.add_tag("dynamic.process.command_line", "do bad thing")
        correct_res_sec.add_tag("dynamic.process.file_name", "blah.exe")
        correct_res_sec.add_tag("dynamic.registry_key", "HKEY\\Registry\\Key\\Path")
        correct_res_sec.add_tag("network.dynamic.domain", "blah.ca")
        correct_ioc_res_sec = ResultTableSection("blah")
        correct_ioc_res_sec.add_row(TableRow(ioc_type="ip", ioc="2.2.2.2"))
        correct_ioc_res_sec.add_row(TableRow(ioc_type="domain", ioc="blah.com"))
        correct_ioc_res_sec.add_row(TableRow(ioc_type="uri", ioc="http://blah.com/blah"))
        correct_ioc_res_sec.add_row(TableRow(ioc_type="uri_path", ioc="/blah"))
        correct_ioc_res_sec.add_tag("network.dynamic.ip", "2.2.2.2")
        correct_ioc_res_sec.add_tag("network.dynamic.domain", "blah.com")
        correct_ioc_res_sec.add_tag("network.dynamic.uri", "http://blah.com/blah")
        correct_ioc_res_sec.add_tag("network.dynamic.uri_path", "/blah")
        assert check_section_equality(sig_res, correct_res_sec)
        assert check_section_equality(ioc_table, correct_ioc_res_sec)

    @staticmethod
    def test_handle_subanalyses(intezer_dynamic_class_instance, dummy_request_class, dummy_api_interface_class, mocker):
        from assemblyline_v4_service.common.result import ResultSection, ResultKeyValueSection, ResultProcessTreeSection, ProcessItem
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()

        mocker.patch.object(intezer_dynamic_class_instance.client, "get_sub_analyses_by_id", return_value=[])
        parent_result_section = ResultSection("blah")
        intezer_dynamic_class_instance._handle_subanalyses(
            dummy_request_class(), "blah", "blah", {}, parent_result_section)
        assert parent_result_section.subsections == []

        mocker.patch.object(
            intezer_dynamic_class_instance.client,
            "get_sub_analyses_by_id",
            return_value=[
                {
                    "sub_analysis_id": "blah",
                    "extraction_info": {
                        "processes": [
                            {
                                "process_id": 124,
                                "process_path": "blah2.exe",
                                "parent_process_id": 321,
                                "module_path": "blah2.exe"
                            },
                        ]
                    },
                    "source": "blah_blah",
                    "sha256": "blah2"
                }
            ]
        )
        mocker.patch.object(
            intezer_dynamic_class_instance.client,
            "get_sub_analysis_code_reuse_by_id",
            return_value={
                "families": [{"reused_gene_count": 2}],
                "blah": "blah"
            }
        )
        mocker.patch.object(
            intezer_dynamic_class_instance.client,
            "get_sub_analysis_metadata_by_id",
            return_value={
                "source": "blah",
                "blah": "blah"
            }
        )
        mocker.patch.object(intezer_dynamic_class_instance, "_process_families")
        mocker.patch.object(intezer_dynamic_class_instance.client, "download_file_by_sha256", return_value=True)
        correct_result_section = ResultKeyValueSection("Subanalysis report for blah2, extracted via blah blah")
        correct_result_section.update_items({"blah": "blah"})
        correct_code_reuse = ResultKeyValueSection("Code reuse detected")
        correct_code_reuse.update_items({"blah": "blah"})
        correct_result_section.add_subsection(correct_code_reuse)
        correct_process_tree = ResultProcessTreeSection("Spawned Process Tree")
        correct_process_tree.add_process(ProcessItem(pid=124, name="blah2.exe", cmd=None))
        correct_process_tree.add_tag("dynamic.processtree_id", "blah2.exe")
        correct_process_tree.add_tag("dynamic.process.file_name", "blah2.exe")
        dummy_request_class_instance = dummy_request_class()
        intezer_dynamic_class_instance._handle_subanalyses(
            dummy_request_class_instance, "blah", "blah", {}, parent_result_section)
        assert check_section_equality(parent_result_section.subsections[0], correct_result_section)
        assert check_section_equality(parent_result_section.subsections[1], correct_process_tree)
        assert dummy_request_class_instance.extracted[0]["description"] == "Extracted via blah blah"
        assert dummy_request_class_instance.extracted[0]["name"] == "blah2.sample"

    @staticmethod
    @pytest.mark.parametrize("families, file_verdict_map, correct_fvp",
                             [([],
                               {},
                               {}),
                              ([{"blah": "blah", "family_type": "blah", "family_name": "blah"}],
                               {},
                               {}),
                              ([{"family_id": "blah", "family_type": "blah", "family_name": "blah"}],
                               {},
                               {}),
                              ([{"family_id": "blah", "family_type": "application", "family_name": "blah"}],
                               {},
                               {}),
                              ([{"family_id": "blah", "family_type": "malware", "family_name": "blah"}],
                               {},
                               {"blah": "malicious"}),
                              ([{"family_id": "blah", "family_type": "malware", "family_name": "blah"}],
                               {"blah": "blah"},
                               {"blah": "malicious"}),
                              ([{"family_id": "blah", "family_type": "malware", "family_name": "blah"}],
                               {"blah": "malicious"},
                               {"blah": "malicious"}),
                              ([{"family_id": "blah", "family_type": "packer", "family_name": "blah"}],
                               {},
                               {"blah": "interesting"}),
                              ([{"family_id": "blah", "family_type": "packer", "family_name": "blah"}],
                               {"blah": "malicious"},
                               {"blah": "malicious"}),
                              ([{"family_id": "blah", "family_type": "packer", "family_name": "UPX"}],
                               {},
                               {}), ])
    def test_process_families(families, file_verdict_map, correct_fvp, intezer_dynamic_class_instance):
        from assemblyline_v4_service.common.result import ResultSection, ResultTableSection, TableRow

        parent_section = ResultSection("blah")
        intezer_dynamic_class_instance._process_families(families, "blah", file_verdict_map, parent_section)

        if not families:
            assert parent_section.subsections == []
        else:
            correct_result_section = ResultTableSection("Family Details")
            for family in families:
                if "family_id" in family:
                    family.pop("family_id")
                correct_result_section.add_row(TableRow(**family))

            assert check_section_equality(parent_section.subsections[0], correct_result_section)
            assert file_verdict_map == correct_fvp

    @staticmethod
    def test_process_extraction_info(intezer_dynamic_class_instance):
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        so = SandboxOntology()

        processes = [
            {
                "process_id": 123,
                "process_path": "blah.exe",
                "parent_process_id": 321,
                "module_path": "blah.exe"
            },
            {
                "process_id": 124,
                "process_path": "blah2.exe",
                "parent_process_id": 321,
                "module_path": "blah2.dll,blah"
            },
            {
                "process_id": 123,
                "process_path": "blah.exe",
                "parent_process_id": 321,
                "module_path": "blah.dll,blah"
            },
            {
                "process_id": 321,
                "process_path": "blah3.exe",
                "parent_process_id": 322,
                "module_path": "blah3.exe"
            },
        ]
        process_path_set = set()
        command_line_set = set()
        correct_processes = [
            {
                "start_time": float("-inf"),
                "end_time": float("inf"),
                "objectid": {
                    "tag": "blah.exe",
                    "treeid": None,
                    "processtree": None,
                    "time_observed": float("-inf")
                },
                "pobjectid": {
                    "tag": "blah3.exe",
                    "treeid": None,
                    "processtree": None,
                    "time_observed": float("-inf")
                },
                "pimage": "blah3.exe",
                "pcommand_line": None,
                "ppid": 321,
                "pid": 123,
                "image": "blah.exe",
                "command_line": "blah.exe blah.dll,blah",
                "integrity_level": None,
                "image_hash": None,
                "original_file_name": None,
            },
            {
                "start_time": float("-inf"),
                "end_time": float("inf"),
                "objectid": {
                    "tag": "blah2.exe",
                    "treeid": None,
                    "processtree": None,
                    "time_observed": float("-inf")
                },
                "pobjectid": {
                    "tag": "blah3.exe",
                    "treeid": None,
                    "processtree": None,
                    "time_observed": float("-inf")
                },
                "pimage": "blah3.exe",
                "pcommand_line": None,
                "ppid": 321,
                "pid": 124,
                "image": "blah2.exe",
                "command_line": "blah2.exe blah2.dll,blah",
                "integrity_level": None,
                "image_hash": None,
                "original_file_name": None,
            },
            {
                "start_time": float("-inf"),
                "end_time": float("inf"),
                "objectid": {
                    "tag": "blah3.exe",
                    "treeid": None,
                    "processtree": None,
                    "time_observed": float("-inf")
                },
                "pobjectid": {
                    "tag": None,
                    "treeid": None,
                    "processtree": None,
                    "time_observed": None
                },
                "pimage": None,
                "pcommand_line": None,
                "ppid": 322,
                "pid": 321,
                "image": "blah3.exe",
                "command_line": None,
                "integrity_level": None,
                "image_hash": None,
                "original_file_name": None,
            },
        ]
        intezer_dynamic_class_instance._process_extraction_info(processes, process_path_set, command_line_set, so)
        for index, process in enumerate(so.get_processes()):
            process_as_primitives = process.as_primitives()
            process_as_primitives["objectid"].pop("guid")
            process_as_primitives["pobjectid"].pop("guid")
            assert process_as_primitives == correct_processes[index]
        assert process_path_set == {"blah.dll,blah", "blah2.dll,blah", "blah2.exe", "blah.exe", "blah3.exe"}
        assert command_line_set == {"blah.exe blah.dll,blah", "blah2.exe blah2.dll,blah"}


class TestALIntezerApi:
    @staticmethod
    def test_set_logger(dummy_al_intezer_api_instance):
        dummy_al_intezer_api_instance.set_logger("blah")
        assert dummy_al_intezer_api_instance.log == "blah"

    @staticmethod
    def test_get_latest_analysis(dummy_al_intezer_api_instance):
        file_hash = "blah"
        private_only = "blah"
        correct_rest_response = {"result": {"details": "blah"}}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{file_hash}", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.get_latest_analysis(file_hash, private_only) == {"details": "blah"}

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{file_hash}", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_latest_analysis, args=(file_hash, private_only,), name="get_latest_analysis with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: "Good" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{file_hash}", exc=HTTPError("GONE"))
            assert dummy_al_intezer_api_instance.get_latest_analysis(file_hash, private_only) is None

            # Case 4: "Bad" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{file_hash}", exc=HTTPError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_latest_analysis, args=(file_hash, private_only,), name="get_latest_analysis with HTTPError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

    @staticmethod
    def test_get_iocs(dummy_al_intezer_api_instance):
        analysis_id = "blah"
        correct_rest_response = {"result": {"details": "blah"}}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/iocs", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.get_iocs(analysis_id) == {"details": "blah"}

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/iocs", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_iocs, args=(analysis_id,), name="get_iocs with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: "Good" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/iocs", exc=HTTPError("FORBIDDEN"))
            assert dummy_al_intezer_api_instance.get_iocs(analysis_id) == {"files": [], "network": []}

            # Case 4: "Bad" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/iocs", exc=HTTPError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_iocs, args=(analysis_id,), name="get_iocs with HTTPError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

    @staticmethod
    def test_get_dynamic_ttps(dummy_al_intezer_api_instance):
        from intezer_sdk.errors import UnsupportedOnPremiseVersion

        analysis_id = "blah"
        correct_rest_response = {"result": {"details": "blah"}}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/dynamic-ttps", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.get_dynamic_ttps(analysis_id) == {"details": "blah"}

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/dynamic-ttps", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_dynamic_ttps, args=(analysis_id,), name="get_dynamic_ttps with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: "Good" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/dynamic-ttps", exc=HTTPError("FORBIDDEN"))
            assert dummy_al_intezer_api_instance.get_dynamic_ttps(analysis_id) == []

            # Case 4: "Bad" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/dynamic-ttps", exc=HTTPError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_dynamic_ttps, args=(analysis_id,), name="get_dynamic_ttps with HTTPError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 5: UnsupportedOnPremiseVersion
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/dynamic-ttps", exc=UnsupportedOnPremiseVersion("blah"))
            assert dummy_al_intezer_api_instance.get_dynamic_ttps(analysis_id) == []

    @staticmethod
    def test_get_sub_analyses_by_id(dummy_al_intezer_api_instance):
        analysis_id = "blah"
        correct_rest_response = {"sub_analyses": {"details": "blah"}}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.get_sub_analyses_by_id(analysis_id) == {"details": "blah"}

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_sub_analyses_by_id, args=(analysis_id,), name="get_sub_analyses_by_id with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses", exc=HTTPError("blah"))
            assert dummy_al_intezer_api_instance.get_sub_analyses_by_id(analysis_id) == []

    @staticmethod
    def test_get_sub_analysis_code_reuse_by_id(dummy_al_intezer_api_instance):
        analysis_id = "blah"
        sub_analysis_id = "blah"
        correct_rest_response = {"result": {"details": "blah"}}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.get_sub_analysis_code_reuse_by_id(analysis_id, sub_analysis_id) == correct_rest_response

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_sub_analysis_code_reuse_by_id, args=(analysis_id, sub_analysis_id,), name="get_sub_analysis_code_reuse_by_id with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/code-reuse", exc=HTTPError("blah"))
            assert dummy_al_intezer_api_instance.get_sub_analysis_code_reuse_by_id(analysis_id, sub_analysis_id) is None

    @staticmethod
    def test_get_sub_analysis_metadata_by_id(dummy_al_intezer_api_instance):
        analysis_id = "blah"
        sub_analysis_id = "blah"
        correct_rest_response = {"result": {"details": "blah"}}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/metadata", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.get_sub_analysis_metadata_by_id(analysis_id, sub_analysis_id) == correct_rest_response

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/metadata", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.get_sub_analysis_metadata_by_id, args=(analysis_id, sub_analysis_id,), name="get_sub_analysis_metadata_by_id with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/analyses/{analysis_id}/sub-analyses/{sub_analysis_id}/metadata", exc=HTTPError("blah"))
            assert dummy_al_intezer_api_instance.get_sub_analysis_metadata_by_id(analysis_id, sub_analysis_id) == {}

    @staticmethod
    def test_download_file_by_sha256(dummy_al_intezer_api_instance):
        analysis_id = "blah"
        dir_path = "/tmp"
        correct_rest_response = {}
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{analysis_id}/download", json=correct_rest_response, status_code=200)
            assert dummy_al_intezer_api_instance.download_file_by_sha256(analysis_id, dir_path) is True

            # Case 2: ConnectionError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{analysis_id}/download", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.download_file_by_sha256, args=(analysis_id,dir_path,), name="download_file_by_sha256 with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: "Good" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{analysis_id}/download", exc=HTTPError("FORBIDDEN"))
            assert dummy_al_intezer_api_instance.download_file_by_sha256(analysis_id, dir_path) is False

            # Case 4: "Bad" HTTPError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{analysis_id}/download", exc=HTTPError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.download_file_by_sha256, args=(analysis_id,dir_path,), name="download_file_by_sha256 with HTTPError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 5: FileExistsError
            m.get(f"{dummy_al_intezer_api_instance.full_url}/files/{analysis_id}/download", exc=FileExistsError("blah"))
            assert dummy_al_intezer_api_instance.download_file_by_sha256(analysis_id, dir_path) is False

    @staticmethod
    def test_analyze_by_file(dummy_al_intezer_api_instance, dummy_get_response_class):
        from intezer_sdk.errors import ServerError
        from intezer_dynamic import CANNOT_EXTRACT_ARCHIVE
        sha256 = "blah"
        file_path = "/tmp/blah"
        file_name = "blah"
        verify_file_support = True
        analysis_id = "blah"
        correct_rest_response = {"result_url": f"blah/blah/{analysis_id}"}
        with open(file_path, "wb") as f:
            f.write(b"blah")
        with requests_mock.Mocker() as m:
            # Case 1: Successful call, status code 200, valid response
            m.post(f"{dummy_al_intezer_api_instance.full_url}/analyze", json=correct_rest_response, status_code=201)
            assert dummy_al_intezer_api_instance.analyze_by_file(sha256, file_path, file_name, verify_file_support) == analysis_id

            # Case 2: ConnectionError
            m.post(f"{dummy_al_intezer_api_instance.full_url}/analyze", exc=ConnectionError("blah"))
            p1 = Process(target=dummy_al_intezer_api_instance.analyze_by_file, args=(sha256, file_path, file_name, verify_file_support,), name="analyze_by_file with ConnectionError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None

            # Case 3: "Good" ServerError
            m.post(f"{dummy_al_intezer_api_instance.full_url}/analyze", exc=ServerError(415, dummy_get_response_class("blah")))
            assert dummy_al_intezer_api_instance.analyze_by_file(sha256, file_path, file_name, verify_file_support) == "file_type_not_supported"

            # Case 4: "Good" ServerError
            m.post(f"{dummy_al_intezer_api_instance.full_url}/analyze", exc=ServerError(500, dummy_get_response_class("blah")))
            assert dummy_al_intezer_api_instance.analyze_by_file(sha256, file_path, file_name, verify_file_support) == "failed"

            # Case 5: "Good" ServerError
            m.post(f"{dummy_al_intezer_api_instance.full_url}/analyze", exc=ServerError(CANNOT_EXTRACT_ARCHIVE, dummy_get_response_class("blah")))
            assert dummy_al_intezer_api_instance.analyze_by_file(sha256, file_path, file_name, verify_file_support) == "file_type_not_supported"

            # Case 6: "Bad" ServerError
            m.post(f"{dummy_al_intezer_api_instance.full_url}/analyze", exc=ServerError(999, dummy_get_response_class("blah")))
            p1 = Process(target=dummy_al_intezer_api_instance.analyze_by_file, args=(sha256, file_path, file_name, verify_file_support,), name="analyze_by_file with HTTPError")
            p1.start()
            p1.join(timeout=2)
            p1.terminate()
            assert p1.exitcode is None
