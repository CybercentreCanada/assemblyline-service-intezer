import os
import pytest
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
    yield DummyGetResponse


@pytest.fixture
def dummy_api_interface_class():
    class DummyApiInterface:
        @staticmethod
        def get_safelist():
            return []
    return DummyApiInterface


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
    def test_execute(sample, intezer_dynamic_class_instance, dummy_api_interface_class, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from json import loads

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

        # Actually executing the sample
        intezer_dynamic_class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")
        correct_result_response.pop("service_context")
        test_result_response.pop("service_context")
        assert test_result_response == correct_result_response

        # Code coverage
        task.service_config = {
            "analysis_id": "blah",
        }
        intezer_dynamic_class_instance._task = task
        service_request = ServiceRequest(task)
        intezer_dynamic_class_instance.execute(service_request)

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
        assert IntezerDynamic.process_details(details, uninteresting_keys) == expected_output

    @staticmethod
    def test_set_heuristic_by_verdict(intezer_dynamic_class_instance):
        from assemblyline_v4_service.common.result import ResultSection
        result_section = ResultSection("blah")
        intezer_dynamic_class_instance.set_heuristic_by_verdict(result_section, None)
        assert result_section.heuristic is None

        intezer_dynamic_class_instance.set_heuristic_by_verdict(result_section, "blah")
        assert result_section.heuristic is None

        intezer_dynamic_class_instance.set_heuristic_by_verdict(result_section, "trusted")
        assert result_section.heuristic is None

        intezer_dynamic_class_instance.set_heuristic_by_verdict(result_section, "malicious")
        assert result_section.heuristic.heur_id == 1

        result_section = ResultSection("blah")
        intezer_dynamic_class_instance.set_heuristic_by_verdict(result_section, "known_malicious")
        assert result_section.heuristic.heur_id == 1

        result_section = ResultSection("blah")
        intezer_dynamic_class_instance.set_heuristic_by_verdict(result_section, "suspicious")
        assert result_section.heuristic.heur_id == 2

    @staticmethod
    def test_process_iocs(intezer_dynamic_class_instance, dummy_api_interface_class, mocker):
        from assemblyline_v4_service.common.result import ResultSection
        from requests import HTTPError
        mocker.patch.object(intezer_dynamic_class_instance, "get_api_interface", return_value=dummy_api_interface_class)
        intezer_dynamic_class_instance.start()
        parent_res_sec = ResultSection("blah")
        file_verdict_map = {}

        mocker.patch.object(intezer_dynamic_class_instance.client, "get_iocs", return_value={"files": [], "network": []})
        intezer_dynamic_class_instance.process_iocs("blah", file_verdict_map, parent_res_sec)
        assert parent_res_sec.subsections == []
        assert file_verdict_map == {}

        mocker.patch.object(intezer_dynamic_class_instance.client, "get_iocs", side_effect=HTTPError("blah"))
        intezer_dynamic_class_instance.process_iocs("blah", file_verdict_map, parent_res_sec)
        assert parent_res_sec.subsections == []
        assert file_verdict_map == {}

        mocker.patch.object(intezer_dynamic_class_instance.client, "get_iocs", return_value={"files": [{"sha256": "blah", "verdict": "malicious"}], "network": [{"ioc": "1.1.1.1", "type": "ip"}, {"ioc": "blah.com", "type": "domain"}]})
        intezer_dynamic_class_instance.process_iocs("blah", file_verdict_map, parent_res_sec)
        correct_res_sec = ResultSection("Network Communication Observed")
        correct_res_sec.add_tag("network.dynamic.ip", "1.1.1.1")
        correct_res_sec.add_tag("network.dynamic.domain", "blah.com")
        correct_res_sec.add_line("IOC: 1.1.1.1")
        correct_res_sec.add_line("IOC: blah.com")
        assert check_section_equality(parent_res_sec.subsections[0], correct_res_sec)
        assert file_verdict_map == {"blah": "malicious"}
