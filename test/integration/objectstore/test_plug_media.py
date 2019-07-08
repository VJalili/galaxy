"""

"""

import json
import os
import string

from base import integration_util  # noqa: I202
from base.populators import (
    DatasetPopulator,
)

from test_jobs import _get_datasets_files_in_path

TEST_INPUT_FILES_CONTENT = "abc def 123 456"


class BaseUserBasedObjectStoreTestCase(integration_util.IntegrationTestCase):
    framework_tool_and_types = True

    @classmethod
    def handle_galaxy_config_kwds(cls, config):
        template = string.Template("""<?xml version="1.0"?>
        <object_store type="hierarchical">
            <backends>
                <backend id="default" type="disk" order="1">
                    <files_dir path="${temp_directory}/files_default"/>
                    <extra_dir type="temp" path="${temp_directory}/tmp_default"/>
                    <extra_dir type="job_work" path="${temp_directory}/job_working_directory_default"/>
                </backend>
            </backends>
        </object_store>
        """)

        temp_directory = cls._test_driver.mkdtemp()
        cls.object_stores_parent = temp_directory
        disk_store_path = os.path.join(temp_directory, "files_default")
        os.makedirs(disk_store_path)
        cls.files_default_path = disk_store_path
        config_path = os.path.join(temp_directory, "object_store_conf.xml")
        with open(config_path, "w") as f:
            f.write(template.safe_substitute({"temp_directory": temp_directory}))
        config["object_store_config_file"] = config_path

    @classmethod
    def setup_objectstore(cls):
        pass

    def setUp(self):
        super(BaseUserBasedObjectStoreTestCase, self).setUp()

    def run_tool(self, tool_id, history_id, inputs):
        self.dataset_populator.run_tool(
            tool_id,
            inputs,
            history_id,
            assert_ok=True,
        )
        self.dataset_populator.wait_for_history(history_id)

    @staticmethod
    def get_files_count(directory):
        return sum(len(files) for _, _, files in os.walk(directory))

    def plug_user_media(self, category, path, order, quota="0.0", usage="0.0", authz_id=None):
        payload = {
            "category": category,
            "path": path,
            "authz_id": authz_id,
            "order": order,
            "quota": quota,
            "usage": usage
        }
        response = self._post(path="plugged_media/create", data=payload)
        return json.loads(response.content)


class DataPersistedOnUserMedia(BaseUserBasedObjectStoreTestCase):

    def setUp(self):
        super(DataPersistedOnUserMedia, self).setUp()

    def test_files_count_and_content_in_user_media(self):
        with self._different_user("vahid@test.com"):
            user_media_path = os.path.join(self._test_driver.mkdtemp(), "user/media/path/")
            plugged_media = self.plug_user_media("local", user_media_path, "1")

            # No file should be in the instance-wide storage before
            # execution of any tool.
            assert self.get_files_count(self.files_default_path) == 0

            # No file should be in user's plugged media before
            # execution of any tool.
            assert self.get_files_count(plugged_media.get("path")) == 0

            self.dataset_populator = DatasetPopulator(self.galaxy_interactor)
            with self.dataset_populator.test_history() as history_id:
                hda1 = self.dataset_populator.new_dataset(history_id, content=TEST_INPUT_FILES_CONTENT)
                self.dataset_populator.wait_for_history(history_id)
                hda1_input = {"src": "hda", "id": hda1["id"]}
                create_10_inputs = {
                    "input1": hda1_input,
                    "input2": hda1_input,
                }
                self.run_tool("create_10", history_id, create_10_inputs)

                assert self.get_files_count(self.files_default_path) == 0
                assert self.get_files_count(plugged_media.get("path")) == 11

                # Assert content
                files = _get_datasets_files_in_path(plugged_media.get("path"))
                expected_content = [str(x) for x in range(1, 11)] + [TEST_INPUT_FILES_CONTENT]
                for filename in files:
                    with open(filename) as f:
                        content = f.read().strip()
                        assert content in expected_content
                        expected_content.remove(content)
                # This confirms that no two (or more) files had same content.
                assert len(expected_content) == 0
