"""

"""

import json
import os
import requests
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

    def purge_datasets(self, history_id, dataset_id):
        """
        Using this method instead of the galaxy_interactor delete method
        because that method assumes all paths are API paths, hence adds
        `api/` to the beginning of the path, which fails when using
        Galaxy controllers such as history.
        :return:
        """
        data = {
            "purge": True,
            "key": self.galaxy_interactor.api_key
        }
        controller_url = "{}/{}".format(
            self.galaxy_interactor.api_url,
            "histories/{}/contents/{}".format(history_id, dataset_id))
        return requests.delete(controller_url, params=data)

    @staticmethod
    def get_files_count(directory):
        return sum(len(files) for _, _, files in os.walk(directory))


class DataPersistedOnUserMedia(BaseUserBasedObjectStoreTestCase):

    def setUp(self):
        super(DataPersistedOnUserMedia, self).setUp()

    def test_files_count_and_content_in_user_media(self):
        with self._different_user("vahid@test.com"):
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
                history_details = self._get(path="histories/" + history_id)
                datasets = json.loads(history_details.content)["state_ids"]["ok"]

                assert len(datasets) == 11

                for dataset_id in datasets:
                    self.purge_datasets(history_id, dataset_id)
