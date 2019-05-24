"""Integration tests for job and object store interactions."""

import os
import string

from base import integration_util  # noqa: I202
from base.populators import (
    DatasetPopulator,
)

DISTRIBUTED_OBJECT_STORE_CONFIG_TEMPLATE = string.Template("""<?xml version="1.0"?>
<object_store type="hierarchical">
    <backends>
        <object_store type="distributed" id="primary" order="0">
            <backends>
                <backend id="files1" type="disk" weight="1">
                    <files_dir path="${temp_directory}/files1"/>
                    <extra_dir type="temp" path="${temp_directory}/tmp1"/>
                    <extra_dir type="job_work" path="${temp_directory}/job_working_directory1"/>
                </backend>
                <backend id="files2" type="disk" weight="1">
                    <files_dir path="${temp_directory}/files2"/>
                    <extra_dir type="temp" path="${temp_directory}/tmp2"/>
                    <extra_dir type="job_work" path="${temp_directory}/job_working_directory2"/>
                </backend>
            </backends>
        </object_store>
        <object_store type="disk" id="secondary" order="1">
            <files_dir path="${temp_directory}/files3"/>
            <extra_dir type="temp" path="${temp_directory}/tmp3"/>
            <extra_dir type="job_work" path="${temp_directory}/job_working_directory3"/>
        </object_store>
    </backends>
</object_store>
""")


class ObjectStoreJobsIntegrationTestCase(integration_util.IntegrationTestCase):

    framework_tool_and_types = True

    @classmethod
    def handle_galaxy_config_kwds(cls, config):
        temp_directory = cls._test_driver.mkdtemp()
        cls.object_stores_parent = temp_directory
        for disk_store_file_name in ["files1", "files2", "files3"]:
            disk_store_path = os.path.join(temp_directory, disk_store_file_name)
            os.makedirs(disk_store_path)
            setattr(cls, "%s_path" % disk_store_file_name, disk_store_path)
        config_path = os.path.join(temp_directory, "object_store_conf.xml")
        with open(config_path, "w") as f:
            f.write(DISTRIBUTED_OBJECT_STORE_CONFIG_TEMPLATE.safe_substitute({"temp_directory": temp_directory}))
        config["object_store_config_file"] = config_path

    def setUp(self):
        super(ObjectStoreJobsIntegrationTestCase, self).setUp()
        self.dataset_populator = DatasetPopulator(self.galaxy_interactor)
        with self.dataset_populator.test_history() as history_id:
            hda1 = self.dataset_populator.new_dataset(history_id, content="1 2 3")
            create_10_inputs = {
                "input1": {"src": "hda", "id": hda1["id"]},
                "input2": {"src": "hda", "id": hda1["id"]},
            }
            self.dataset_populator.run_tool(
                "create_10",
                create_10_inputs,
                history_id,
                assert_ok=True,
            )
            self.dataset_populator.wait_for_history(history_id)

    def test_files_count_in_each_objectstore_backend(self):
        """
        According to the ObjectStore configuration given in the
        `DISTRIBUTED_OBJECT_STORE_CONFIG_TEMPLATE` variable, datasets
        can be stored on three backends, named:
            -   primary/files1;
            -   primary/files2;
            -   secondary/files3.

        Objectstore _randomly_ distributes tools outputs on
        `primary/files1` and `primary/files2`, and will use
        `secondary/files3` and both `primary` backends fail.

        This test runs a tools that creates ten dummy datasets,
        and asserts if ObjectStore correctly creates ten files
        in `primary/files1` and `primary/files2`, and none in
        `secondary/files3`, assuming it will not fail persisting
        data in `primary` backend.
        """
        files_1_count = _files_count(self.files1_path)
        files_2_count = _files_count(self.files2_path)
        files_3_count = _files_count(self.files3_path)

        # Ensure no files written to the secondary/inactive hierarchical disk store.
        assert files_3_count == 0

        # Ensure the 10 inputs were written to one of the distributed object store's disk
        # stores (it will have either 10 or 11 depending on whether the input was also
        # written there. The other disk store may or may not have the input file so should
        # have at most one file.
        assert (files_1_count + files_2_count == 10) or (files_1_count + files_2_count == 11)

        # Other sanity checks on the test - just make sure the test was setup as intended
        # and not actually testing object store behavior.
        assert (files_1_count <= 11) and (files_2_count <= 11)
        assert (files_1_count >= 0) and (files_2_count >= 0)


def _files_count(directory):
    return sum(len(files) for _, _, files in os.walk(directory))
