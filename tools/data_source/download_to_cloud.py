"""

"""

import argparse
import sys

# try:
#     from cloudbridge.cloud.factory import CloudProviderFactory, ProviderList
# except ImportError:
#     CloudProviderFactory = None
#     ProviderList = None


def download_to_cloud(provider, access_key, secret_key, bucket_name, object_name, output):
    print('\n\n\n\n\n\n\n---------------------------- in the tool\n\n\n\n\n\n\n\n')
    # if CloudProviderFactory is None:
    #     raise Exception(NO_CLOUDBRIDGE_ERROR_MESSAGE)
    # connection = self._configure_provider(provider, credentials)
    #
    # bucket_obj = connection.object_store.get(bucket)
    # if bucket_obj is None:
    #     raise ObjectNotFound("Could not find the specified bucket `{}`.".format(bucket))
    #
    # history = trans.sa_session.query(trans.app.model.History).get(history_id)
    # downloaded = []
    # for hda in history.datasets:
    #     if dataset_ids is None or hda.dataset.id in dataset_ids:
    #         object_label = hda.name
    #         if overwrite_existing is False and bucket_obj.get(object_label) is not None:
    #             object_label += "-" + datetime.datetime.now().strftime("%y-%m-%d-%H-%M-%S")
    #         created_obj = bucket_obj.create_object(object_label)
    #         created_obj.upload_from_file(hda.dataset.get_file_name())
    #         downloaded.append(object_label)
    # return downloaded

def __main__():
    print('\n\n\n\n\n\n\n---------------------------- in the tool\n\n\n\n\n\n\n\n')
    # parser = argparse.ArgumentParser()
    # parser.add_argument('-p', '--provider', type=str, help="Provider", required=True)
    # parser.add_argument('-a', '--access', type=str, help="AWS access key", required=True)
    # parser.add_argument('-s', '--secret', type=str, help="AWS secret key", required=True)
    # parser.add_argument('-b', '--bucket', type=str, help="AWS S3 bucket name", required=True)
    # parser.add_argument('-o', '--object', type=str, help="AWS S3 object name", required=True)
    # parser.add_argument('-u', '--output', type=str, help="Downloaded file", required=True)
    # args = parser.parse_args(sys.argv[1:])
    # download_to_cloud("aaa", "bbb", "ccc", "ddd", "eee", "fff")

if __name__ == "__main__":
    __main__()
