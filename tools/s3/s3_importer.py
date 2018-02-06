"""

"""
import argparse
import sys

try:
    from cloudbridge.cloud.factory import CloudProviderFactory, ProviderList
except ImportError:
    CloudProviderFactory = None
    ProviderList = None


def download_from_s3(access_key, secret_key, bucket_name, object_name, output):
    aws_config = {'aws_access_key': access_key,
                  'aws_secret_key': secret_key}
    connection = CloudProviderFactory().create_provider(ProviderList.AWS, aws_config)
    try:
        bucket = connection.object_store.get(bucket_name)
        if bucket is None:
            # TODO: inform user that bucket does not exist.
            return None
    except Exception:
        # This generic exception will be replaced by specific exception
        # once proper exceptions are exposed by CloudBridge.
        # TODO: inform user that could not read bucket.
        return None
    key = bucket.get(object_name)
    with open(output, "w+") as f:
        key.save_content(f)


def __main__():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--access', type=str, help="AWS access key", required=True)
    parser.add_argument('-s', '--secret', type=str, help="AWS secret key", required=True)
    parser.add_argument('-b', '--bucket', type=str, help="AWS S3 bucket name", required=True)
    parser.add_argument('-o', '--object', type=str, help="AWS S3 object name", required=True)
    parser.add_argument('-u', '--output', type=str, help="Downloaded file", required=True)
    args = parser.parse_args(sys.argv[1:])
    download_from_s3(
        access_key=args.access,
        secret_key=args.secret,
        bucket_name=args.bucket,
        object_name=args.object,
        output=args.output)


if __name__ == "__main__":
    __main__()
