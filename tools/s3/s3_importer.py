"""

"""
import argparse
import sys
import boto
from boto.exception import S3ResponseError
from boto.s3.connection import S3Connection
from boto.s3.key import Key

try:
    from cloudbridge.cloud.factory import CloudProviderFactory, ProviderList
except ImportError:
    CloudProviderFactory = None
    ProviderList = None


def download_from_s3(access_key, secret_key, bucket, object):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--access', type=str, help="AWS access key", required=True)
    parser.add_argument('-s', '--secret', type=str, help="AWS secret key", required=True)
    parser.add_argument('-b', '--bucket', type=str, help="AWS S3 bucket name", required=True)
    parser.add_argument('-o', '--object', type=str, help="AWS S3 object name", required=True)
    args = parser.parse_args(sys.argv)
    download_from_s3(access_key=args.access, secret_key=args.secret, bucket=args.bucket, object=args.object)


if __name__ == "__main__":
    sys.exit(main())