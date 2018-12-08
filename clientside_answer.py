#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Module: clientside.py
Author: zlamberty
Created: 2017-09-20

Description:
    client-side encryption functions for `s3`

Usage:
    >>> python clientside.py upload -m mymessage -k mykey -b bucket -s s3keyname
    >>> python clientside.py download -b bucket -s s3keyname
    >>> python clientside.py encrypt -m mymessage

"""

import argparse

import boto3


# ----------------------------- #
#   Main routine                #
# ----------------------------- #

def encrypt(message, encr_key_alias):
    """encrypt a message using an aws kms key"""
    session = boto3.session.Session()
    kms = session.client('kms')

    encrypted_message = kms.encrypt(
        KeyId='alias/{}'.format(encr_key_alias),
        Plaintext=message
    )['CiphertextBlob']

    return encrypted_message


def decrypt(encrypted_message):
    """decrypt a message using an aws kms key"""
    session = boto3.session.Session()
    kms = session.client('kms')
    message = kms.decrypt(CiphertextBlob=encrypted_message)['Plaintext']
    return message


def encrypt_and_upload(message, encr_key_alias, bucket, s3_key_name):
    """encrypt a message using an aws kms key, and then upload it to s3

    note: the s3 key is the key name of the file and has nothing to do with
    encryption

    """
    session = boto3.session.Session()

    # encrypt the message
    encrypted_message = encrypt(message, encr_key_alias)

    # save that encrypted message to `bucket` as `keyname`
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket)
    s3file = bucket.Object(key=s3_key_name)
    s3file.put(
        Body=encrypted_message,
        ContentType='text/plain'
    )


def download_and_decrypt(bucket, s3_key_name):
    """download an encrypted message on s3 and decrypt it

    note: the s3 key is the key name of the file and has nothing to do with
    encryption

    """
    session = boto3.session.Session()

    # download the contents of `bucket` file `s3_key_name` to a string
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket)
    s3file = bucket.Object(key=s3_key_name)
    encrypted_message = s3file.get()['Body'].read()

    # decrypt that string and return it below
    decrypted_message = decrypt(encrypted_message)

    return decrypted_message


# ----------------------------- #
#   command line                #
# ----------------------------- #

def parse_args():
    parser = argparse.ArgumentParser()

    # shared flags parent parser
    parent = argparse.ArgumentParser(add_help=False)

    keyalias = "the alias of the encryption key we should use"
    parent.add_argument("-k", "--keyalias", help=keyalias, required=True)

    # subcommands --------------------------------------------------------------
    subparsers = parser.add_subparsers(
        title='subcommands', description='valid subcommands',
        help='additional help', dest='cmd'
    )

    # encrypt
    enc = subparsers.add_parser('encrypt', parents=[parent])

    message = "the message we wish to encrypt"
    enc.add_argument("-m", "--message", help=message, required=True)

    # decrypt
    dec = subparsers.add_parser('decrypt')

    message = "the message we wish to decrypt"
    dec.add_argument("-m", "--message", help=message, required=True)

    # encrypt_and_upload
    encup = subparsers.add_parser('upload', parents=[parent])

    encup.add_argument("-m", "--message", help=message, required=True)

    bucket = "the name of the S3 bucket (no need for s3:// or any of that)"
    encup.add_argument("-b", "--bucket", help=bucket, required=True)

    s3keyname = "the key name of an S3 file"
    encup.add_argument("-s", "--s3keyname", help=s3keyname, required=True)

    # download_and_decrypt
    downdec = subparsers.add_parser('download')

    downdec.add_argument("-b", "--bucket", help=bucket, required=True)
    downdec.add_argument("-s", "--s3keyname", help=s3keyname, required=True)

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.cmd == 'encrypt':
        print(encrypt(message=args.message, encr_key_alias=args.keyalias))
    elif args.cmd == 'decrypt':
        print(decrypt(encrypted_message=args.message))
    elif args.cmd == 'upload':
        encrypt_and_upload(
            message=args.message, bucket=args.bucket, s3_key_name=args.s3keyname,
            encr_key_alias=args.keyalias
        )
    elif args.cmd == 'download':
        decrypted_message = download_and_decrypt(
            bucket=args.bucket, s3_key_name=args.s3keyname
        )
        print(decrypted_message)
