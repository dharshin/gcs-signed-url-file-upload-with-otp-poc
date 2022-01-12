from datetime import timedelta
from time import time
from base64 import urlsafe_b64encode

import json

from google import auth
from google.auth.transport import requests
from google.cloud.storage import Client

from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256


BUCKET='signedurl-poc-dds'

MIN_SIZE=1 # 1 Byte
MAX_SIZE=1000000 # 1 MB

EXP=timedelta(seconds=600)

# Only for POC, this needs to come from a vault
KEY=b'uEwvd9ZR8ukdEvvMSaE9ov6PVoAn1BB8SnE81rcWUqE'


def generate_filename():
    '''
    Generating a non-guessable filename. This has 256-bits of randomness
    '''
    return f"{str(time())}-{urlsafe_b64encode(get_random_bytes(32)).decode('ASCII').strip('=')}"


def generate_otp(file_name, user_id=0, contet_hash=''):
    '''
    Generates an OTP using the filename, user ID, content hash and a cryptographically secure random number.
    Just the random number should do it, but I'm being paranoid here. GCS API only validates the final value
    '''
    nonce = urlsafe_b64encode(get_random_bytes(32)).decode('ASCII').strip('=')
    content = bytes(f"{file_name}{str(user_id)}{contet_hash}{nonce}", "ASCII")

    hmac = HMAC.new(KEY, digestmod=SHA256)
    hmac.update(content)

    return hmac.hexdigest()


def sign(request):
    """
    Returns a signed URL (for file upload) and an OTP for 
    """
    credentials, project_id = auth.default()
    if credentials.token is None:
        # Perform a refresh request to populate the access token of the
        # current credentials.
        credentials.refresh(requests.Request())

    # Connecting to the bucket
    client = Client()
    bucket = client.get_bucket(BUCKET)

    #
    file_name = generate_filename()
    object = bucket.blob(file_name)

    # Mandatory header
    headers = {
        "X-Goog-Content-Length-Range": f"{MIN_SIZE},{MAX_SIZE}" # limitting the upload file size
    }

    # mandatory fields
    sign_request = {
        "version": "v4",
        "expiration": EXP,
        "service_account_email": credentials.service_account_email,
        "access_token": credentials.token,
        "method": "PUT",
        "virtual_hosted_style": True
    }
    # Adding information in the request
    request_json = request.get_json()

    # Content MD5 is a standard integrity check in GCS
    content_md5 = ''
    # "MD5! OMG the sky is fallling!"
    # Calm down!...
    #   1. This is just a checksum and the only one that we can use with GCS
    #   2. It should be good enough for most use cases given the short validity
    #      of the signed URL. 
    #   3. If the use-case requires stronger checks a stronger hashing algorithm 
    #      such as SHA-256 should be used, but the check has to be done after the object
    #      has landed in the bucket as Google Cloud Storage does not support it as of
    #      Jan 2022 
    if request_json and 'content-md5' in request_json:
        content_md5 = request_json['content-md5']
        sign_request['content_md5'] = content_md5

    uid = 0
    if request_json and 'user-id' in request_json:
        uid = int(request_json['user-id'])

    # Adding custom headers in the request
    header_json = {}
    if "headers" in request.args:
        header_json = json.loads(request.args.get('headers'))

        for key, val in header_json.iteritems():
            headers[key] = str(val)

    # adding the OTP
    OTP = generate_otp(file_name, user_id=uid, contet_hash=content_md5)
    headers['otp'] = OTP


    # Adding headers to the request
    sign_request['headers']=headers

    # Debugging
    # debug = sign_request.copy()
    # debug['access_token']='###'
    # debug['expiration']=str(EXP)

    return json.dumps({
        'url': object.generate_signed_url(**sign_request),
        'otp': OTP,
        #'debug': debug,
        #'request': request.get_json()
    })
    