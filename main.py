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

EXPIRE_AFTER_SECONDS=600

# Only for POC, this needs to come from a vault
KEY=b'uEwvd9ZR8ukdEvvMSaE9ov6PVoAn1BB8SnE81rcWUqE'


def generate_filename():
    '''
    Generating a non-guessable filename. This has 256-bits of randomness
    '''
    return f"{str(time())}-{urlsafe_b64encode(get_random_bytes(32)).decode('ASCII').strip('=')}"


def generate_otp(file_name, user_id='', contet_hash=''):
    '''
    Generates an OTP using the filename, user ID, content hash and a cryptographically secure random number.
    Just the random number should do it, but I'm being paranoid here. GCS API only validates the final value
    '''

    hmac = HMAC.new(KEY, digestmod=SHA256)
    
    hmac.update(
        bytes(file_name, "ASCII") +
        bytes(contet_hash, "ASCII") +
        bytes(str(user_id), "ASCII") +
        get_random_bytes(32) # nonce
    )

    return hmac.hexdigest()


def sign(request):
    """
    Returns a signed URL (for file upload) and an OTP
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
        "expiration": timedelta(seconds=EXPIRE_AFTER_SECONDS),
        "service_account_email": credentials.service_account_email,
        "access_token": credentials.token,
        "method": "PUT",
        "virtual_hosted_style": True
    }
    # Adding information in the request
    request_json = request.get_json()

    # Content MD5 is a standard integrity check in GCS
    content_md5 = ''
    # If the use-case requires stronger checks a stronger hashing algorithm 
    # such as SHA-256 should be used, but the check has to be done after the object
    # has landed in the bucket as Google Cloud Storage does not support SHA256 as
    # as an integrity checking machanism as of Jan 2022 
    if request_json and 'content-md5' in request_json:
        content_md5 = request_json['content-md5']
        sign_request['content_md5'] = content_md5


    content_sha256 = ""
    # GCS API will not perform the hash validation for PUT requests. Ideally this must be stored
    # somewhere else (e.g. in a database) so that the files content can be read and SHA256 hash
    # of the content can be calculated after the object lands in the bucket. This code avoides
    # that step 
    if request_json and 'content-sha256' in request_json:
        content_sha256 = request_json['content-sha256']
        headers['x-content-sha256'] = content_sha256

    uid = 0
    if request_json and 'user-id' in request_json:
        uid = int(request_json['user-id'])


    # Adding custom headers in the request
    if "headers" in request_json:
        try:
            for key, val in request_json['headers'].iteritems():
                headers[key] = str(val)
        except:
            #TODO: log what the issue is. but this is just for a PoC
            pass

    # adding the OTP
    OTP = generate_otp(
        file_name, 
        user_id=uid,
        contet_hash=content_sha256 if len(content_sha256) > 0 else content_md5 # prefer SHA256 if present
    )
    headers['x-otp'] = OTP


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
    