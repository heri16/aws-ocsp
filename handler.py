import os
import json
import base64
import logging
from urllib.parse import unquote
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import boto3
dynamodb = boto3.resource('dynamodb')

from ocsp.http import parse_ocsp_request, http_ocsp_response
from ocsp.response import OCSPResponders, CertificateStatus

from ocsp import CertId, Certificate
from ocsp import ValidateFuncRet, CertRetrieveFuncRet

ISSUER_COUNT = int(os.environ['ISSUER_COUNT'])

responders = OCSPResponders()
for i in range(1, ISSUER_COUNT+1):
    ocsp_pfx = os.environ['OCSP_PFX_{}'.format(i)]
    ocsp_pfx_password = os.environ['OCSP_PFX_PASS_{}'.format(i)]

    # Each issuer should have a unique dynamodb lookup table
    table = os.environ.get('DYNAMODB_TABLE_{}'.format(i))

    r = responders.add_frompfx(
        ocsp_pfx, ocsp_pfx_password,
        validate_func=(lambda cid, issuer_cert, table=table: validate_cert(cid, issuer_cert, table)),
        cert_retrieve_func=(lambda cid, issuer_cert, table=table: get_cert(cid, issuer_cert, table)),
    )

OCSP_DEFAULT_REQUEST = 'MG8wbTBGMEQwQjAJBgUrDgMCGgUABBQYEy+ej9QcS4v1YlHWNbL0fh+cngQUfqTT8lJftqDD3fV+PTbQlG4K+74CCQClAUsjbsYHoqIjMCEwHwYJKwYBBQUHMAECBBIEENM9dTSRus0yJWyK3m2s+fg='

def validate_cert(req_cert_id: CertId, issuer_cert: Certificate, lookup_table: str = None) -> ValidateFuncRet:
    """
    Assume the certificates are stored in DynamoDB Table with the
    serial as the lookup key.
    """
    # table = dynamodb.Table(lookup_table)
    # fetch todo from the database
    # result = table.get_item(
    #     Key={
    #         'id': event['pathParameters']['id']
    #     }
    # )

    serial = req_cert_id['serial_number'].native
    issuer_key_hash = req_cert_id['issuer_key_hash'].native
    issuer_name_hash = req_cert_id['issuer_name_hash'].native
    hash_algorithm = req_cert_id['hash_algorithm']
    hash_algo_name = hash_algorithm['algorithm'].native
    #hash_algo_params = hash_algorithm['parameters'].native

    return (CertificateStatus.good, None)

    # if certificate_is_valid(serial):
    #     return (CertificateStatus.good, None)
    # elif certificate_is_expired(serial):
    #     expired_at = get_expiration_date(serial)
    #     return (CertificateStatus.revoked, expired_at)
    # elif certificate_is_revoked(serial):
    #     revoked_at = get_revocation_date(serial)
    #     return (CertificateStatus.revoked, revoked_at)
    # else:
    #     return (CertificateStatus.unknown, None)

def get_cert(req_cert_id: CertId, issuer_cert: Certificate, lookup_table: str = None) -> CertRetrieveFuncRet:
    """
    Assume the certificates are stored in DynamoDB Table with the
    serial as the lookup key.
    """
    # table = dynamodb.Table(lookup_table)

    serial = req_cert_id['serial_number'].native

    from asn1crypto import x509

    tbs_cert = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial,
        'issuer': issuer_cert.subject,
    })
    cert = x509.Certificate({
        'tbs_certificate': tbs_cert
    })
    return cert

    #with open('certs/yulia.cer', 'r') as f:
    #    return f.read().strip()


def respond(event: dict, context) -> dict:
    """
    An OCSP GET request contains the DER-in-base64 encoded OCSP request in the
    HTTP request URL.
    An OCSP POST request contains the DER encoded OCSP request in the HTTP
    request body.
    """
    logger.debug("Lambda Event: %s", event)

    http_method = event.get('httpMethod')
    if not http_method:
        der = base64.b64decode(OCSP_DEFAULT_REQUEST)
    elif http_method == 'GET':
        request_param = event['pathParameters'].get('request_b64')
        request_data = unquote(request_param)
        der = base64.b64decode(request_data)
    elif event.get('isBase64Encoded'):
        request_data = event['body']
        der = base64.b64decode(request_data)
    elif isinstance(event['body'], str):
        logger.warn("Http Request Body seems invalid: %s", type(event['body']))
        logger.warn(str(event['body']))
        der = event['body'].encode()
    else:
        logger.warn("Http Request Body seems invalid: %s", type(event['body']))
        logger.warn(str(event['body']))
        der = bytes(event['body'])

    ocsp_request, error = parse_ocsp_request(der)

    if error:
        ocsp_response = error
    else:
        ocsp_response = responders.build_ocsp_response(ocsp_request)

    if ocsp_response['response_status'].native == 'successful':
        ocsp_response_data = ocsp_response.response_data
        for single_response in ocsp_response_data['responses']:
            logger.info("Certificate Revocation Status: %s", single_response['cert_status'].name)

    return http_ocsp_response(ocsp_response)
