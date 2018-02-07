import os
import base64
from urllib.parse import unquote
from datetime import datetime, timezone

from botocore.exceptions import ClientError
import boto3
dynamodb = boto3.resource('dynamodb')

from asn1crypto import pem

from ocsp.http import parse_ocsp_request, http_ocsp_response
from ocsp.response import OCSPResponders
from ocsp.model import CertificateStatus

from ocsp import CertId, Certificate
from ocsp import ValidateFuncRet, CertRetrieveFuncRet

from log_cfg import logger


OCSP_COUNT = int(os.environ['OCSP_COUNT'])

DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE')
DYNAMODB_DATETIME_FORMAT = os.environ.get('DYNAMODB_DATETIME_FORMAT', '%Y-%m-%dT%H:%M:%S.%f%z')

responders = OCSPResponders()
for i in range(1, OCSP_COUNT+1):
    ocsp_pfx = os.environ['OCSP_PFX_{}'.format(i)]
    ocsp_pfx_password = os.environ.get('OCSP_PFX_PASS_{}'.format(i), None)
    ocsp_days = os.environ.get('OCSP_DAYS_{}'.format(i), 1)

    # Each issuer should have a unique dynamodb lookup table
    table = os.environ.get('DYNAMODB_TABLE_{}'.format(i)) or DYNAMODB_TABLE

    r = responders.add_frompfx(
        ocsp_pfx, ocsp_pfx_password,
        validate_func=(lambda cid, issuer_cert, table=table: validate_cert(cid, issuer_cert, table)),
        #cert_retrieve_func=(lambda cid, issuer_cert, table=table: get_cert(cid, issuer_cert, table)),
        next_update_days=ocsp_days,
    )

def validate_cert(req_cert_id: CertId, issuer_cert: Certificate, lookup_table: str = None) -> ValidateFuncRet:
    """
    The certificate records are stored in DynamoDB Table with the
    the lookup key of '<cert_authority_key_id_hex>:<cert_serial_hex>'.
    """
    if not lookup_table:
        return (CertificateStatus.unknown, None)
    else:
        table = dynamodb.Table(lookup_table)

        cert_serial_num = req_cert_id['serial_number'].native
        cert_serial_hex = hex(cert_serial_num)[2:]
        cert_authority_key_id_hex = issuer_cert.key_identifier.hex()

        try:
            # fetch cert record from the database
            response = table.get_item(
                Key={
                    'uid': '{}:{}'.format(cert_authority_key_id_hex, cert_serial_hex)
                }
            )
        except ClientError as e:
            logger.exception(e.response['Error']['Message'])
            return (CertificateStatus.unknown, None)
        else:
            if not 'Item' in response:
                return (CertificateStatus.unknown, None)

            item = response['Item']
            logger.info("DynamoDB GetItem succeeded: %s", item)

            status = item.get('status')
            revokedAt = item.get('revokedAt') 
            if revokedAt:
                dt = datetime.strptime(revokedAt, DYNAMODB_DATETIME_FORMAT)
                return (CertificateStatus[status], dt)
            else:
                return (CertificateStatus[status], None)

    #serial = req_cert_id['serial_number'].native
    #issuer_key_hash = req_cert_id['issuer_key_hash'].native
    #issuer_name_hash = req_cert_id['issuer_name_hash'].native
    #hash_algorithm = req_cert_id['hash_algorithm']
    #hash_algo_name = hash_algorithm['algorithm'].native
    #hash_algo_params = hash_algorithm['parameters'].native

    #return (CertificateStatus.unknown, None)
    #revoked_time = datetime(2015, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    #return (CertificateStatus.key_compromise, revoked_time)

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


def respond(event: dict, context) -> dict:
    """
    An OCSP GET request contains the DER-in-base64 encoded OCSP request in the
    HTTP request URL.
    An OCSP POST request contains the DER encoded OCSP request in the HTTP
    request body.
    """
    logger.debug("APIGW event: %s", event)

    http_method = event.get('httpMethod')
    if not http_method:
        with open('config/sample-ocsp-request.txt', 'r') as f:
            der = base64.b64decode(f.read().strip())
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
            logger.info("OCSP Next Update: %s", single_response['next_update'].native)

    response = http_ocsp_response(ocsp_response, max_age=43200)
    logger.debug("APIGW Response: %s", response)
    return response

