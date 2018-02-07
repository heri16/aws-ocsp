import os
import http.client as httplib
from datetime import datetime

from botocore.exceptions import ClientError
import boto3
s3 = boto3.resource('s3')
dynamodb = boto3.resource('dynamodb')

from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError

from pynamodb.exceptions import DoesNotExist, PutError, DeleteError, UpdateError

from ocsp.model import CertRecordModel, CertificateStatus
from ocsp.util import read_pem_file, load_certs, fetch_chain_via_aia 

from log_cfg import logger


TRUST_ROOTS = os.environ['TRUST_ROOTS']
TRUST_CERTS = load_certs(read_pem_file(TRUST_ROOTS))

DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE')
DYNAMODB_DATETIME_FORMAT = os.environ.get('DYNAMODB_DATETIME_FORMAT', '%Y-%m-%dT%H:%M:%S.%f%z')

def event(event, context):
    """
    Triggered by s3 events, object create and remove

    """
    # Sample event:
    #
    # _event = {'Records': [{'eventVersion': '2.0', 'eventSource': 'aws:s3', 'awsRegion': 'us-east-1',
    #                        'eventTime': '2017-11-25T23:57:38.988Z', 'eventName': 'ObjectCreated:Put',
    #                        'userIdentity': {'principalId': 'AWS:AROAJWJG5IVL3URF4WKKK:su-xx-test-create'},
    #                        'requestParameters': {'sourceIPAddress': '75.82.111.45'},
    #                        'responseElements': {'x-amz-request-id': '9E39B8F9A3D22C83',
    #                                             'x-amz-id-2': 'GiWcmOHnxnxOJa64k5rkgTsiiwo+JOR3p2DvuQ6txQXl9jC0jNhO+gbDwwP/3WKAl4oPbVZsTE4='},
    #                        's3': {'s3SchemaVersion': '1.0', 'configurationId': 'dad7b639-0cd8-4e47-a2ae-91cc5bf866c8',
    #                               'bucket': {'name': 'su-xx', 'ownerIdentity': {'principalId': 'AEZOG5WRKFUM2'},
    #                                          'arn': 'arn:aws:s3:::su-xx'},
    #                               'object': {'key': 'test/bbc498ea-d23b-11e7-af42-2a31486da301', 'size': 11060,
    #                                          'eTag': 'd50cb2e8d7ad6768d46b3d47ba9b241e',
    #                                          'sequencer': '005A1A0372C5A1D292'}}}]}

    logger.debug('S3 event: %s', event)
    event_name = event['Records'][0]['eventName']

    if 'ObjectCreated:' in event_name:
        return obj_created(event, context)
    elif 'ObjectRemoved:' in event_name:
        return obj_removed(event, context)

def obj_created(event, context):
    s3_bucket_name = event['Records'][0]['s3']['bucket']['name']
    s3_key = event['Records'][0]['s3']['object']['key']

    filename, _fileext = os.path.splitext(os.path.basename(s3_key))
    item_alias_uid = filename.lower()
    logger.info("Certificate %s was added to bucket: %s", item_alias_uid, s3_bucket_name)

    cert_pem = None
    try:
        s3_obj = s3.Object(s3_bucket_name, s3_key)
        resp = s3_obj.get()
        f = resp['Body']
        try:
            cert_pem = f.read()
        except:
            logger.exception("Cannot read content of s3 object: %s/%s", s3_bucket_name, s3_key)
            return _response(httplib.UNPROCESSABLE_ENTITY, "Cannot read content of s3 object: {}/{}".format(s3_bucket_name, s3_key))
        finally:
            f.close()
    except:
        logger.exception("s3 object not found: %s/%s", s3_bucket_name, s3_key)
        return _response(httplib.NOT_FOUND, "s3 object not found: {}/{}".format(s3_bucket_name, s3_key))

    try:
        certs = fetch_chain_via_aia(cert_pem)

        subject_cert = certs[0]
        if len(certs) > 1:
            intermediates = certs[1:]
        else:
            intermediates = None

        # Self-signed certificates cannot be revoked & should not be registered
        if subject_cert.self_issued and subject_cert.self_signed != 'no':
            return _response(httplib.FORBIDDEN, "Rejected root certificate: {}/{}".format(s3_bucket_name, s3_key))

        validContext = ValidationContext(trust_roots=TRUST_CERTS, allow_fetching=False, revocation_mode='soft-fail')
        validator = CertificateValidator(subject_cert, intermediates, validation_context=validContext)
    except Exception as e:
        logger.exception("Problem with X.509 Certificate: %s", e)
        return _response(httplib.UNPROCESSABLE_ENTITY, "Problem with X.509 Certificate: {}".format, e)
    else:
        try:
            validator.validate_usage(set())

            cert_serial_num = subject_cert.serial_number
            cert_serial_hex = hex(cert_serial_num)[2:]
            cert_key_id_hex = subject_cert.key_identifier.hex()
            cert_authority_key_id_hex = subject_cert.authority_key_identifier.hex()
            cert_subject = subject_cert.subject.native

            logger.debug("cert_serial_num: %s", cert_serial_num)
            logger.debug("cert_serial_hex: %s", cert_serial_hex)
            logger.debug("cert_key_id_hex: %s", cert_key_id_hex)
            logger.debug("cert_authority_key_id_hex: %s", cert_authority_key_id_hex)
            logger.debug("cert_subject: %s", cert_subject)

            item_uid = '{}:{}'.format(cert_authority_key_id_hex, cert_serial_hex)

            table = dynamodb.Table(DYNAMODB_TABLE)

            # TODO: Not use Pynamodb
            cert_record = CertRecordModel()
            cert_record.uid = item_uid
            cert_record.keyId = cert_key_id_hex
            cert_record.subject = cert_subject
            cert_record.status = CertificateStatus.good.name

            # fetch any existing alias record from the database
            response = table.get_item(
                Key={
                    'uid': item_alias_uid
                }
            )

            if 'Item' in response:
                item_alias = response['Item']
                if 'key' in item_alias:
                    # update old cert record in the database
                    table.update_item(
                        Key=item_alias['key'],
                        UpdateExpression='SET #attr1 = :val1, #attr2 = :val2, #attr3 = :val2',
                        ExpressionAttributeNames={
                            '#attr1': 'status',
                            '#attr2': 'revokedAt',
                            '#attr3': 'updatedAt',
                        },
                        ExpressionAttributeValues={
                            ':val1': CertificateStatus.superseded.name,
                            ':val2': datetime.now().astimezone().strftime(DYNAMODB_DATETIME_FORMAT),
                        }
                    )
                    logger.info("Certificate %s revoked under uid: %s", item_alias_uid, item_alias['key']['uid'])

            # save the cert record to the database
            cert_record.save()
            try:
                # Add new alias record to the database
                table.put_item(
                    Item={
                        'uid': item_alias_uid,
                        'key': {
                            'uid': item_uid
                        },
                    }
                )
            except:
                # remove the cert record from the database if its alias could not be added
                cert_record.delete()
                raise

            logger.info("Certificate %s registered under uid: %s", item_alias_uid, item_uid)

        except PathValidationError as e:
            logger.exception(e)
            return _response(httplib.FORBIDDEN, "X.509 Path Validation Failed: {}".format, e)

        except ClientError as e:
            logger.exception(e.response['Error']['Message'])
            return _response(httplib.INTERNAL_SERVER_ERROR, e.response['Error']['Message'])

        except ValueError as e:
            logger.exception(e)
            return _response(httplib.INTERNAL_SERVER_ERROR, "PynamoDB Validation Error: {}".format, e)

        except Exception as e:
            logger.exception(e)
            return _response(httplib.INTERNAL_SERVER_ERROR, "Internal Error: {}".format, e)

    return _response(httplib.ACCEPTED)


def obj_removed(event, context):
    s3_bucket_name = event['Records'][0]['s3']['bucket']['name']
    s3_key = event['Records'][0]['s3']['object']['key']

    filename, _fileext = os.path.splitext(os.path.basename(s3_key))
    item_alias_uid = filename.lower()
    logger.info("Certificate %s was removed from bucket: %s", item_alias_uid, s3_bucket_name)

    table = dynamodb.Table(DYNAMODB_TABLE)
    try:
        # fetch alias record from the database
        response = table.get_item(
            Key={
                'uid': item_alias_uid
            }
        )
    except ClientError as e:
        logger.exception(e.response['Error']['Message'])
        return _response(httplib.INTERNAL_SERVER_ERROR, e.response['Error']['Message'])
    else:
        if not 'Item' in response:
            return _response(httplib.UNPROCESSABLE_ENTITY, "Item Alias not found in DynamoDB: {}".format(item_alias_uid))

        item_alias = response['Item']
        if not 'key' in item_alias:
            return _response(httplib.UNPROCESSABLE_ENTITY, "Invalid Item Alias found in DynamoDB: {}".format(item_alias_uid))

        try:
            # update cert record in the database
            table.update_item(
                Key=item_alias['key'],
                UpdateExpression='SET #attr1 = :val1, #attr2 = :val2, #attr3 = :val2',
                ExpressionAttributeNames={
                    '#attr1': 'status',
                    '#attr2': 'revokedAt',
                    '#attr3': 'updatedAt',
                },
                ExpressionAttributeValues={
                    ':val1': CertificateStatus.revoked.name,
                    ':val2': datetime.now().astimezone().strftime(DYNAMODB_DATETIME_FORMAT),
                }
            )
            logger.info("Certificate %s revoked under uid: %s", item_alias_uid, item_alias['key']['uid'])
        except ClientError as e:
            logger.exception(e.response['Error']['Message'])
            return _response(httplib.INTERNAL_SERVER_ERROR, e.response['Error']['Message'])
        
        # delete alias record from the database
        table.delete_item(
            Key={
                'uid': item_alias_uid
            }
        )

    return _response(httplib.ACCEPTED)


def _response(statusCode, error = None, *args, **kwargs):
    response = {
        'statusCode': statusCode,
    }
    if callable(error):
        response['body'] = {
            'error_message': error(*args, **kwargs)
        }
    elif error:
        response['body'] = {
            'error_message': "{}".format(error)
        }
    logger.debug("S3 Response: %s", response)
    return response

