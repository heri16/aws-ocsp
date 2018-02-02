import logging
import base64
import hashlib
from time import mktime
from email.utils import formatdate
from typing import Optional

from asn1crypto.ocsp import OCSPRequest, OCSPResponse

from .response import ResponseStatus, _fail


logger = logging.getLogger(__name__)

def parse_ocsp_request(request_der: bytes) -> (Optional[OCSPRequest], Optional[OCSPResponse]):
    """
    Parse the request bytes, return an ``OCSPRequest`` instance.
    """
    try:
        return (OCSPRequest.load(request_der), None)
    except Exception as e:
        logger.exception('Could not load/parse OCSPRequest: %s', e)
        return (None, _fail(ResponseStatus.malformed_request))

def http_ocsp_response(ocsp_response: OCSPResponse, max_age: int = 86400) -> dict:
    ocsp_response_bytes = ocsp_response.dump()

    # calculate sha1 digest of ocsp_response
    h = hashlib.sha1()
    h.update(ocsp_response_bytes)

    # create a http response
    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/ocsp-response",
            "ETag": h.hexdigest(),
        },
        "body": base64.b64encode(ocsp_response_bytes).decode('utf8'),
        "isBase64Encoded": True,
    }

    # conform http response to RFC 5019
    if ocsp_response['response_status'].native == ResponseStatus.successful.value:
        response_headers = response['headers']
        ocsp_response_data = ocsp_response.response_data
        if ocsp_response_data['produced_at']:
            ts = mktime(ocsp_response_data['produced_at'].native.timetuple())
            response_headers["Last-Modified"] = formatdate(timeval=ts, localtime=False, usegmt=True)

            for single_response in ocsp_response_data['responses']:
                if single_response['next_update']:
                    ts = mktime(single_response['next_update'].native.timetuple())
                    response_headers["Expires"] = formatdate(timeval=ts, localtime=False, usegmt=True)
                    response_headers["Cache-Control"] = "max-age={},public,no-transform,must-revalidate".format(max_age)
                    break

    return response