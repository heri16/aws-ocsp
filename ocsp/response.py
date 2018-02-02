import logging
import base64
import enum
from datetime import datetime, timezone, timedelta
from typing import Callable, Tuple, Optional, Union

from asn1crypto import x509, keys
from asn1crypto.ocsp import OCSPRequest, OCSPResponse, CertId
from oscrypto import asymmetric
from ocspbuilder import OCSPResponseBuilder

from .util import _type_name, _pretty_message


logger = logging.getLogger(__name__)


# Enums

class ResponseStatus(enum.Enum):
    successful = 'successful'
    malformed_request = 'malformed_request'
    internal_error = 'internal_error'
    try_later = 'try_later'
    sign_required = 'sign_required'
    unauthorized = 'unauthorized'


class CertificateStatus(enum.Enum):
    good = 'good'
    revoked = 'revoked'
    key_compromise = 'key_compromise'
    ca_compromise = 'ca_compromise'
    affiliation_changed = 'affiliation_changed'
    superseded = 'superseded'
    cessation_of_operation = 'cessation_of_operation'
    certificate_hold = 'certificate_hold'
    remove_from_crl = 'remove_from_crl'
    privilege_withdrawn = 'privilege_withdrawn'
    unknown = 'unknown'


# Types

StrOrBytes = Union[str, bytes]
PrivateKey = Union[keys.PrivateKeyInfo, asymmetric.PrivateKey]
Certificate = Union[x509.Certificate, asymmetric.Certificate]

ValidateFuncRet = Tuple[CertificateStatus, Optional[datetime]]
ValidateFunc = Callable[[int, bytes, bytes, x509.Certificate], ValidateFuncRet]
CertRetrieveFuncRet = Union[str, asymmetric.Certificate, x509.Certificate]
CertRetrieveFunc = Callable[[int, bytes, bytes, x509.Certificate], CertRetrieveFuncRet]


# Methods

def _fail(status: ResponseStatus) -> OCSPResponse:
    builder = OCSPResponseBuilder(response_status=status.value)
    return builder.build()

def _get_req_cert_id(ocsp_request: OCSPRequest) -> CertId:
    # Get the certificate request
    tbs_request = ocsp_request['tbs_request']
    request_list = tbs_request['request_list']
    if len(request_list) != 1:
        logger.warning('Received OCSP request with multiple sub requests')
        raise NotImplemented('Combined requests not yet supported')
    single_request = request_list[0]  # TODO: Support more than one request
    req_cert_id = single_request['req_cert'] 

    return req_cert_id

# API classes

class OCSPResponder:

    _issuer_cert = None

    def __init__(self, issuer_cert: Certificate, responder_cert: Certificate, responder_key: PrivateKey,
                       validate_func: ValidateFunc, cert_retrieve_func: CertRetrieveFunc,
                       next_update_days: int = 7):
        """
        Create a new OCSPResponder instance.
        :param issuer_cert: The issuer certificate.
        :param responder_cert: The certificate of the OCSP responder
            with the `OCSP Signing` extension.
        :param responder_key: The private key belonging to the
            responder cert.
        :param validate_func: A function that - given a certificate serial -
            will return the appropriate :class:`CertificateStatus` and -
            depending on the status - a revocation datetime.
        :param cert_retrieve_func: A function that - given a certificate serial -
            will return the corresponding certificate as a string.
        :param next_update_days: The ``nextUpdate`` value that will be written
            into the response. Default: 7 days.
        """
        # Certs and keys
        self.issuer_cert = issuer_cert
        self._responder_cert = responder_cert
        self._responder_key = responder_key

        # Functions
        self._validate = validate_func
        self._cert_retrieve = cert_retrieve_func

        # Next update
        self._next_update_days = next_update_days

    @classmethod
    def frompfx(cls, responder_pkcs12: StrOrBytes, pkcs12_password: StrOrBytes,
                       validate_func: ValidateFunc, cert_retrieve_func: CertRetrieveFunc,
                       next_update_days: int = 7):
        """
        Create a new OCSPResponder instance from a pkcs12 filepath or bytes.
        :param responder_pfx: Path to or Bytes of the pfx / pkcs12 that also contains the issuer cert.
        :param validate_func: A function that - given a certificate serial -
            will return the appropriate :class:`CertificateStatus` and -
            depending on the status - a revocation datetime.
        :param cert_retrieve_func: A function that - given a certificate serial -
            will return the corresponding certificate as a string.
        :param next_update_days: The ``nextUpdate`` value that will be written
            into the response. Default: 7 days.
        """
        # Certs and keys
        _responder_key, _responder_cert, chain_certs = asymmetric.load_pkcs12(responder_pkcs12, pkcs12_password)

        _issuer_cert = None
        for cert in chain_certs:
            if cert.asn1.subject == _responder_cert.asn1.issuer:
                _issuer_cert = cert
                break

        return cls(_issuer_cert, _responder_cert, _responder_key,
                validate_func=validate_func,
                cert_retrieve_func=cert_retrieve_func,
                next_update_days=next_update_days)

    @classmethod
    def frompem(cls, issuer_cert: StrOrBytes, responder_cert: StrOrBytes, responder_key: StrOrBytes,
                       validate_func: ValidateFunc, cert_retrieve_func: CertRetrieveFunc,
                       next_update_days: int = 7):
        """
        Create a new OCSPResponder instance from filepaths or bytes.
        :param issuer_cert: Path to or Bytes of the issuer certificate.
        :param responder_cert: Path to or Bytes of the certificate of the OCSP responder
            with the `OCSP Signing` extension.
        :param responder_key: Path to or Bytes of the private key belonging to the
            responder cert.
        :param validate_func: A function that - given a certificate serial -
            will return the appropriate :class:`CertificateStatus` and -
            depending on the status - a revocation datetime.
        :param cert_retrieve_func: A function that - given a certificate serial -
            will return the corresponding certificate as a string.
        :param next_update_days: The ``nextUpdate`` value that will be written
            into the response. Default: 7 days.
        """
        # Certs and keys
        _issuer_cert = asymmetric.load_certificate(issuer_cert)
        _responder_cert = asymmetric.load_certificate(responder_cert)
        _responder_key = asymmetric.load_private_key(responder_key)

        return cls(_issuer_cert, _responder_cert, _responder_key,
                validate_func=validate_func,
                cert_retrieve_func=cert_retrieve_func,
                next_update_days=next_update_days)

    @property
    def issuer_dname(self) -> x509.Name:
        return self._issuer_cert.subject

    @property
    def issuer_public_key(self) -> x509.PublicKeyInfo:
        return self._issuer_cert.public_key

    @property
    def issuer_cert(self) -> x509.Certificate:
        return self._issuer_cert

    @issuer_cert.setter
    def issuer_cert(self, value):
        """
        An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
        of the issuer.
        """

        is_oscrypto = isinstance(value, asymmetric.Certificate)
        if not is_oscrypto and not isinstance(value, x509.Certificate):
            raise TypeError(_pretty_message(
                '''
                issuer must be an instance of asn1crypto.x509.Certificate or
                oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        self._issuer_cert = value

    def build_ocsp_response(self, ocsp_request: OCSPRequest) -> OCSPResponse:
        """
        Create and return an OCSP response from an OCSP request.
        """
        # Get the certificate serial
        req_cert_id = _get_req_cert_id(ocsp_request)
        #serial = req_cert_id['serial_number'].native
        #issuer_key_hash = req_cert_id['issuer_key_hash'].native
        #issuer_name_hash = req_cert_id['issuer_name_hash'].native
        #hash_algorithm = req_cert_id['hash_algorithm']
        #hash_algo_name = hash_algorithm['algorithm'].native
        #hash_algo_params = hash_algorithm['parameters'].native

        # Check certificate status
        try:
            certificate_status, revocation_date = self._validate(req_cert_id, self.issuer_cert)
        except Exception as e:
            logger.exception('Could not determine certificate status: %s', e)
            return _fail(ResponseStatus.internal_error)

        # Retrieve certificate
        try:
            subject_cert_contents = self._cert_retrieve(req_cert_id, self.issuer_cert)
        except Exception as e:
            logger.exception('Could not retrieve certificate with serial %s: %s', serial, e)
            return _fail(ResponseStatus.internal_error)

        # Parse certificate if needed
        if isinstance(subject_cert_contents, x509.Certificate):
            subject_cert = subject_cert_contents
        elif isinstance(subject_cert_contents, asymmetric.Certificate):
            subject_cert = subject_cert_contents.asn1
        else:
            try:
                subject_cert = asymmetric.load_certificate(subject_cert_contents.encode('utf8'))
            except Exception as e:
                logger.exception('Returned certificate with serial %s is invalid: %s', serial, e)
                return _fail(ResponseStatus.internal_error)

        # Build the response
        builder = OCSPResponseBuilder(**{
            'response_status': ResponseStatus.successful.value,
            'certificate': subject_cert,
            'certificate_status': certificate_status.value,
            'revocation_date': revocation_date,
        })

        # Parse extensions
        tbs_request = ocsp_request['tbs_request']
        for extension in tbs_request['request_extensions']:
            extn_id = extension['extn_id'].native
            critical = extension['critical'].native
            value = extension['extn_value'].parsed

            # This variable tracks whether any unknown extensions were encountered
            unknown = False

            # Handle nonce extension
            if extn_id == 'nonce':
                builder.nonce = value.native

            # That's all we know
            else:
                unknown = True

            # If an unknown critical extension is encountered (which should not
            # usually happen, according to RFC 6960 4.1.2), we should throw our
            # hands up in despair and run.
            if unknown is True and critical is True:
                logger.warning('Could not parse unknown critical extension: %r',
                        dict(extension.native))
                return _fail(ResponseStatus.internal_error)

            # If it's an unknown non-critical extension, we can safely ignore it.
            elif unknown is True:
                logger.info('Ignored unknown non-critical extension: %r', dict(extension.native))

        # Set certificate issuer
        builder.certificate_issuer = self._issuer_cert

        # Set next update date
        builder.next_update = datetime.now(timezone.utc) + timedelta(days=self._next_update_days)

        return builder.build(self._responder_key, self._responder_cert)


class OCSPResponders:

    def __init__(self):
        self._responders = {}
        self.default_responder = None

    @property
    def responders(self):
        return self._responders

    def add(self, responder: OCSPResponder) -> OCSPResponder:
        for key_hash_algo in ['sha1', 'sha256']:
            k = getattr(responder.issuer_public_key, key_hash_algo)
            self._responders[k] = responder

        return responder

    def add_new(self, *args, **kwargs) -> OCSPResponder:
        responder = OCSPResponder(*args, **kwargs)
        return self.add(responder)

    def add_frompfx(self, *args, **kwargs) -> OCSPResponder:
        responder = OCSPResponder.frompfx(*args, **kwargs)
        return self.add(responder)

    def add_frompem(self, *args, **kwargs) -> OCSPResponder:
        responder = OCSPResponder.frompem(*args, **kwargs)
        return self.add(responder)

    def build_ocsp_response(self, ocsp_request: OCSPRequest) -> OCSPResponse:
        # Get the issuer_key_hash
        try:
            req_cert_id = _get_req_cert_id(ocsp_request)
        except Exception as e:
            logger.exception('Could not parse OCSPRequest: %s', e)
            return _fail(ResponseStatus.malformed_request)
        else:
            try:
                issuer_key_hash = req_cert_id['issuer_key_hash'].native
            except ValueError as e:
                responder = self.default_responder
            else:
                # Get the correct responder for the request
                responder = self._responders.get(issuer_key_hash)

            if responder:
                return responder.build_ocsp_response(ocsp_request)
            else:
                return _fail(ResponseStatus.unauthorized)
