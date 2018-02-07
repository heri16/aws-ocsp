import re
import textwrap
import logging
from urllib.request import urlopen

from asn1crypto import pem, x509, cms

logger = logging.getLogger(__name__)


def read_pem_file(filepath):
    with open(filepath, 'rb') as f:
        return read_pem(f.read())

def read_pem(pem_data):
    if not pem.detect(pem_data):
        return [pem_data]

    der_bytes_list = []
    for _, _, der_bytes in pem.unarmor(pem_data, multiple=True):
        der_bytes_list.append(der_bytes)
    return der_bytes_list

def load_certs(der_bytes_list):
    certs = []
    for der_bytes in der_bytes_list:
        certs.append(x509.Certificate.load(der_bytes))
    return certs

def fetch_chain_via_aia(value):
    certs = []

    if isinstance(value, x509.Certificate):
        last_cert = value
        certs.append(last_cert)
        cert_pem = None
    else:
        cert_pem = value

    found_next = True
    while found_next:
        if cert_pem:
            # parse the certificate data
            parsed_certs = load_certs(read_pem(cert_pem))
            for cert in parsed_certs:
                logger.debug("%d: %s", len(certs), cert.subject.native['common_name'])
            last_cert = parsed_certs[-1]
            certs.extend(parsed_certs)

        # try to fetch the next certificate
        found_next = False
        aia = last_cert.authority_information_access_value if last_cert else None
        if aia:
            for desc in aia:
                if desc['access_method'].native == 'ca_issuers' and desc['access_location'].name == 'uniform_resource_identifier':
                    found_next = True
                    cert_pem = None

                    uri = desc['access_location'].chosen.native
                    try:
                        with urlopen(uri) as infile:
                            content_type = infile.info().get_content_type()
                            cert_pem = infile.read()
                    except:
                        logger.exception("Cannot retrieve chain-certificate from URI specified in authorityInfoAccess: %s", uri)
                        last_cert = None
                    else:
                        # if next certificate is in PKCS#7 format
                        if content_type == "application/x-pkcs7-mime":
                            try:
                                signed_data = cms.SignedData.load(cert_pem)
                            except:
                                # HACK: call the openssl cli tool since pyOpenSSL doesn't export the functions to process PKCS#7 data
                                proc = subprocess.Popen(["openssl", "pkcs7", "-inform", "DER", "-outform", "PEM", "-print_certs"],
                                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                out, err = proc.communicate(cert_pem)
                                if proc.returncode != 0:
                                    proc = subprocess.Popen(["openssl", "pkcs7", "-inform", "PEM", "-outform", "PEM", "-print_certs"],
                                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                    out, err = proc.communicate(cert_text)
                                    if proc.returncode != 0:
                                        logger.error("Invalid PKCS#7 data encountered\n")
                                        exit(1)
                                cert_pem = out
                            else:
                                for ch in signed_data['certificates']:
                                    if ch.name == 'certificate':
                                        last_cert = ch.chosen
                                        certs.append(last_cert)
                                    elif ch.name == 'extended_certificate':
                                        last_cert = ch.chosen['extended_certificate_info']['certificate']
                                        certs.append(last_cert)

    logger.info("%d chain-certificate(s) found.", len(certs)-1)
    return certs



def _type_name(value):
    """
    :param value:
        A value to get the object name of
    :return:
        A unicode string of the object name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)


def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:
     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace
    :param string:
        The string to format
    :param *params:
        Params to interpolate into the string
    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output

