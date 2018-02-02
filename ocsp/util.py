import re
import textwrap

from asn1crypto import x509


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




class MockCertificate(x509.Certificate):

    # issuer = x509.Name.build({"common_name": "Will Bond", "country_name": "US", "organization": "Codex Non Sufficit LC"})


    @property
    def subject(self):
        """
        :return:
            The Name object for the subject of this certificate
        """

        return self['tbs_certificate']['subject']

    @property
    def issuer(self):
        """
        :return:
            The Name object for the issuer of this certificate
        """

        return self['tbs_certificate']['issuer']

    @property
    def serial_number(self):
        """
        :return:
            An integer of the certificate's serial number
        """

        return self['tbs_certificate']['serial_number'].native

    @property
    def issuer_serial(self):
        """
        :return:
            A byte string of the SHA-256 hash of the issuer concatenated with
            the ascii character ":", concatenated with the serial number as
            an ascii string
        """

        if self._issuer_serial is None:
            self._issuer_serial = self.issuer.sha256 + b':' + str_cls(self.serial_number).encode('ascii')
        return self._issuer_serial
