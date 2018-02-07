import os
from enum import Enum
from datetime import datetime

from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, UTCDateTimeAttribute, MapAttribute


# Enums

class CertificateStatus(Enum):
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


# DyanomoDB Attributes

class X509NameMap(MapAttribute):
    common_name = UnicodeAttribute(null=True)
    organizational_unit_name = UnicodeAttribute(null=True)
    organization_name = UnicodeAttribute(null=True)

    locality_name = UnicodeAttribute(null=True)
    country_name = UnicodeAttribute(null=True)

    name = UnicodeAttribute(null=True)
    surname = UnicodeAttribute(null=True)
    given_name = UnicodeAttribute(null=True)
    email_address = UnicodeAttribute(null=True)


# DyanomoDB Models

class CertRecordModel(Model):
    """
    A DynamoDB Certificate Record
    """
    class Meta:
        table_name = os.environ['DYNAMODB_TABLE']
        region = os.environ['DYNAMODB_REGION']

    uid = UnicodeAttribute(hash_key=True)

    status = UnicodeAttribute(null=False, default=CertificateStatus.unknown.name)
    subject = X509NameMap(null=False)
    keyId = UnicodeAttribute(null=False)
    revokedAt = UTCDateTimeAttribute(null=True)
    updatedAt = UTCDateTimeAttribute(null=False, default=datetime.now().astimezone())

    def save(self, *args, **kwargs):
        self.updatedAt = datetime.now().astimezone()
        return super(CertRecordModel, self).save(*args, **kwargs)

