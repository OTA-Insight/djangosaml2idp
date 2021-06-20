from django.core.management.base import BaseCommand
from django.core.exceptions import ObjectDoesNotExist

from djangosaml2idp.models import ServiceProvider

from saml2.mdstore import MetaDataFile


class Command(BaseCommand):
    """
    Custom 'manage.py' command which reads the metadata XML of a Service
    Provider and imports it.
    """
    help = 'Imports a Service Provider from its metadata XML'

    def add_arguments(self, parser):
        parser.add_argument('metadata', nargs='+', type=str)

    def handle(self, *args, **options):
        for path in options['metadata']:
            with open(path) as file:
                raw_xml = file.read()
            metadata = MetaDataFile(None, path)
            metadata.load()
            entity = metadata[list(metadata.keys())[0]]
            entity_id = entity["entity_id"]
            desc = entity["spsso_descriptor"][0]
            assertions_signed = (desc["want_assertions_signed"] == "true")
            requests_signed = (desc["authn_requests_signed"] == "true")

            try:
                ServiceProvider.objects.get(entity_id=entity_id)
                ServiceProvider.objects.filter(entity_id=entity_id).update(
                    active=True,
                    _sign_response=requests_signed,
                    _sign_assertion=assertions_signed,
                    local_metadata=raw_xml
                )
                print("Updating existing entry...")
            except ObjectDoesNotExist:
                ServiceProvider.objects.create(
                    entity_id=entity_id,
                    pretty_name=entity_id,
                    active=True,
                    _sign_response=requests_signed,
                    _sign_assertion=assertions_signed,
                    local_metadata=raw_xml
                )
                print("Creating new entry...")
