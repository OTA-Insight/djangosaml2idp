import json

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from .models import ServiceProvider
from .processors import instantiate_processor, validate_processor_path
from .utils import validate_metadata

boolean_form_select_choices = ((None, _('--------')), (True, _('Yes')), (False, _('No')))


class ServiceProviderAdminForm(forms.ModelForm):

    class Meta:
        model = ServiceProvider
        fields = '__all__'
        widgets = {
            '_encrypt_saml_responses': forms.Select(choices=boolean_form_select_choices),
            '_sign_response': forms.Select(choices=boolean_form_select_choices),
            '_sign_assertion': forms.Select(choices=boolean_form_select_choices),
        }

    def clean__attribute_mapping(self):
        value_as_string = self.cleaned_data['_attribute_mapping']
        try:
            value = json.loads(value_as_string)
        except Exception as e:
            raise ValidationError('The provided string could not be parsed with json. ({})'.format(e))
        if not isinstance(value, dict):
            raise ValidationError('The provided attribute_mapping should be a string representing a dict.')
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValidationError('The provided attribute_mapping should be a dict with strings for both all keys and values.')
        return json.dumps(value, indent=4)

    def clean__processor(self):
        value = self.cleaned_data['_processor']
        validate_processor_path(value)
        return value

    def clean_local_metadata(self):
        value = self.cleaned_data['local_metadata']
        validate_metadata(value)
        return value

    def clean(self):
        cleaned_data = super().clean()

        if not (cleaned_data.get('remote_metadata_url') or cleaned_data.get('local_metadata')):
            raise ValidationError('Either a remote metadata URL, or a local metadata xml needs to be provided.')

        if '_processor' in cleaned_data:
            processor_path = cleaned_data['_processor']
            entity_id = cleaned_data['entity_id']

            processor_cls = validate_processor_path(processor_path)
            instantiate_processor(processor_cls, entity_id)

        self.instance.local_metadata = cleaned_data.get('local_metadata')
        # Call the validation methods to catch ValidationErrors here, so they get displayed cleanly in the admin UI
        if cleaned_data.get('remote_metadata_url'):
            self.instance.remote_metadata_url = cleaned_data.get('remote_metadata_url')
            cleaned_data['local_metadata'] = self.instance.local_metadata
        self.instance.refresh_metadata(force_refresh=True)
