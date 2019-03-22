from django import forms
from django.utils.translation import gettext as _

class AgreementForm(forms.Form):
    CHOICES = ((1, _('I Agree')),
               (0, _('I do not Agree')))

    confirm = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect)
    dont_show_again = forms.BooleanField(label=_("Remember My Choice"),
                                         required=False)
