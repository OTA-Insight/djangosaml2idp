from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext as _


class LoginForm(AuthenticationForm):
    # these are inherited
    # username = forms.CharField()
    # password = forms.CharField(widget=forms.PasswordInput())
    forget_agreement = forms.BooleanField(label=_("Forget my last agreement"),
                                          required=False)


class AgreementForm(forms.Form):
    CHOICES = ((1, _('I Agree')),
               (0, _('I do not Agree')))

    confirm = forms.ChoiceField(choices=CHOICES, widget=forms.RadioSelect)
    dont_show_again = forms.BooleanField(label=_("Remember my choice "
                                                 "for the next login"),
                                         required=False)
