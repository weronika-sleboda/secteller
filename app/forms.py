""" 
Creates form that takes a domain as an input and based on this
creates a doman object for analsysis that will be displayed on the same page
"""

import re
from django import forms
from django.core.exceptions import ValidationError


class DomainForm(forms.Form):
    """
    Enter domain name for analysis
    """
    domain = forms.CharField(label="Enter Domain Name for Analysis", max_length=255)

    def clean_domain(self):
        """ some """
        domain = self.cleaned_data.get("domain")
        domain_regex = r"^(?!:\/\/)([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z]{2,6}$"
        if not re.match(domain_regex, domain):
            raise ValidationError("Invalid domain name. Please enter a valid domain.")
        return domain
