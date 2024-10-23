from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.mail import send_mail
from django.conf import settings
import phonenumbers
def validate_phone_number(value):
    if not isinstance(value, str):
        raise ValueError('Phone number must be a string.')

    # Ensure phone number starts with a '+'
    if not value.startswith('+'):
        raise ValueError('Phone number must start with a "+".')

    # Ensure phone number is between 10 and 15 characters long
    if len(value) < 10 or len(value) > 15:
        raise ValueError('Phone number must be between 10 and 15 digits.')
    
    number = phonenumbers.parse(value)
    try:
        phone_number = phonenumbers.parse(value, None)
        if not phonenumbers.is_valid_number(phone_number):
            raise ValidationError(f'{value} is not a valid phone number')
    except phonenumbers.NumberParseException:
        raise ValidationError(f'{value} is not a valid phone number')


def send_verificaiton_email(subject, profile, message_text):
    message = message_text
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [profile.email]
    
    send_mail(subject, message, from_email, recipient_list)

