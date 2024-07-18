from django.forms import ModelForm
from django import forms
from django.contrib.auth.forms import UserCreationForm

from login_system.models import CustomerUserProfile

class CustomRegisterForm(UserCreationForm):
    
    class Meta:
        model = CustomerUserProfile
        fields = [
        'first_name', 
        'last_name' ,
        'profile_picture' ,
        'username' ,
        'email' ,
        'address_line1' ,
        'city' ,
        'state' ,
        'pincode',
        'user_type' ]


class CustomLoginForm(forms.Form):
    username = forms.CharField( max_length=128, required=True)
    password = forms.CharField( max_length=128, required=True, widget= forms.PasswordInput() )

    
