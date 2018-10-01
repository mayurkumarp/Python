from difflib import SequenceMatcher
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile
from django.core.exceptions import ValidationError
from django.forms import widgets
from django.contrib.auth import login
from django.shortcuts import redirect
from fuzzywuzzy import fuzz

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, widget=widgets.TextInput(attrs={'class': 'required'}))
    last_name = forms.CharField(max_length=30, widget=widgets.TextInput(attrs={'class': 'required'}))
    phone = forms.CharField(widget=widgets.TextInput(attrs={'class': 'required'}))
    email = forms.EmailField(max_length=254, widget=widgets.TextInput(attrs={'class': 'required'}))

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise ValidationError("Email already exists.")
        return email

    def clean_phone(self):
        phone = self.cleaned_data['phone']
        if UserProfile.objects.filter(phone=phone).exists():
            raise ValidationError("Phone number already exists.")
        return phone

    def clean_password2(self):
        email = self.cleaned_data.get('email')
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        max_similarity = 30
        similar = fuzz.ratio(email, password1)
        if similar > max_similarity:
            raise ValidationError("The password is too similar to the email.")
        return password2

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', 'phone')

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect('login')



