from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True)
    password_reset_token = models.CharField(max_length=20, blank=True, null=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    expired = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username

class UserLog(models.Model):
    DEVICE_TYPE_CHOICES = (
        ('w', 'web'),
        ('a', 'android'),
        ('i', 'ios'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_type = models.CharField(max_length = 1, choices=DEVICE_TYPE_CHOICES)
    device_token = models.GenericIPAddressField()
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

