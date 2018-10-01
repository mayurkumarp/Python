from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from backend.forms import SignUpForm
from .models import UserProfile, UserLog
from django import forms
from .forms import SignUpForm
from django.core.exceptions import ValidationError


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('phone', 'user', 'password_reset_token', 'created', 'modified','expired')

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'userprofile'

class UserAdmin(BaseUserAdmin):
    form = SignUpForm
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name','is_staff', 'last_login')

    def add_view(self, *args, **kwargs):
        self.inlines = []
        return super(UserAdmin, self).add_view(*args, **kwargs)

    def change_view(self, *args, **kwargs):
        self.inlines = [UserProfileInline]
        return super(UserAdmin, self).change_view(*args, **kwargs)

class UserLogAdmin(admin.ModelAdmin):
    list_display = ('user','device_type','device_token','created', 'modified')

admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.register(UserLog, UserLogAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.site_header = "JWT Auth administration"
admin.site.site_title = "JWT"
admin.site.index_title = "Welcome to JWT Auth"
admin.site.login_template = "mysite/registration/login.html"
# admin.site.index_template = "admin/index2.html"