from django.conf.urls import url, include
from django.conf.urls import url
from rest_framework_jwt.views import obtain_jwt_token
from . import views
from django.contrib.auth import views as auth_views
from rest_framework.urlpatterns import format_suffix_patterns
from rest_framework import routers
from django.conf.urls import url
from rest_framework_swagger.views import get_swagger_view
from .views import  get_user_info, UserProfileViewSet, UserViewSet
from django.views.decorators.csrf import csrf_exempt
from .serializers import UserAuthenticationSerializer
from .serializers import *
from rest_framework.decorators import renderer_classes
from rest_framework_swagger.views import get_swagger_view
from rest_framework import routers

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'userprofile', UserProfileViewSet)

urlpatterns = router.urls


schema_view = get_swagger_view(title='Jwt Auth API')

urlpatterns = [

    url(r'^$', views.index, name='index'),
    url(r'^login/$', views.login, name='login'),
    url(r'^logout/$', views.logout, name='logout'),
    url(r'^signup/$', views.signup, name='signup'),
    url(r'^profile', views.edit_profile, name='edit_profile'),
    url(r'^change_password/$', views.change_password, name='change_password'),
    # url(r'^forget_password/$', views.forget_password, name='forget_password'),
    # url(r'^reset_password_link$', views.reset_password_link, name='reset_password_link'),
    # url(r'^reset_password(?:token=[0-9A-Za-z]{1,18})?/$', views.active_reset_password, name='active_reset_password'),
    # url(r'^new_password(?:token=[0-9A-Za-z]{1,18})?/$', views.new_password, name='new_password'),
    url(r'^password_reset/$', auth_views.password_reset, name='password_reset'),
    url(r'^password_reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',auth_views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.activate, name='activate'),

    # JWT API
    url(r'^swagger$', schema_view),
    url(r'^jwt-auth$', obtain_jwt_token),
    url(r'^api/create$', views.register, name='register'),
    url(r'^api/update$', views.update_user_detail, name='update_user_detail'),
    url(r'^api/change_password$', views.change_user_password, name='change_user_password'),
    url(r'^forget_password$', views.forget_password, name="forget_password"),
    url(r'^api/register', views.User_list.as_view(), name='save_contact'),
    url(r'^user/reg', views.save_register, name='save_register'),

    url(r'^get_user_info', views.get_user_info, name='get_user_info'),
    # url(r'^api/register$', views.register, name='register'),
    # url(r'^api/users/$', UserListView.as_view()),
    # url(r'^api/users/(?P<pk>\d+)/$', UserView.as_view()),
    # url(r'^api/users/$', UserViewSet),
    # url(r'^api/userprofile/$', UserProfileViewSet),


    # Validation for edit profile page
    url(r'^email_validation', views.email_validation, name='email_validation'),
    url(r'^phone_validation', views.phone_validation, name='phone_validation'),
    url(r'^username_validation', views.username_validation, name='username_validation'),
]

urlpatterns = format_suffix_patterns(urlpatterns, allowed=['json', 'html'])