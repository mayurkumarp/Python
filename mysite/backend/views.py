import binascii
import os
import json
import requests
import datetime
import jwt
from django.conf import settings
from django.contrib import messages, auth
from django.contrib.auth import authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm
from django.http.response import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login
from .forms import SignUpForm
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import (check_password, is_password_usable, make_password,)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from datetime import datetime
from datetime import timedelta
from django.utils import timezone
from .models import UserProfile, UserLog
from rest_framework.views import APIView
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from rest_framework.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode
from django.db.models.query_utils import Q
from django.http import Http404
from rest_framework_jwt.authentication import (jwt_decode_handler, jwt_get_username_from_payload)
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.schemas import SchemaGenerator
from rest_framework_swagger import renderers
from rest_framework import permissions
from rest_framework import renderers
from rest_framework import response
from rest_framework import schemas
from rest_framework import viewsets
from rest_framework.decorators import api_view
from rest_framework.decorators import permission_classes
from rest_framework.decorators import renderer_classes
from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer
from rest_framework.decorators import api_view, renderer_classes
from .serializers import UserAuthenticationSerializer, UserProfileSerializer
from rest_framework import generics
from django.core import serializers
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site


def index(request):
    return render(request, 'mysite/index.html')


def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            user_profile = UserProfile.objects.create(user_id=user.id, phone=request.POST['phone'])
            current_site = get_current_site(request)
            subject = "Activate your account"
            message = render_to_string(
                    'account_activation_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
            user.email_user(subject, message)
            messages.add_message(request, messages.WARNING, 'You account is not activate. Please confirm email after you can access login.')
            return redirect('/login')
    else:
        form = SignUpForm()
    return render(request, 'mysite/registration/signup.html', {'form': form })


def activate(request, uidb64, token):
    try:
        uid= force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return redirect('login')
    return HttpResponse('Activation link is invalid!')


@csrf_exempt
def device(request,type, id):
    if request.PC:
        type = 'w'
        token = request.META['REMOTE_ADDR']
    elif request.Android:
        type = 'a'
        token = "-"
    elif request.iOS:
        type = 'i'
        token = '-'
    user_log = UserLog.objects.create(user_id=id, device_type=type, device_token=token)
    return type


def login(request):
    error = ''
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_authenticated:
                if user.is_superuser:
                    auth_login(request, user)
                    id = user.id
                    device(request, type, id)
                    return redirect(settings.ADMIN_LOGIN_REDIRECT_URL)
                else:
                    auth_login(request,user)
                    id = user.id
                    device(request, type, id)
                    return redirect(settings.LOGIN_REDIRECT_URL)
        else:
            error = "Your username and password is incorrect! Please Try again"
    return render(request, 'mysite/registration/login.html',{'error': error})


def logout(request):
    auth.logout(request)
    return redirect('/')


@login_required(login_url='/login/')
def change_password(request):
    error = ''
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Your password has been successfully changed.")
            return redirect('change_password')
        else:
            error = "Please enter correct below."
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'mysite/registration/change_password.html',{'error':error,'form':form})


@login_required(login_url='/login/')
def edit_profile(request):
    user_id = request.session.get('_auth_user_id')
    if request.method == "POST":
        users = User.objects.filter(id=user_id).update(username=request.POST['username'],
                                                      first_name=request.POST['first_name'],
                                                      last_name = request.POST['last_name'],
                                                      email=request.POST['email'])
        userprofile = UserProfile.objects.filter(user_id=user_id).update(phone=request.POST['phone'])
        messages.success(request, "Your profile was successfully updated.")
        return HttpResponseRedirect(request.path)
    return render(request, 'mysite/profile.html')


@api_view()
@renderer_classes([SwaggerUIRenderer, OpenAPIRenderer])
def schema_view(request):
    generator = schemas.SchemaGenerator(title='Pastebin API')
    return response.Response(generator.get_schema(request=request))


# -------------------------------
#       JWT Authentication
# -------------------------------
@csrf_exempt
@api_view(['POST'])
def save_register(request):
    response = {}
    if request.method == "POST":
        data = {
            'id': request.data.get('id'),
            'username': request.data.get('username'),
            'first_name': request.data.get('first_name'),
            'last_name': request.data.get('last_name'),
            'email': request.data.get('email'),
            'phone': request.data.get('phone'),
            'password': make_password(request.data.get('password'))
        }
        serializer = UserAuthenticationSerializer(data=data)
        print(serializer, "serializer")
        if serializer.is_valid():
            serializer.save()
            response['message'] = "Successfully register user!"
            response['error_code'] = 0
            return Response(response, status=status.HTTP_201_CREATED)
        response['message'] = "Please try again after sometime!"
        response['error_code'] = 1
        return Response(response, status=status.HTTP_200_OK)

@csrf_exempt
@api_view(['POST'])
# @permission_classes([AllowAny,])
# @renderer_classes([SwaggerUIRenderer, renderers.JSONRenderer])
def register(request):
    response = {}
    username = request.POST.get('username')
    first_name = request.POST.get('first_name')
    last_name = request.POST.get('last_name')
    phone = request.POST.get('phone')
    email = request.POST.get('email')
    password = request.POST.get('password')
    user = User.objects.create(username=username, first_name=first_name, last_name=last_name,
                              email=email, password=make_password(password))
    userprofile = UserProfile.objects.create(user_id=user.id, phone=phone)
    response['message'] = "Successfully register user!"
    response['error_code'] = 0
    return HttpResponse(json.dumps(response), content_type="application/json")


@api_view(['GET'])
def get_user_info(request):
    response = {}
    auth_token = request.META.get('HTTP_AUTHORIZATION', " ")
    try:
        payload = jwt_decode_handler(auth_token)
    except (jwt.ExpiredSignature, jwt.DecodeError, jwt.InvalidTokenError):
        response['message'] = "Signature is expired."
        response['error_code'] = 401
        return JsonResponse(response, status=status.HTTP_401_UNAUTHORIZED)
    data = {'token': auth_token}
    valid_data = VerifyJSONWebTokenSerializer().validate(data)
    user = valid_data['user']
    request.user = user
    if request.method == "GET":
        if user:
            response['id'] = request.user.id
            response['username'] = request.user.username
            response['first_name'] = request.user.first_name
            response['last_name'] = request.user.last_name
            response['email'] = request.user.email
            response['phone'] = request.user.userprofile.phone
        else:
            response['message'] = "Error! Please correct the errors below."
            response['error_code'] = 1
    else:
        response['message'] = "Method not allowed."
        response['error_code'] = 405
        return JsonResponse(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    return Response(response, status=status.HTTP_200_OK)


@api_view(['PUT'])
@permission_classes([AllowAny, ])
@renderer_classes([OpenAPIRenderer, ])
@csrf_exempt
def update_user_detail(request):
    response = {}
    auth_token = request.META.get('HTTP_AUTHORIZATION', " ")
    try:
        payload = jwt_decode_handler(auth_token)
    except (jwt.ExpiredSignature, jwt.DecodeError, jwt.InvalidTokenError):
        response['message'] = "Signature is expired."
        response['error_code'] = 401
        return JsonResponse(response, status=status.HTTP_401_UNAUTHORIZED)
    data = {'token' : auth_token}
    valid_date = VerifyJSONWebTokenSerializer().validate(data)
    user = valid_date['user']
    request.user = user
    if request.method == "POST":
        if user:
            user_data = User.objects.filter(id=request.user.id).update(username=request.POST['username'],
                                                first_name=request.POST['first_name'],
                                                last_name=request.POST['last_name'],
                                                email=request.POST['email'],
                                                )
            userprofile = UserProfile.objects.filter(user_id=request.user.id).update(phone=request.POST['phone'])
            response['message'] ="Your profile was successfully updated."
            response['error_code'] = 0
        else:
            response['message'] = "Error! Please correct the errors below."
            response['error_code'] = 1
    else:
        response['message'] = "Method not allowed."
        response['error_code'] = 405
        return JsonResponse(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    return HttpResponse(json.dumps(response), content_type="application/json")


@api_view(['POST'])
@csrf_exempt
def change_user_password(request):
    response = {}
    auth_token = request.META.get('HTTP_AUTHORIZATION', " ")
    try:
        payload = jwt_decode_handler(auth_token)
    except (jwt.ExpiredSignature, jwt.DecodeError, jwt.InvalidTokenError):
        response['message'] = "Signature is expired."
        response['error_code'] = 401
        return JsonResponse(response, status=status.HTTP_401_UNAUTHORIZED)
    data = {'token': auth_token}
    valid_date = VerifyJSONWebTokenSerializer().validate(data)
    user = valid_date['user']
    request.user = user
    if request.method == "POST":
        if user:
            old_password_user = check_password(request.POST['old_password'], request.user.password)
            if old_password_user is True:
                new_password1 = request.POST['new_password1']
                new_password2 = make_password(request.POST['new_password2'])
                confirm_password = check_password(new_password1, new_password2)
                if confirm_password is True:
                    user = User.objects.filter(id=request.user.id).update(password=make_password(new_password1))
                    response['message'] = "Success! Your password has been successfully changed."
                    response['error_code'] = 0
                else:
                    response['message'] = "The two password fields didn't match."
                    response['error_code'] = 404
                    return JsonResponse(response, status=status.HTTP_404_NOT_FOUND)
            else:
                response['message'] = "Your old password was entered incorrectly. Please enter it again."
                response['error_code'] = 404
                return JsonResponse(response, status=status.HTTP_404_NOT_FOUND)
        else:
            response['message'] = "Error! Please try again."
            response['error_code'] = 1
    else:
        response['message'] = "Method not Allowed."
        response['error_code'] = 405
        return JsonResponse(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    return HttpResponse(json.dumps(response), content_type="application/json")


@csrf_exempt
def forget_password(request):
    response = {}
    if request.method == "POST":
        email = request.POST['email']
        users = User.objects.filter(Q(email=email))
        if users.exists():
            for user in users:
                scheme = request.is_secure() and "https://" or "http://"
                c = {
                    'email': user.email,
                    'domain': request.META['HTTP_HOST'],
                    'site_name': 'reset',
                    'uid': urlsafe_base64_encode(force_bytes(user.id)),
                    'user': user,
                    'token': default_token_generator.make_token(user),
                    'protocol': scheme,
                }
                valid_link = c['protocol'] + c['domain'] + "/" + c['site_name'] + "/" + c['uid'] + "/" + c['token'] + "/"
                response['email'] = email
                response['reset_password_link'] = valid_link
        else:
            response['message'] = "Email is not exists. Please enter register email."
            response['error_code'] = 406
            return JsonResponse(response, status=status.HTTP_406_NOT_ACCEPTABLE)
    else:
        response['message'] = "Method not allowed"
        response['error_code'] = 405
        return JsonResponse(response, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    return HttpResponse(json.dumps(response), content_type="application/json")


def email_validation(request):
    id = request.GET.get('id')
    email = request.GET.get('email')
    user = User.objects.exclude(id=id).filter(email=email).values()
    if user:
        return HttpResponse("false")
    else:
        return HttpResponse("true")


def phone_validation(request):
    id = request.GET.get('id')
    phone = request.GET.get('phone')
    user = UserProfile.objects.exclude(user_id=id).filter(phone=phone).values()
    if user:
        return HttpResponse("false")
    else:
        return HttpResponse("true")


def username_validation(request):
    id = request.GET.get('id')
    username = request.GET.get('username')
    user = User.objects.exclude(id=id).filter(username=username).values()
    if user:
        return HttpResponse("false")
    else:
        return HttpResponse("true")


# --------------------
 # As view get list
 # -------------------



# @csrf_exempt
# @api_view(['POST'])
# @permission_classes([AllowAny,])
# @renderer_classes([SwaggerUIRenderer, renderers.JSONRenderer])
# def register(request):
#     id = request.POST.get('id')
#     username = request.POST.get('username')
#     first_name = request.POST.get('first_name')
#     last_name = request.POST.get('last_name')
#     phone = request.POST.get('phone')
#     email = request.POST.get('email')
#     password = request.POST.get('password')
#     try:
#         user = User.objects.create(id=id,username=username,first_name=first_name,last_name=last_name,
#                                   email=email,password=make_password(password))
#         userprofile = UserProfile.objects.create(user_id=id,phone=phone)
#         response['message'] = "Successfully registre user!"
#         return Response(response, status=status.HTTP_201_CREATED)
#     except Exception as ex:
#         return Response(ex, status=status.HTTP_400_BAD_REQUEST)
#     return Response({'status': status.HTTP_403_FORBIDDEN})

# class UserListView(generics.ListCreateAPIView):
#     queryset = User.objects.all()
#     queryset = UserProfile.objects.all()
#     serializer_class = UserAuthenticationSerializer
#     permission_classes = (AllowAny,)
#
# class UserView(generics.RetrieveUpdateDestroyAPIView):
#     queryset = User.objects.all()
#     queryset = UserProfile.objects.all()
#     serializer_class = UserAuthenticationSerializer
#     permission_classes = (AllowAny,)


# from rest_framework.generics import GenericAPIView
#
#
# class UserAuthentication(generics.GenericAPIView):
#
#     serializer_class = UserAuthenticationSerializer
#     permission_classes = [IsAuthenticated, ]
#
#     def get(self, request, format=None):
#         users = User.objects.all()
#         serializer = UserAuthenticationSerializer(users, many=True)
#         return Response(serializer.data, serializer1.data)
#
#     def post(self, request, format=None):
#         serializer = UserAuthenticationSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['GET','POST'])
# @permission_classes([AllowAny,])
# @renderer_classes([SwaggerUIRenderer, OpenAPIRenderer, ])
# def hello_world(request, format=None):
#     try:
#         user = User.objects.get(pk=pk)
#     except User.DoesNotExist:
#         return Response(status=status.HTTP_404_NOT_FOUND)
#
#     if request.method == 'GET':
#         serializer = UserAuthenticationSerializer(user)
#         return Response(serializer.data)
#
#     elif request.method == 'PUT':
#         serializer = UserAuthenticationSerializer(User, data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#
# @api_view(['POST'])
# @permission_classes([AllowAny,])
# @renderer_classes([SwaggerUIRenderer, OpenAPIRenderer, ])
# @csrf_exempt
# def register(request):
#     id = request.POST['id']
#     username = request.POST['username']
#     first_name = request.POST['first_name']
#     last_name = request.POST['last_name']
#     phone = request.POST['phone']
#     email = request.POST['email']
#     password = request.POST['password']
#     try:
#         user = User.objects.create(id=id, username=username, first_name=first_name, last_name=last_name,
#                                    email=email, password=make_password(password))
#         userprofile = UserProfile.objects.create(user_id=id, phone=phone)
#         reg = json.dumps(user)
#         return Response(reg, status=status.HTTP_201_CREATED)
#     except Exception as ex:
#         return Response(ex, status=status.HTTP_400_BAD_REQUEST)

# @api_view(['POST'])
# @permission_classes([AllowAny,])
# @renderer_classes([OpenAPIRenderer, ])
# def register(request):
#     if request.method == 'GET':
#         users = User.objects.all()
#         serializer = UserAuthenticationSerializer(users, context={'request': request}, many=True)
#         return Response(serializer.data)
#     elif request.method == 'POST':
#         serializer = UserAuthenticationSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class User_list(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserAuthenticationSerializer

from rest_framework import viewsets

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserAuthenticationSerializer

class UserProfileViewSet(viewsets.ModelViewSet):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer