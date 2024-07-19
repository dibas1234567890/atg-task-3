from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render, HttpResponseRedirect
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication 
from rest_framework.authtoken.models import Token
from login_system.models import BlogModel, Category, CustomerUserProfile
from login_system.serializers import BlogSerializer, CategorySerializer, CustomLoginSerializer, CustomRegisterSerializer, UserSerailizer
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from oauth2_provider.views.generic import ProtectedResourceView
from .models import Event
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import datetime
import pytz
from django.shortcuts import render
from django.http import HttpResponse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from .models import Event  
from django.utils import timezone
import datetime


class CustomRegisterView(APIView):
    def post(self, request):
        print(request.data['password1'])
        serializer = CustomRegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
           
            
            return Response({'message': 'Successfully Registered'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CustomLoginView(APIView):
    def post(self, request):
        serializer = CustomLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "token": str(refresh.access_token),
            })
        return Response({"detail": "Invalid username or password"},status=status.HTTP_401_UNAUTHORIZED)

class PatientDashboardView(APIView):

    def get(self, request, *args, **kwargs):
        user = request.user
        display_object = None
        print(user)
        if user.user_type == 'patient':
            display_object = CustomerUserProfile.objects.filter(user_type = 'doctor')
        print(display_object)
        serializer = UserSerailizer(display_object, many = True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DoctorDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        display_object = CustomerUserProfile.objects.get(user=user)
        context = {
            'id': display_object.id,
            'username': display_object.user.username,
            'email': display_object.user.email,
            'city': display_object.city
        }
        return Response(context, status=status.HTTP_200_OK)

class IndexView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        context = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
        }
        return Response(context, status=status.HTTP_200_OK)



class BlogView(APIView):

    def get(self, request):
        if request.user.user_type == 'doctor':
            blogs = BlogModel.objects.filter(user=request.user)
        elif request.user.user_type == 'patient':
            blogs = BlogModel.objects.filter(status='published')
        else:
            blogs = BlogModel.objects.none() 

        if not blogs.exists():
            return Response({'empty': 'No blogs found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = BlogSerializer(blogs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

    def post(self, request):
        

        data = {
            'title': request.data.get('title'),
            'image': request.data.get('image'),
            'category': request.data.get('category'),  
            'summary': request.data.get('summary'),
            'content': request.data.get('content'),
            'status': request.data.get('status'),
            'user': request.user.id,

        }

        serializer = BlogSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Blog created successfully!'}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
class Categories(APIView):
    def get(self, request):
        serialiser = {} 
        categories = Category.objects.all()
        if categories is None: 
            serializer.data = { 'empty': 'empty'}
        else: 
                    serializer = CategorySerializer(categories, many=True, include_id = True)  

        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        
        serializer = CategorySerializer( data = request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
                      
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
@ensure_csrf_cookie
def csrf_token_view(request):
    print(request.META.get('CSRF_COOKIE'))
    return JsonResponse({'csrfToken': request.META.get('CSRF_COOKIE')})

class UserView(APIView):
    def get(self, request, user_id):
            try:
                user = CustomerUserProfile.objects.get(id=user_id)
                serializer = CustomRegisterSerializer(user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except CustomerUserProfile.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class CategoryForBlogView(APIView):
    def get(self, request, category_id):
            try:
                category = Category.objects.get(id=category_id)
                serializer = CategorySerializer(category)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Category.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
class BlogsByCategory(APIView):
    def get(self, request, category_id):
            try:
                category_blog = BlogModel.objects.filter(id=category_id)
                serializer = BlogSerializer(category_blog, many =True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except Category.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']

class CalendarView(ProtectedResourceView):
    @method_decorator(login_required)
    def get(self, request, *args, **kwargs):
        return HttpResponse("This is your calendar view")


SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

def fetch_events(request):
    try:
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build('calendar', 'v3', credentials=creds)

        now = datetime.datetime.utcnow().isoformat() + 'Z'  # RFC3339 timestamp

        # Execute API request
        events_result = service.events().list(
            calendarId='primary', timeMin=now, maxResults=10, singleEvents=True,
            orderBy='startTime').execute()

        events_data = events_result.get('items', [])

        for event_data in events_data:
            start_time = event_data['start'].get('dateTime', event_data['start'].get('date'))
            end_time = event_data['end'].get('dateTime', event_data['end'].get('date'))

            if 'T' in start_time:
                start_time = datetime.datetime.fromisoformat(start_time)
            else:
                start_time = datetime.datetime.strptime(start_time, '%Y-%m-%d')

            if 'T' in end_time:
                end_time = datetime.datetime.fromisoformat(end_time)
            else:
                end_time = datetime.datetime.strptime(end_time, '%Y-%m-%d')

            if start_time.tzinfo is not None:
                start_time = start_time.astimezone(timezone.get_default_timezone())
            if end_time.tzinfo is not None:
                end_time = end_time.astimezone(timezone.get_default_timezone())

            Event.objects.create(
                summary=event_data.get('summary', ''),
                start_time=start_time,
                end_time=end_time
            )

        events = Event.objects.all()
        context = {'events': events}
        return render(request, 'calendar_events.html', context)

    except Exception as e:
        return HttpResponse(f"An error occurred: {e}")