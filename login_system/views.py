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
from login_system.serializers import BlogSerializer, CategorySerializer, CustomLoginSerializer, CustomRegisterSerializer
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

def fetch_events(request):
    try:
        # Load credentials from the token file
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

        # Refresh the credentials if they have expired
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

        # Build the Google Calendar service
        service = build('calendar', 'v3', credentials=creds)

        # Get the current time in UTC format
        now = datetime.datetime.utcnow().isoformat() + 'Z'  # RFC3339 timestamp

        # Log the request URL and parameters
        request_url = f"https://www.googleapis.com/calendar/v3/calendars/primary/events?timeMin={now}&maxResults=10&singleEvents=true&orderBy=startTime&alt=json"

        # Fetch events from the primary calendar
        events_result = service.events().list(
            calendarId='primary', timeMin=now, maxResults=10, singleEvents=True,
            orderBy='startTime').execute()

        events_data = events_result.get('items', [])

        # Process the fetched events and save to the database
        for event_data in events_data:
            start_time = event_data['start'].get('dateTime', event_data['start'].get('date'))
            end_time = event_data['end'].get('dateTime', event_data['end'].get('date'))
            start_time = datetime.datetime.fromisoformat(start_time)
            end_time = datetime.datetime.fromisoformat(end_time)
            
            # Convert to naive datetime objects if they are timezone-aware
            if start_time.tzinfo is not None:
                start_time = start_time.replace(tzinfo=None)
            if end_time.tzinfo is not None:
                end_time = end_time.replace(tzinfo=None)
                
            Event.objects.create(
                summary=event_data.get('summary', ''),
                start_time=start_time,
                end_time=end_time
            )

        # Fetch all events from the database to display
        events = Event.objects.all()
        context = {'events': events}
        return render(request, 'calendar_events.html', context)

    except Exception as e:
        return HttpResponse(f"An error occurred: {e}")

if __name__ == '__main__':
    fetch_events()