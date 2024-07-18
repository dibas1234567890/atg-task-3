# login_system/urls.py
from django.urls import path
from login_system.views import (
    BlogView,
    BlogsByCategory,
    Categories,
    CategoryForBlogView,
    CustomRegisterView, 
    CustomLoginView, 
    DoctorDashboardView, 
    PatientDashboardView, 
    IndexView,
    UserView,
    csrf_token_view,
    fetch_events
)
from rest_framework_simplejwt import views as jwt_views

app_name = 'home'

urlpatterns = [
    path('', IndexView.as_view(), name='home'),
    path('register', CustomRegisterView.as_view(), name='register'),
    path('login', CustomLoginView.as_view(), name='login'),
    path('patient_dashboard', PatientDashboardView.as_view(), name='patient_dashboard'),
    path('doctor_dashboard', DoctorDashboardView.as_view(), name='doctor_dashboard'),
    path('categories', Categories.as_view(), name='categories'),
    path('blogs', BlogView.as_view(), name='blogs'),
    path('blogs_by_category/<int:category_id>', BlogsByCategory.as_view(), name='blogs'),
    path('user/<int:user_id>', UserView.as_view(), name='user'),
    path('categories/<int:category_id>', CategoryForBlogView.as_view(), name='category'),

    path('token', 
          jwt_views.TokenObtainPairView.as_view(), 
          name ='token_obtain_pair'),
     path('token/refresh', 
          jwt_views.TokenRefreshView.as_view(), 
          name ='token_refresh'),
              path('csrf_token', csrf_token_view, name=''),

    path('fetch-events/', fetch_events, name='fetch_events')

]
