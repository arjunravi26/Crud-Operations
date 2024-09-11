from django.urls import path
from user import views

urlpatterns = [
    path('home', views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('login', views.login, name='login'),
]
