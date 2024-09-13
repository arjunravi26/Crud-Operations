from django.urls import path
from user import views

urlpatterns = [
    path('user', views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('admin_dashboard', views.admin_view, name='admin'),
    path('delete', views.delete, name='delete'),
    path('edit_update', views.edit_update, name='edit_update'),
    path('edit_user', views.edit_user, name='edit_user'),
]
