from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods


def is_superuser(user):
    return user.is_superuser
@never_cache
@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_view(request):
    # Get the search query from the GET parameters
    query = request.GET.get('search', '')
    
    # Filter users based on the search query
    if query:
        users = User.objects.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        )
    else:
        users = User.objects.filter(is_staff=0)

    # Render the admin page with the filtered user list and search query
    return render(request, 'admin.html', {
        'users': users,
        'search_query': query
    })
@never_cache
@login_required
def home(request):
    if request.user.is_superuser:
        return redirect('admin')
    return render(request, 'home.html', {'user': request.user})

@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def login(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        print(email,password)
        if not email or not password:
            messages.error(request, 'Please provide both email and password.')
            return render(request, 'login.html')
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Please enter a valid email address.')
            return render(request, 'login.html')
        try:
            user = User.objects.get(username=email)
            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                auth_login(request, user)
                print("sdfsdf")
                return redirect('admin' if user.is_superuser else 'home')
            else:
                messages.error(request, 'Invalid email or password.')
        except User.DoesNotExist:
            messages.error(request, 'No user found with this email address.')
    return render(request, 'login.html')

@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def signup(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        first_name = request.POST.get('firstname')
        last_name = request.POST.get('lastname')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if not all([first_name, last_name, email, password1, password2]):
            messages.error(request, 'All fields are required.')
            return render(request, 'signup.html')
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Please enter a valid email address.')
            return render(request, 'signup.html')
        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'signup.html')
        if len(password1) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return render(request, 'signup.html')
        if User.objects.filter(username=email).exists():
            messages.error(request, 'A user with this email already exists.')
            return render(request, 'signup.html')
        user = User.objects.create_user(first_name=first_name, last_name=last_name,
                                        username=email, password=password1)
        messages.success(request, 'Account created successfully. Please log in.')
        return redirect('login')
    return render(request, 'signup.html')

@never_cache
@login_required
@user_passes_test(is_superuser)
@csrf_protect
def delete(request):
    if request.method == 'POST':
        user_id = request.POST.get('id')
        user = get_object_or_404(User, id=user_id)
        user.delete()
        messages.success(request, 'User deleted successfully.')
    return redirect('admin')
@login_required
def edit_user(request):
    user_id = request.POST.get('id')  # Get user ID from the query parameter
    user = User.objects.get(id=user_id)

    # Render the edit form with the user's current data
    return render(request, 'edit.html', {'user': user})
@never_cache
@login_required
@user_passes_test(is_superuser)
@csrf_protect
def edit_update(request):
    if request.method == 'POST':
        user_id = request.POST.get('id')
        user = get_object_or_404(User, id=user_id)
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        new_email = request.POST.get('email', user.email)
        if new_email != user.email:
            if User.objects.filter(email=new_email).exists():
                messages.error(request, 'A user with this email already exists.')
                return render(request, 'edit.html', {'user': user})
            user.email = new_email
            user.username = new_email
        new_password = request.POST.get('new_password')
        if new_password:
            if len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
                return render(request, 'edit.html', {'user': user})
            user.set_password(new_password)
        user.save()
        messages.success(request, 'User information updated successfully.')
        return redirect('admin')
    # else:
    #     user_id = request.GET.get('id')
    #     print(user_id)
    #     user = User.objects.get(id=user_id)
        # return render(request, 'edit.html', {'user': user})

@never_cache
@login_required
def logout(request):
    auth_logout(request)
    return redirect('login')