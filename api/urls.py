from django.urls import path
from .views import SignupView, LoginView, VerifyEmailView, LogoutView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify/<uidb64>/<token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('logout/', LogoutView.as_view(), name='logout'),
]