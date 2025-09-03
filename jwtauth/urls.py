# jwtauth/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from . import views

app_name = 'jwtauth'

urlpatterns = [
    # Custom Authentication Endpoints (currently implemented)
    path('auth/register/', views.register_view, name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/profile/', views.UserProfileView.as_view(), name='profile'),
    
    # Token Management
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # Comment out these until you implement the views:
    # path('auth/logout/', views.logout_view, name='logout'),
    # path('auth/change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    # path('auth/verify-email/', views.verify_email_view, name='verify_email'),
    # path('auth/verify-mobile/', views.verify_mobile_view, name='verify_mobile'),
    # path('auth/resend-verification/', views.resend_verification_view, name='resend_verification'),
    # path('auth/forgot-password/', views.forgot_password_view, name='forgot_password'),
    # path('auth/reset-password/', views.reset_password_view, name='reset_password'),
    # path('auth/deactivate/', views.deactivate_account_view, name='deactivate_account'),
    # path('auth/delete/', views.delete_account_view, name='delete_account'),
]