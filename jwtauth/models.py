from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.utils import timezone
import re


# Create your models here.
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        
        if not username:
            raise ValueError('Username is required')
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Super user must have is_staff : True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser : True')
        
        return self.create_user(username, email, password, **extra_fields)
    

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
        ('moderator', 'Moderator'),
    ]

    # Validators
    phone_validator = RegexValidator(
    regex=r'^\+91[6-9]\d{9}$',
    message="Phone number must be entered in the format: '+919876543210'.")

    username_validator = RegexValidator(
        regex=r'^[a-zA-Z0-9_]+$',
        message="Username can only contain letters, numbers, and underscores."
    )
    
    name = models.CharField(max_length=50, help_text="Full name of the user")
    email = models.EmailField(unique=True, max_length=255, help_text="Email address (used for login)")
    username = models.CharField(max_length=20, unique=True, validators=[username_validator],
        help_text="Username (used for login, 3-20 characters, letters/numbers/underscores only)")
    mobile_no = models.CharField(max_length=17, unique=True, validators=[phone_validator],help_text="Mobile number with country code")
    

    # Account Status & Permissions
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_mobile_verified = models.BooleanField(default=False)
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    
    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Security Fields
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(default=timezone.now)
    
    # Email/Mobile Verification
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    mobile_verification_code = models.CharField(max_length=6, blank=True, null=True)
    verification_code_expires_at = models.DateTimeField(null=True, blank=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'  # Primary login field
    REQUIRED_FIELDS = ['username', 'name', 'mobile_no']
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['username']),
            models.Index(fields=['mobile_no']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def clean(self):
        from django.core.exceptions import ValidationError
        super().clean()
        
        # Validate password strength (for admin interface)
        if hasattr(self, '_password') and self._password:
            if not self.validate_password_strength(self._password):
                raise ValidationError({
                    'password': 'Password must contain at least 8 characters with uppercase, lowercase, number, and special character.'
                })
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password strength"""
        if len(password) < 8:
            return False
        
        # Check for uppercase, lowercase, digit, and special character
        patterns = [
            r'[A-Z]',  # uppercase
            r'[a-z]',  # lowercase
            r'\d',     # digit
            r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]'  # special character
        ]
        
        return all(re.search(pattern, password) for pattern in patterns)
    
    def can_login(self):
        """Check if user can login (account not locked)"""
        if self.account_locked_until:
            return timezone.now() > self.account_locked_until
        return True
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock account if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.account_locked_until = timezone.now() + timezone.timedelta(minutes=30)
        self.save()
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_login = timezone.now()
        self.save()