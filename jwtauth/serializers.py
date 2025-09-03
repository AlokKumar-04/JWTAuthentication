from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User



class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password], style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = [
            'name', 'email', 'username', 'mobile_no', 
            'password', 'confirm_password'
        ]
    
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Password confirmation does not match.'
            })
        
        # Additional password strength validation
        if not User.validate_password_strength(attrs['password']):
            raise serializers.ValidationError({
                'password': 'Password must contain at least 8 characters with uppercase, lowercase, number, and special character.'
            })
        
        return attrs
    
    def validate_email(self, value):
        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError("Email already exists.")
        return value.lower()
    
    def validate_username(self, value):
        if User.objects.filter(username=value.lower()).exists():
            raise serializers.ValidationError("Username already exists.")
        return value.lower()
    
    def validate_mobile_no(self, value):
        if User.objects.filter(mobile_no=value).exists():
            raise serializers.ValidationError("Mobile number already exists.")
        return value
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    login = serializers.CharField()  # Can be email or username
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        login = attrs.get('login')
        password = attrs.get('password')
        
        if login and password:
            # Try to authenticate with email or username
            user = None
            
            # Check if login is email format
            if '@' in login:
                try:
                    user_obj = User.objects.get(email=login.lower())
                    user = authenticate(email=login.lower(), password=password)
                except User.DoesNotExist:
                    pass
            else:
                try:
                    user_obj = User.objects.get(username=login.lower())
                    user = authenticate(email=user_obj.email, password=password)
                except User.DoesNotExist:
                    pass
            
            if not user:
                # Increment failed login attempts if user exists
                try:
                    if '@' in login:
                        existing_user = User.objects.get(email=login.lower())
                    else:
                        existing_user = User.objects.get(username=login.lower())
                    existing_user.increment_failed_login()
                except User.DoesNotExist:
                    pass
                
                raise serializers.ValidationError('Invalid login credentials.')
            
            if not user.is_active:
                raise serializers.ValidationError('Account is deactivated.')
            
            if not user.can_login():
                raise serializers.ValidationError('Account is temporarily locked due to multiple failed login attempts.')
            
            # Reset failed login attempts on successful authentication
            user.reset_failed_login()
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include login and password.')
        
        return attrs


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'name', 'email', 'username', 'mobile_no', 
            'is_email_verified', 'is_mobile_verified', 'role',
            'date_joined', 'last_login'
        ]
        read_only_fields = [
            'id', 'email', 'username', 'is_email_verified', 
            'is_mobile_verified', 'role', 'date_joined', 'last_login'
        ]
