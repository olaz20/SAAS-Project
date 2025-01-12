from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.validators import UniqueValidator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import AuthenticationFailed


User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())],
    )
    username = serializers.CharField(required=True,
        validators=[UniqueValidator(queryset=User.objects.all())])
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name','last_name' 'password']

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        user = User.objects.create_user(**validated_data)
        user.is_active = False 
        user.save()
        return user
    
class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username_or_email = data.get("username_or_email")
        password = data.get("password")

        if '@' in username_or_email:
            try:
                user = User.objects.get(email=username_or_email)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")
        else:
            try:
                user = User.objects.get(username=username_or_email)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid username or password.")
        if not check_password(password, user.password):
            raise serializers.ValidationError("Invalid email, or password.")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")
        return user

class ResendEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(
        max_length=500, required=False, read_only=True
    )

    class Meta:
        fields = ["email"]
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True
    )
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = [
            "password",
            "token",
            "uidb64",
        ]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            token = attrs.get("token")
            uidb64 = attrs.get("uidb64")

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("The reset link is invalid", 401)

            user.set_password(password)
            user.save()

            return user
        except Exception as e:
            raise AuthenticationFailed("The reset link is invalid", 401)


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    auth_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8)

    class Meta:
        model = User
        fields = ["email", "auth_code", "new_password"]


class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=False)

    def validate(self, attrs):
        user = self.context["request"].user
        password = attrs.get("password")

        if password:
            # Verify the user's password
            if not user.check_password(password):
                raise serializers.ValidationError(
                    {"password": "Incorrect password."}
                )

        return attrs
