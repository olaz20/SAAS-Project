import logging
import os
from rest_framework.permissions import (
    AllowAny,
    BasePermission,
    IsAuthenticated,
)
from django.utils.encoding import DjangoUnicodeDecodeError, smart_str
from django.http import HttpResponsePermanentRedirect
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.signing import BadSignature, Signer
from rest_framework_simplejwt.tokens import RefreshToken
from v1.serializers import SignupSerializer, LoginSerializer, ResendEmailSerializer, ResetPasswordEmailRequestSerializer,SetNewPasswordSerializer,ResetPasswordSerializer
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, TokenExpired

from services import(
    CustomResponseMixin,
    send_password_reset_email,
    send_signup_verification_email
    
)
from users.models import User
from rest_framework import generics, status

logger = logging.getLogger(__file__)

class UserSignUpView(CustomResponseMixin,APIView): 
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer
    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user_data = serializer.validated_data
            serializer.save()
            try:
                send_signup_verification_email(request, user_data)
                return self.custom_response(
                    status=status.HTTP_201_CREATED,
                    message="Registration initiated. Please check your email to verify your account.",
                )
            except Exception as e:
                return self.custom_response(
                    message=f"Failed to send email: {str(e)}",
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        return self.custom_response(
            status=status.HTTP_400_BAD_REQUEST,
            message="Invalid data provided.",
            data=serializer.errors,
        )

class ResendEmailView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = ResendEmailSerializer(request.data)
        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
            if user.is_active:
                return self.custom_response(
                    message="Account is already verified."
                )

            send_signup_verification_email(request, user, "email-verify")
            return self.custom_response(
                status=status.HTTP_201_CREATED,
                message="Registration initiated. Please check your email to verify your account.",
            )

        except User.DoesNotExist:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="User with the provided email does not exist.",
            )

        except Exception as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                message=f"Failed to send email: {str(ex)}",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class VerifyCodeView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        code = request.data.get("code")

        if not email or not code:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Email and code are required.",
            )

        cached_code = cache.get(f"auth_code_{email}")
        if not cached_code:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Verification code expired or not found.",
            )

        if str(cached_code) != str(code):
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid verification code.",
            )

        user_data = cache.get(f"user_data_{email}")

        if not user_data:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="User data is missing or expired.",
            )

        User = get_user_model()
        user = User.objects.filter(email=email).first()

        if not user:
            return self.custom_response(
                status=status.HTTP_404_NOT_FOUND, message="user not found."
            )

        user.is_active = True
        user.save()
        cache.delete(f"auth_code_{email}")
        cache.delete(f"user_data_{email}")
        return self.custom_response(
            status=status.HTTP_201_CREATED,
            message="Authentication code verified successfully. Your account has been activated.",
        )


class EmailVerifyView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            token = request.query_params.get("token")
            signer = Signer()
            email = signer.unsign(token)

            user = get_user_model().objects.get(email=email)
            user.is_active = True
            user.save()

        except TypeError as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid request, no token provided",
            )
        except BadSignature as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid or expired token.",
            )

        except User.DoesNotExist as ex:
            logger.error(f"{ex}")
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST, message="User not found."
            )

        return self.custom_response(
            message="Email successfully verified. Your account is now active."
        )


class LoginView(CustomResponseMixin, APIView):
    permission_classes = [AllowAny]
    serializers = LoginSerializer

    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            email_or_username = serializer.validated_data.get("email") or serializer.validated_data.get("username")
            password = serializer.validated_data.get("password")
            user = authenticate(username=email_or_username, password=password)
            if user is not None and user.is_active:
                refresh = RefreshToken.for_user(user)


                return self.custom_response(
                    status=status.HTTP_200_OK,
                    message="login successfull",
                    data={
                        "accessToken": str(refresh.access_token),
                        "refreshToken": str(refresh),
                    },
                )
            else:
                return self.custom_response(
                    status=status.HTTP_401_UNAUTHORIZED,
                    message="Invalid email/username or password, or the account is inactive.",
                )

        return self.custom_response(
            status=status.HTTP_400_BAD_REQUEST,
            message="Invalid data provided",
            data=serializer.errors,
        )

class LogoutView(CustomResponseMixin, APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Refresh token is required."
            )    
        try:
            token = RefreshToken(refresh_token)

            token.blacklist()

            return self.custom_response(
                status=status.HTTP_200_OK,
                message="Logout successful."
            )
        except InvalidToken:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid refresh token."
            )
        except TokenExpired:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Refresh token has expired."
            )
        except TokenError:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="An error occurred while processing the refresh token."
            )
        except Exception as e:
            return self.custom_response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message=f"An unexpected error occurred: {str(e)}"
            )
        
class RequestPasswordEmail(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["email"]

        try:
            user = User.objects.filter(email=identifier).first() or User.objects.filter(username=identifier).first()
            if user:
                send_password_reset_email(request, user)
                return self.custom_response(
                    status=status.HTTP_201_CREATED,
                    message="Registration initiated. Please check your email to verify your account.",
                )
            else:
                return self.custom_response(
                    status=status.HTTP_404_NOT_FOUND,
                    message="No user found with this email or username.",
                )
        except Exception as e:
            return self.custom_response(
                message=f"Failed to send email: {str(e)}",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        
class CustomRedirect(HttpResponsePermanentRedirect):
    permission_classes = [AllowAny]
    allowed_schemes = [os.environ.get("APP_SCHEME"), "http", "https"]


class PasswordTokenCheckAPI(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        # Use localhost as the default redirect URL during development
        redirect_url = request.GET.get("redirect_url", "http://localhost:3000")

        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return CustomRedirect(
                    f"{redirect_url}?token_valid=False&message=Invalid or expired token"
                )

            return CustomRedirect(
                f"{redirect_url}?token_valid=True&message=Credentials Valid&uidb64={uidb64}&token={token}"
            )

        except DjangoUnicodeDecodeError:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid UID encoding",
            )

        except User.DoesNotExist:
            return self.custom_response(
                status=status.HTTP_404_NOT_FOUND, message="User not found"
            )

        except (
            Exception
        ) as e:  
            return self.custom_response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Unexpected error occurred",
            )

class SetNewPasswordAPIView(CustomResponseMixin, generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.custom_response(
            data={"success": True, "message": "Password reset success"},
        )
class ValidateOTPAndResetPassword(
    CustomResponseMixin, generics.GenericAPIView
):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        # Extract request data
        email = request.data.get("email", "").strip()
        auth_code = request.data.get("auth_code", "")
        new_password = request.data.get("new_password", "").strip()

        # Validate auth_code format
        try:
            auth_code = int(auth_code)
        except ValueError:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Invalid authentication code format. Must be a numeric value.",
            )

        # Check for required fields
        if not email or not auth_code or not new_password:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="All fields are required.",
            )

        # Retrieve OTP from cache
        stored_auth_code = cache.get(f"password_reset_code_{email}")

        if stored_auth_code is None:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST,
                message="Authentication code expired or not found.",
            )

        # Convert to integer (safe since it was retrieved as a string)
        try:
            stored_auth_code = int(stored_auth_code)
        except ValueError:
            return self.custom_response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Stored authentication code is corrupted.",
            )

        # Verify OTP
        if stored_auth_code != auth_code:
            return self.custom_response(
                status=status.HTTP_400_BAD_REQUEST, message="Invalid OTP."
            )

        # Verify user existence
        if not User.objects.filter(email=email).exists():
            return self.custom_response(
                status=status.HTTP_404_NOT_FOUND,
                message="User with this email does not exist.",
            )

        # Reset user password
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()

        # Clear the OTP from cache
        cache.delete(f"password_reset_code_{email}")

        return self.custom_response(
            message="Password has been reset successfully.",
        )

