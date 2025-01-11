from rest_framework.permissions import (
    AllowAny,
    BasePermission,
    IsAuthenticated,
)
from v1.serializers import SignupSerializer
from rest_framework.views import APIView

from services import(
    CustomResponseMixin,
    send_password_reset_email,
    send_signup_verification_email
    
)
from rest_framework import generics, status


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


