from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_nested import routers
from users.v1 import views

router = routers.SimpleRouter()


urlpatterns = [
    path("signup/", views.UserSignUpView.as_view(), name="signup"),
    path(
        "api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"
    ),
    path(
        "api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"
    ),
    path(
        "email-verify/", views.EmailVerifyView.as_view(), name="email-verify"
    ),
    path(
        "resend-auth-code/",
        views.ResendEmailView.as_view(),
        name="resend_auth_code",
    ),
    path(
        "email-code-verify/",
        views.VerifyCodeView.as_view(),
        name="email-code-verify",
    ),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path(
        "delete-account/",
        views.DeleteAccountView.as_view(),
        name="delete-account",
    ),
    path(
        "request-reset-password/",
        views.RequestPasswordEmail.as_view(),
        name="request-reset-password",
    ),
    path(
        "password-reset/<uidb64>/<token>/",
        views.PasswordTokenCheckAPI.as_view(),
        name="password-reset-confirm",
    ),
    path(
        "validate-reset-otp/",
        views.ValidateOTPAndResetPassword.as_view(),
        name="validate-reset-otp",
    ),
    path(
        "password-reset-complete",
        views.SetNewPasswordAPIView.as_view(),
        name="password-reset-complete",
    ),
    path("", include(router.urls)),
]