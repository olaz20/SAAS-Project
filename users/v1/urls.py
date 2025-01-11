from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework_nested import routers
from users.v1 import views

router = routers.SimpleRouter()


urlpatterns = [
    path("signup/", views.UserSignUpView.as_view(), name="signup")
]