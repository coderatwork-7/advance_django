from django.urls import path, include
from rest_framework.routers import DefaultRouter

from rest_framework_simplejwt.views import TokenObtainPairView, TokenVerifyView, TokenRefreshView

from product import views

router = DefaultRouter()

urlpatterns = [
    path('', include(router.urls)),

]