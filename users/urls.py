from django.urls import path, include
from rest_framework.routers import DefaultRouter
from users import views, serializers

from rest_framework_simplejwt.views import TokenObtainPairView, TokenVerifyView, TokenRefreshView


router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='users')
# router.register(r'login', views.LoginViewset, basename='login')

urlpatterns = [
    path('', include(router.urls)),
    path('login/', TokenObtainPairView.as_view(serializer_class=serializers.CustomJWTSerializer), name='login'),

]