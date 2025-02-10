from django.urls import path,include
from rest_framework.routers import DefaultRouter
from .views import UserRegistrationsApiView, activate_user, UserLoginApiView, UserLogoutView, UserAccountViewSet,PasswordChangeView,CustomResetPasswordRequestToken, CustomResetPasswordConfirm
router = DefaultRouter()
router.register(r'useraccounts', UserAccountViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('register/', UserRegistrationsApiView.as_view(), name='user-register'),
    path('login/', UserLoginApiView.as_view(), name='user-login'),
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
    path('activate/<uidb64>/<token>/', activate_user, name='activate-user'),
    path('change-password/', PasswordChangeView.as_view(), name='change-password'),
    path('reset-password-request/', CustomResetPasswordRequestToken.as_view(), name='reset-password-request'),
    path('reset-password-confirm/', CustomResetPasswordConfirm.as_view(), name='reset-password-confirm'),
]