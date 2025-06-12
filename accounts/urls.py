from django.urls import path
from .views import (
    SignupView, LoginView, LoginWithIdView, UserUpdateView, VerifyEmailView,
    ResendVerificationEmailView, GoogleSignInView, PasswordResetRequestView,
    PasswordResetConfirmView, DeleteAccountView, LogoutView, CheckEmailVerificationView,
    AccessCodeCreateView, AccessCodeVerifyView, AccessCodeByUserListView,
    AccessCodeDeactivateView, AccessCodeVerifiedCountView, AccessCodeUnapprovedCountView,
    VisitorCheckinListView, AlertCreateView, AlertListView, LostFoundItemCreateView,
    LostFoundItemListView, LostFoundItemDetailView, VerifyAndCreditView,
    ResidenceUsersListView, SecurityPersonnelUsersListView,
    ResidenceUsersCountView, SecurityPersonnelUsersCountView,
    AlertDeleteView,
    LostFoundAndAlertCountView,
)

urlpatterns = [
    # Authentication
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/<int:pk>/', LoginWithIdView.as_view(), name='login-with-id'),
    path('user/<int:pk>/', UserUpdateView.as_view(), name='user-update'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
    path('google-signin/', GoogleSignInView.as_view(), name='google-signin'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset/confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('delete-account/<int:pk>/', DeleteAccountView.as_view(), name='delete-account'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('check-email-verification/', CheckEmailVerificationView.as_view(), name='check-email-verification'),

    # Access Codes
    path('access-code/create/', AccessCodeCreateView.as_view(), name='access-code-create'),
    path('access-code/verify/', AccessCodeVerifyView.as_view(), name='access-code-verify'),
    path('access-code/verified-count/', AccessCodeVerifiedCountView.as_view(), name='access-code-verified-count'),
    path('access-code/unapproved-count/', AccessCodeUnapprovedCountView.as_view(), name='access-code-unapproved-count'),
    path('access-codes/by-user/', AccessCodeByUserListView.as_view(), name='access-code-by-user-list'),
    path('access-codes/<str:code>/deactivate/', AccessCodeDeactivateView.as_view(), name='access-code-deactivate'),
    path('visitor/checkin/', VisitorCheckinListView.as_view(), name='visitor-checkin-list'),

    # Alerts
    path('alerts/', AlertListView.as_view(), name='alert-list'),
    path('alerts/create/', AlertCreateView.as_view(), name='alert-create'),
    path('alerts/<int:alert_id>/delete/', AlertDeleteView.as_view(), name='alert-delete'),
    path('alerts/<int:alert_id>/', AlertDeleteView.as_view(), name='alert-delete-delete'),

    # Lost and Found
    path('lostfound/', LostFoundItemListView.as_view(), name='lostfound-list'),
    path('lostfound/create/', LostFoundItemCreateView.as_view(), name='lostfound-create'),
    path('lostfound/<int:pk>/', LostFoundItemDetailView.as_view(), name='lostfound-detail'),

    # Payments
    path('verify-and-credit/', VerifyAndCreditView.as_view(), name='verify-and-credit'),

    # User role based lists and counts
    path('residence-users/', ResidenceUsersListView.as_view(), name='residence-users-list'),
    path('security-personnel-users/', SecurityPersonnelUsersListView.as_view(), name='security-personnel-users-list'),
    path('residence-users/count/', ResidenceUsersCountView.as_view(), name='residence-users-count'),
    path('security-personnel-users/count/', SecurityPersonnelUsersCountView.as_view(), name='security-personnel-users-count'),
    path('counts/', LostFoundAndAlertCountView.as_view(), name='lostfound-alerts-count'),
]
