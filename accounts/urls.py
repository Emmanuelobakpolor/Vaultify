from django import views
from django.urls import path
from django.contrib.auth.views import PasswordResetConfirmView
from .views import (
    AccessCodeUnapprovedCountByEstateView, AccessCodeVerifiedCountByEstateView, AlertCountByEstateView, AlertCountView, GeneralAlertListView, GeneralVisitorCheckinListView, LostFoundCountByEstateView, LostFoundCountView, PrivateMessageCreateView, PrivateMessageListView, ResidenceUsersCountByEstateView, SecurityPersonnelUsersCountByEstateView, SignupSendOTPView, SignupVerifyOTPView, SignupView, LoginView, LoginWithIdView, UploadProfileImageView, UserTransactionListView, UserUpdateView, VerifyEmailView,
    ResendVerificationEmailView, GoogleSignInView, PasswordResetRequestView,
    PasswordResetVerifyOTPView, DeleteAccountView, LogoutView, CheckEmailVerificationView,
    AccessCodeCreateView, AccessCodeVerifyView, AccessCodeByUserListView,
    AccessCodeDeactivateView, AccessCodeVerifiedCountView, AccessCodeUnapprovedCountView,
    VisitorCheckinListView, AlertCreateView, AlertListView, LostFoundItemCreateView,
    LostFoundItemListView, LostFoundItemDetailView, VerifyAndCreditView,
    ResidenceUsersListView, SecurityPersonnelUsersListView,
    ResidenceUsersListAllView, SecurityPersonnelUsersListAllView, LostFoundItemListAllView,
    ResidenceUsersCountView, SecurityPersonnelUsersCountView,
    AlertDeleteView,
    LostFoundAndAlertCountView,
    PrivateMessageMarkSeenView,
    PrivateMessageDeleteView,
    ChangePasswordView,
    SubscriptionUsersListView,
)


urlpatterns = [
    # Authentication
    path('signup/send-otp/', SignupSendOTPView.as_view(), name='signup-send-otp'),
    path('signup/verify-otp/', SignupVerifyOTPView.as_view(), name='signup-verify-otp'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/<int:pk>/', LoginWithIdView.as_view(), name='login-with-id'),
    path('user/<int:pk>/', UserUpdateView.as_view(), name='user-update'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
    path('google-signin/', GoogleSignInView.as_view(), name='google-signin'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset/confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password-reset/verify-otp/', PasswordResetVerifyOTPView.as_view(), name='password-reset-verify-otp'),
    path('delete-account/<int:pk>/', DeleteAccountView.as_view(), name='delete-account'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('check-email-verification/', CheckEmailVerificationView.as_view(), name='check-email-verification'),
    # Deprecated combined counts endpoint
    path('counts/', LostFoundAndAlertCountView.as_view(), name='lostfound-alerts-count'),
    # New separate counts endpoints
    path('alerts/count/', AlertCountView.as_view(), name='alert-count'),
    path('lostfound/count/', LostFoundCountView.as_view(), name='lostfound-count'),
    # Access Codes
    path('access-code/create/', AccessCodeCreateView.as_view(), name='access-code-create'),
    path('access-code/verify/', AccessCodeVerifyView.as_view(), name='access-code-verify'),
    path('access-code/verified-count/', AccessCodeVerifiedCountView.as_view(), name='access-code-verified-count'),
    path('access-code/unapproved-count/', AccessCodeUnapprovedCountView.as_view(), name='access-code-unapproved-count'),
    path('access-codes/by-user/', AccessCodeByUserListView.as_view(), name='access-code-by-user-list'),
    path('access-codes/<str:code>/deactivate/', AccessCodeDeactivateView.as_view(), name='access-code-deactivate'),
    path('visitor/checkin/', VisitorCheckinListView.as_view(), name='visitor-checkin-list'),
    path('visitor/checkin/all/', GeneralVisitorCheckinListView.as_view(), name='visitor-checkin-list-all'),
    # Alerts
    path('alerts/', AlertListView.as_view(), name='alert-list'),
    path('alerts/create/', AlertCreateView.as_view(), name='alert-create'),
    path('alerts/<int:alert_id>/delete/', AlertDeleteView.as_view(), name='alert-delete'),
    path('alerts/<int:alert_id>/', AlertDeleteView.as_view(), name='alert-delete-delete'),
    # Lost and Found
    path('lostfound/', LostFoundItemListView.as_view(), name='lostfound-list'),
    path('lostfound/create/', LostFoundItemCreateView.as_view(), name='lostfound-create'),
    path('lostfound/<int:pk>/', LostFoundItemDetailView.as_view(), name='lostfound-detail'),
    path('residence-users/all/', ResidenceUsersListAllView.as_view(), name='residence-users-list-all'),
    path('security-personnel-users/all/', SecurityPersonnelUsersListAllView.as_view(), name='security-personnel-users-list-all'),
    path('lostfound/all/', LostFoundItemListAllView.as_view(), name='lostfound-list-all'),
    path('alerts/all/', GeneralAlertListView.as_view(), name='general-alert-list'),
    # Payments
    path('verify-and-credit/', VerifyAndCreditView.as_view(), name='verify-and-credit'),
    # User role based lists and counts
    path('residence-users/', ResidenceUsersListView.as_view(), name='residence-users-list'),
    path('security-personnel-users/', SecurityPersonnelUsersListView.as_view(), name='security-personnel-users-list'),
    path('residence-users/count/', ResidenceUsersCountView.as_view(), name='residence-users-count'),
    path('security-personnel-users/count/', SecurityPersonnelUsersCountView.as_view(), name='security-personnel-users-count'),
    path('alerts/count/by-estate/', AlertCountByEstateView.as_view(), name='alert-count-by-estate'),
    path('lostfound/count/by-estate/', LostFoundCountByEstateView.as_view(), name='lostfound-count-by-estate'),
    path('access-code/verified-count/by-estate/', AccessCodeVerifiedCountByEstateView.as_view(), name='access-code-verified-count-by-estate'),
    path('access-code/unapproved-count/by-estate/', AccessCodeUnapprovedCountByEstateView.as_view(), name='access-code-unapproved-count-by-estate'),
    path('residence-users/count/by-estate/', ResidenceUsersCountByEstateView.as_view(), name='residence-users-count-by-estate'),
    path('security-personnel-users/count/by-estate/', SecurityPersonnelUsersCountByEstateView.as_view(), name='security-personnel-users-count-by-estate'),
    # Private Messages
    path('private-messages/', PrivateMessageListView.as_view(), name='private-message-list'),
    path('private-messages/send/', PrivateMessageCreateView.as_view(), name='private-message-create'),
    path('private-messages/mark-seen/', PrivateMessageMarkSeenView.as_view(), name='private-message-mark-seen'),
    path('private-messages/<int:pk>/delete/', PrivateMessageDeleteView.as_view(), name='private-message-delete'),
    path('private-messages/<int:pk>/', PrivateMessageDeleteView.as_view(), name='private-message-delete-alt'),
    # Profile Image Upload
    path('upload-profile-image/', UploadProfileImageView.as_view(), name='upload-profile-image'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('user/<int:user_id>/transactions/', UserTransactionListView.as_view(), name='user-transactions'),
    path('subscription-users/', SubscriptionUsersListView.as_view(), name='subscription-users-list'),
]
