from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import BaseParser, JSONParser
from rest_framework.renderers import JSONRenderer, BrowsableAPIRenderer
import uuid
from rest_framework import filters
from django.db import IntegrityError
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework.authtoken.models import Token as AuthToken
from django.contrib.auth import authenticate
from rest_framework import serializers
from .serializers import AlertSerializer, UserSerializer, LostFoundItemSerializer, TransactionSerializer, SubscriptionUserSerializer
from .models import Alert, UserProfile, LostFoundItem, Transaction
from google.oauth2 import id_token
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework.permissions import IsAuthenticated
import logging
import pytz

WAT = pytz.timezone('Africa/Lagos')
from rest_framework import generics
from .serializers import AccessCodeSerializer
from .models import AccessCode
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse
import json
import hashlib
import hmac
from rest_framework.decorators import api_view
from decimal import Decimal

from rest_framework.parsers import FormParser


from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from rest_framework.parsers import MultiPartParser, FormParser  # Add this import

import os
import uuid
from django.utils.deconstruct import deconstructible

class SubscriptionUsersListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if estate:
            users = User.objects.filter(profile__is_email_verified=True, profile__estate=estate).distinct()
        else:
            users = User.objects.filter(profile__is_email_verified=True).distinct()

        subscription_users = []

        for user in users:
            amount = user.profile.wallet_balance
            payment_date = None
            subscription_type = user.profile.plan.lower() if user.profile.plan else 'free'

            subscription_users.append({
                'user_id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'payment_amount': amount,
                'subscription_type': subscription_type,
                'payment_date': payment_date,
            })

        serializer = SubscriptionUserSerializer(subscription_users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UploadProfileImageView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, format=None):
        import logging
        logger = logging.getLogger(__name__)
        logger.info("UploadProfileImageView POST called")
        logger.info(f"Request user: {request.user}")
        logger.info(f"Request files: {request.FILES}")

        file_obj = request.FILES.get('image')
        if not file_obj:
            logger.warning("No image file provided in request")
            return Response({'error': 'No image file provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a unique filename with the original extension
        ext = os.path.splitext(file_obj.name)[1]  # e.g. '.jpg'
        unique_filename = f"{uuid.uuid4().hex}{ext}"

        # Save the file to default storage (e.g., media folder) with unique name
        file_path = default_storage.save(f'profile_images/{unique_filename}', ContentFile(file_obj.read()))
        image_url = default_storage.url(file_path)

        # Prepend base URL to image_url if not absolute
        base_url = get_base_url()
        if not image_url.startswith('http'):
            if image_url.startswith('/'):
                image_url = base_url + image_url
            else:
                image_url = base_url + '/' + image_url

        logger.info(f"Image saved at: {file_path}, URL: {image_url}")

        return Response({'image_url': image_url}, status=status.HTTP_200_OK)

class UserTransactionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        transactions = Transaction.objects.filter(user=user).order_by('-date')
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

from django.db import transaction
from django.utils.timezone import now
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
import random

OTP_LIFETIME_MINUTES = 10


class SignupView(APIView):
    """
    Signup + email‑OTP verification.
    """
    def post(self, request):
        email      = request.data.get('email', '').strip().lower()
        otp        = request.data.get('otp', '').strip()
        first_name = request.data.get('first_name', '').strip()
        last_name  = request.data.get('last_name', '').strip()
        password   = request.data.get('password', '').strip()

        if not all([email, first_name, last_name, password]):
            return Response(
                {'error': 'Email, first name, last name, and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
            profile = user.profile

            # Already verified?  Bail out early.
            if profile.is_email_verified:
                return Response(
                    {'message': 'Email already verified. Please sign in.'},
                    status=status.HTTP_200_OK
                )

            # --- Verify OTP ---
            if otp:
                if otp != profile.signup_otp:
                    return Response(
                        {'status': 'failure', 'message': 'Invalid OTP'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if profile.signup_otp_expiry < now():
                    return Response(
                        {'status': 'failure', 'message': 'OTP expired'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                profile.is_email_verified = True
                profile.signup_otp = None
                profile.signup_otp_expiry = None
                profile.save(update_fields=[
                    'is_email_verified', 'signup_otp', 'signup_otp_expiry'
                ])
                return Response(
                    {'status': 'success', 'message': 'Email verified successfully'},
                    status=status.HTTP_200_OK
                )

            # --- Resend OTP (but don’t regenerate if still valid) ---
            if profile.signup_otp and profile.signup_otp_expiry > now():
                otp_code = profile.signup_otp         # reuse existing
            else:
                otp_code = f"{random.randint(100000, 999999)}"
                profile.signup_otp = otp_code
                profile.signup_otp_expiry = now() + timedelta(minutes=OTP_LIFETIME_MINUTES)
                profile.save(update_fields=['signup_otp', 'signup_otp_expiry'])

            self._send_signup_otp_email(user.first_name, user.email, otp_code)
            return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

        # ----------------------------------------------------------
        # New user branch
        # ----------------------------------------------------------
        except User.DoesNotExist:
            with transaction.atomic():
                from .serializers import UserSerializer
                profile_data = request.data.get('profile', {})
                role_value = profile_data.get('role', '').strip()
                if role_value.lower() == 'security personnel':
                    role_value = 'Security Personnel'
                elif role_value.lower() == 'residence':
                    role_value = 'Residence'
                else:
                    role_value = ''  # Invalid role will cause serializer validation error

                user_data = {
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'password': password,
                    'profile': {
                        'phone_number': profile_data.get('phone_number', ''),
                        'role': role_value,
                        'estate': profile_data.get('estate', ''),
                        'estate_email': profile_data.get('estate_email', ''),
                        'house_address': profile_data.get('house_address', ''),
                        'pin': profile_data.get('pin', ''),
                        'plan': profile_data.get('plan', ''),
                        'profile_picture': profile_data.get('profile_picture', ''),
                        'wallet_balance': 0.0,
                    }
                }
                serializer = UserSerializer(data=user_data)
                if serializer.is_valid():
                    user = serializer.save()
                    profile = user.profile

                    # Set subscription start and expiry dates based on plan after signup
                    from django.utils.timezone import now
                    plan = profile_data.get('plan', '').lower()
                    profile.subscription_start_date = now()
                    if plan == 'monthly':
                        profile.subscription_expiry_date = now() + timedelta(days=30)
                    elif plan == 'annual':
                        profile.subscription_expiry_date = now() + timedelta(days=365)
                    else:
                        # For free or unknown plans, set expiry 30 days from now
                        profile.subscription_expiry_date = now() + timedelta(days=30)
                    profile.save(update_fields=['signup_otp', 'signup_otp_expiry', 'subscription_start_date', 'subscription_expiry_date'])

                    print(f"Subscription dates set after signup: start={profile.subscription_start_date}, expiry={profile.subscription_expiry_date}, plan={plan}")

                    otp_code = f"{random.randint(100000, 999999)}"
                    profile.signup_otp = otp_code
                    profile.signup_otp_expiry = now() + timedelta(minutes=OTP_LIFETIME_MINUTES)
                    profile.save(update_fields=['signup_otp', 'signup_otp_expiry'])
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            self._send_signup_otp_email(first_name, email, otp_code)
            return Response(
                {'message': 'User created and OTP sent successfully'},
                status=status.HTTP_201_CREATED
            )

    # ------------------------------------------------------------------
    # Helper: send e‑mail (kept outside the main logic for clarity)
    # ------------------------------------------------------------------
    def _send_signup_otp_email(self, first_name, email, otp_code):
        send_mail(
            subject='Your Vaultify Signup OTP',
            message=f"""Dear {first_name},

You’re just one step away from joining your Estate on Vaultify.
please verify your email address. Here’s why it’s important:
	•	Account Protection: Verifying your email helps secure your profile and prevent unauthorized access.
	•	Stay Informed: Get important announcements, updates, and alerts from your estate without missing a thing.

Input the otp below to confirm your email and get the full Vaultify experience:

                   Confirm Email

Warm regards,
The Vaultify Team.
To complete your sign‑in, please verify your email address using the OTP below.

Your OTP is: {otp_code}

This OTP expires in {OTP_LIFETIME_MINUTES} minutes.

Warm regards,
The Vaultify Team""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
class PlainTextParser(BaseParser):
    """
    Plain text parser for 'text/plain' content type.
    """
    media_type = 'text/plain'

    def parse(self, stream, media_type=None, parser_context=None):
        return stream.read().decode('utf-8')

class PlainTextOrFormParser(FormParser):
    """
    Parser to accept both 'text/plain' and 'application/x-www-form-urlencoded' content types.
    """
    media_type = 'text/plain'

    def parse(self, stream, media_type=None, parser_context=None):
        if media_type == 'application/x-www-form-urlencoded':
            return super().parse(stream, media_type, parser_context)
        return stream.read().decode('utf-8')

PAYSTACK_SECRET_KEY = 'sk_live_43fc893ff9d7a6dd07302e43aae78602c0dc62c8'  # Replace with your Paystack secret key

# Helper function to get the base URL for email links
def get_base_url():
    return getattr(settings, 'BASE_URL', 'https://vaultify-43wm.onrender.com')

logger = logging.getLogger(__name__)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import random
from datetime import timedelta
from django.utils.timezone import now
from django.core.mail import send_mail
from django.conf import settings
import logging
import uuid

logger = logging.getLogger(__name__)

class SignupSendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email', '').strip().lower()
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists
        from django.contrib.auth.models import User
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        profile = user.profile

        # Generate 6-digit OTP
        otp = f"{random.randint(100000, 999999)}"
        profile.signup_otp = otp
        profile.signup_otp_expiry = now() + timedelta(minutes=10)
        profile.save()

        # Send OTP email with personalized text
        try:
            send_mail(
                'Your Vaultify Signup OTP',
                f"""Dear {user.first_name},

You’re just one step away from joining your Estate on Vaultify. To complete your sign-in, please verify your email address using the OTP below. Here’s why it’s important:
\t•\tAccount Protection: Verifying your email helps secure your profile and prevent unauthorized access.
\t•\tStay Informed: Get important announcements, updates, and alerts from your estate without missing a thing.

Your OTP is: {otp}

This OTP expires in 10 minutes.

Warm regards,
The Vaultify Team.
""",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Signup OTP sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send signup OTP: {e}")
            return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

class SignupVerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email', '').strip().lower()
        otp = request.data.get('otp', '').strip()

        if not email or not otp:
            return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

        from django.contrib.auth.models import User
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        profile = user.profile

        if profile.signup_otp != otp:
            return Response({'status': 'failure', 'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if profile.signup_otp_expiry < now():
            return Response({'status': 'failure', 'message': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Mark email as verified and clear OTP fields
        profile.is_email_verified = True
        profile.signup_otp = None
        profile.signup_otp_expiry = None
        profile.save()

        logger.info(f"Email verified for user {user.email} via OTP")
        return Response({'status': 'success', 'message': 'Email verified successfully'}, status=status.HTTP_200_OK)
class CheckEmailVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.profile.is_email_verified:
            return Response({'is_email_verified': True}, status=status.HTTP_200_OK)
        else:
            return Response({'is_email_verified': False}, status=status.HTTP_200_OK)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email').lower()  # Normalize to lowercase
        password = request.data.get('password')
        user = authenticate(username=email, password=password)
        if user:
            if not user.profile.is_email_verified:
                logger.warning(f"Login failed: Email not verified for {email}")
                return Response({'error': 'Email not verified'}, status=status.HTTP_403_FORBIDDEN)
            token, _ = AuthToken.objects.get_or_create(user=user)
            logger.info(f"User {email} logged in successfully, Role: {user.profile.role}")
            return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)
        logger.warning(f"Login failed: Invalid credentials for {email}")
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    from datetime import timedelta
    from django.utils.timezone import now
    import random
    def put(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        old_email = user.email
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            new_email = serializer.instance.email
            logger.info(f"User {old_email} updated to {new_email}, Role: {user.profile.role}, Profile Picture: {user.profile.profile_picture}")

            # If email changed, generate new OTP for email verification and send OTP email
            if old_email != new_email:
                otp_code = f"{random.randint(100000, 999999)}"
                user.profile.signup_otp = otp_code
                user.profile.signup_otp_expiry = now() + timedelta(minutes=10)
                user.profile.is_email_verified = False
                user.profile.save(update_fields=['signup_otp', 'signup_otp_expiry', 'is_email_verified'])
                from django.core.mail import send_mail
                from django.conf import settings
                send_mail(
                    'Verify Your New Email - OTP',
                    f'Your OTP to verify your new email is: {otp_code}. It expires in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [new_email],
                    fail_silently=False,
                )
                logger.info(f"Verification OTP email sent to {new_email} after email change")

            return Response(serializer.data, status=status.HTTP_200_OK)
        logger.error(f"User update errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AccessCodeCreateView(generics.CreateAPIView):
    serializer_class = AccessCodeSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        try:
            serializer.save(creator=self.request.user)
        except IntegrityError as e:
            # The perform_create method should not return Response objects.
            # Instead, raise the exception to be handled by the framework.
            raise e

@method_decorator(csrf_exempt, name='dispatch')
class PaystackWebhookView(APIView):
    def post(self, request, *args, **kwargs):
        paystack_secret = 'sk_live_43fc893ff9d7a6dd07302e43aae78602c0dc62c8'  # Use your secret key
        signature = request.headers.get('x-paystack-signature')
        payload = request.body

        if not signature:
            return JsonResponse({'error': 'Signature missing'}, status=400)

        computed_signature = hmac.new(
            paystack_secret.encode('utf-8'),
            msg=payload,
            digestmod=hashlib.sha512
        ).hexdigest()

        if not hmac.compare_digest(computed_signature, signature):
            return JsonResponse({'error': 'Invalid signature'}, status=400)

        event = json.loads(payload)

        if event.get('event') == 'charge.success':
            data = event.get('data', {})
            reference = data.get('reference')
            amount = data.get('amount')  # amount in kobo
            customer_email = data.get('customer', {}).get('email')

            try:
                user = User.objects.get(email=customer_email)
                profile = user.profile
                amount_naira = Decimal(amount) / Decimal('100.0')
                profile.wallet_balance += amount_naira
                profile.save()
                logger.info(f"Wallet updated for {customer_email}: +{amount_naira}")
                return JsonResponse({'status': 'success'}, status=200)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)

        return JsonResponse({'status': 'ignored'}, status=200)

from django.shortcuts import get_object_or_404, redirect
from django.conf import settings
from urllib.parse import urlencode

class VerifyEmailView(APIView):
    def get(self, request, token):
        redirect_url = getattr(settings, 'EMAIL_VERIFICATION_REDIRECT_URL', None)
        try:
            profile = UserProfile.objects.get(email_verification_token=token)
            profile.is_email_verified = True
            profile.email_verification_token = ''
            profile.save()
            logger.info(f"Email verified for user {profile.user.email}")
            if redirect_url:
                params = urlencode({'status': 'success'})
                return redirect(f"{redirect_url}?{params}")
            else:
                return Response({
                    'status': 'success',
                    'message': 'Your email has been verified successfully. You can now log in.'
                }, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            if redirect_url:
                params = urlencode({'status': 'failure'})
                return redirect(f"{redirect_url}?{params}")
            else:
                return Response({
                    'status': 'failure, you might have received another email please verify with that', 
                    'message': 'Invalid token. Please request a new verification email.'
                }, status=status.HTTP_400_BAD_REQUEST)

class ResendVerificationEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            if user.profile.is_email_verified:
                return Response({'error': 'Email already verified'}, status=status.HTTP_400_BAD_REQUEST)
            verification_token = str(uuid.uuid4())
            user.profile.email_verification_token = verification_token
            user.profile.save()
            send_mail(
                'Verify Your Email',
                f'Click the link to verify your email: {get_base_url()}/api/verify-email/{verification_token}/',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            logger.info(f"Verification email resent to {email}")
            return Response({'message': 'Verification email resent'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class GoogleSignInView(APIView):
    def post(self, request):
        token = request.data.get('id_token')
        try:
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), settings.GOOGLE_CLIENT_ID)
            email = idinfo['email']
            name = idinfo.get('name', '')
            first_name = name.split(' ')[0] if name else ''
            last_name = ' '.join(name.split(' ')[1:]) if len(name.split(' ')) > 1 else ''
            user, created = User.objects.get_or_create(
                username=email,
                defaults={
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                }
            )
            if created:
                user.set_password(str(uuid.uuid4()))
                user.save()
                UserProfile.objects.create(user=user, is_email_verified=True)
            if not user.profile.is_email_verified:
                return Response({'error': 'Email not verified'}, status=status.HTTP_403_FORBIDDEN)
            token, _ = AuthToken.objects.get_or_create(user=user)
            logger.info(f"Google sign-in successful for {email}, Role: {user.profile.role}")
            return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)
        except ValueError:
            return Response({'error': 'Invalid Google token'}, status=status.HTTP_400_BAD_REQUEST)

import random
from datetime import datetime, timedelta
from django.utils.timezone import now

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            users = User.objects.filter(email=email)
            if not users.exists():
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            for user in users:
                profile = user.profile
                # Generate 6-digit OTP
                otp = f"{random.randint(100000, 999999)}"
                profile.password_reset_otp = otp
                profile.password_reset_otp_expiry = now() + timedelta(minutes=10)
                profile.save()

                # Send OTP email
                send_mail(
                    'Password Reset OTP',
                    f'Your password reset OTP is: {otp}. It expires in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                logger.info(f"Password reset OTP sent to {email} for user {user.id}")
            return Response({'message': 'Password reset OTP sent'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error in PasswordResetRequestView: {str(e)}")
            return Response({'error': 'An error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PasswordResetVerifyOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')

        if not all([email, otp, new_password]):
            return Response({'error': 'Email, OTP, and new password are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            users = User.objects.filter(email=email)
            if not users.exists():
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            if users.count() > 1:
                logger.warning(f"Multiple users found with email {email}. Using the first user for OTP verification.")
            user = users.first()
            profile = user.profile
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if profile.password_reset_otp != otp:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if profile.password_reset_otp_expiry < now():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        # Clear OTP fields
        profile.password_reset_otp = None
        profile.password_reset_otp_expiry = None
        profile.save()

        logger.info(f"Password reset successful for {user.email} via OTP")
        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)




class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        if request.user.pk != pk:
            return Response({'error': 'You can only delete your own account'}, status=status.HTTP_403_FORBIDDEN)
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            logger.info(f"Account deleted for {user.email}")
            return Response({'message': 'Account deleted successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            if request.auth:
                token = AuthToken.objects.get(key=request.auth)
                token.delete()
                logger.info(f"User {request.user.email} logged out successfully")
                return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)
            return Response({'error': 'No active session found'}, status=status.HTTP_400_BAD_REQUEST)
        except AuthToken.DoesNotExist:
            return Response({'error': 'Failed to logout: Token not found'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response({'error': 'Failed to logout'}, status=status.HTTP_400_BAD_REQUEST)

class LoginWithIdView(APIView):
    def get(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            if not user.profile.is_email_verified:
                return Response({'error': 'Email not verified'}, status=status.HTTP_403_FORBIDDEN)
            token, _ = AuthToken.objects.get_or_create(user=user)
            logger.info(f"Login with ID successful for {user.email}, Role: {user.profile.role}")
            return Response({'token': token.key, 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
        
from datetime import timedelta, time

class AccessCodeCreateView(generics.CreateAPIView):
    serializer_class = AccessCodeSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        try:
            instance = serializer.save(creator=self.request.user)
            logger.info(f"Access code created: {instance.code} by user {self.request.user.email}")
        except Exception as e:
            logger.error(f"Error creating access code: {e}")
            raise e

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import AccessCode, UserDeletedAlert, Alert
from .serializers import AccessCodeSerializer, AlertSerializer
from django.utils import timezone
import logging
import pytz
from rest_framework.permissions import IsAuthenticated

WAT = pytz.timezone('Africa/Lagos')
logger = logging.getLogger(__name__)

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class AlertCountByEstateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        alerts_count = Alert.objects.filter(sender__profile__estate=estate).count()
        return Response({'estate': estate, 'alerts_count': alerts_count}, status=status.HTTP_200_OK)

class LostFoundCountByEstateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        lostfound_count = LostFoundItem.objects.filter(sender__profile__estate=estate).count()
        return Response({'estate': estate, 'lostfound_count': lostfound_count}, status=status.HTTP_200_OK)

class AccessCodeVerifiedCountByEstateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        verified_count = AccessCode.objects.filter(creator__profile__estate=estate, current_uses__gt=0).count()
        return Response({'estate': estate, 'verified_count': verified_count}, status=status.HTTP_200_OK)

class AccessCodeUnapprovedCountByEstateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        unapproved_count = AccessCode.objects.filter(creator__profile__estate=estate, current_uses=0).count()
        return Response({'estate': estate, 'unapproved_count': unapproved_count}, status=status.HTTP_200_OK)

class ResidenceUsersCountByEstateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        count = User.objects.filter(profile__role='Residence', profile__is_email_verified=True, profile__estate=estate).count()
        return Response({'estate': estate, 'count': count}, status=status.HTTP_200_OK)

class SecurityPersonnelUsersCountByEstateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        count = User.objects.filter(profile__role='Security Personnel', profile__is_email_verified=True, profile__estate=estate).count()
        return Response({'estate': estate, 'count': count}, status=status.HTTP_200_OK)

class LostFoundAndAlertCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Deprecated combined counts endpoint
        return Response({'detail': 'Use separate endpoints for alerts and lostfound counts'}, status=status.HTTP_400_BAD_REQUEST)

class AlertCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        deleted_alert_ids = user.deleted_alerts.values_list('alert_id', flat=True)
        user_role = None
        try:
            user_role = user.profile.role
        except Exception as e:
            # Log error if user profile or role is missing
            logger.error(f"Error getting user role for alert count: {e}")
        if not user_role:
            return Response({'alerts_count': 0}, status=status.HTTP_200_OK)
        alerts_count = Alert.objects.filter(
            recipients__contains=[user_role]
        ).exclude(
            id__in=deleted_alert_ids
        ).count()
        logger.debug(f"User {user.username} with role {user_role} has {alerts_count} alerts")
        return Response({'alerts_count': alerts_count}, status=status.HTTP_200_OK)

class LostFoundCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        lostfound_count = LostFoundItem.objects.count()
        logger.debug(f"Total lost and found items count: {lostfound_count}")
        return Response({'lostfound_count': lostfound_count}, status=status.HTTP_200_OK)

class AlertDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, alert_id):
        user = request.user
        try:
            alert = Alert.objects.get(id=alert_id)
        except Alert.DoesNotExist:
            return Response({'error': 'Alert not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if already deleted
        deleted, created = UserDeletedAlert.objects.get_or_create(user=user, alert=alert)
        if created:
            logger.info(f"User {user.username} deleted alert {alert_id}")
        else:
            logger.info(f"User {user.username} had already deleted alert {alert_id}")

        return Response({'message': 'Alert deleted successfully'}, status=status.HTTP_200_OK)

    def delete(self, request, alert_id):
        user = request.user
        try:
            alert = Alert.objects.get(id=alert_id)
        except Alert.DoesNotExist:
            return Response({'error': 'Alert not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if already deleted
        deleted, created = UserDeletedAlert.objects.get_or_create(user=user, alert=alert)
        if created:
            logger.info(f"User {user.username} deleted alert {alert_id} via DELETE")
        else:
            logger.info(f"User {user.username} had already deleted alert {alert_id} via DELETE")

        return Response({'message': 'Alert deleted successfully'}, status=status.HTTP_200_OK)

class AlertListView(generics.ListAPIView):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['alert_type', 'urgency_level', 'recipients']

    def get_queryset(self):
        user = self.request.user
        try:
            user_role = user.profile.role
        except Exception:
            user_role = None
        if not user_role:
            return Alert.objects.none()

        # Define opposite role mapping for cross-role alert fetching
        opposite_role_map = {
            'Residence': 'Security Personnel',
            'Security Personnel': 'Residence',
        }

        opposite_role = opposite_role_map.get(user_role)

        # Get alerts deleted by the user
        deleted_alert_ids = user.deleted_alerts.values_list('alert_id', flat=True)

        # Filter alerts where recipients contain user_role and sender's role is opposite_role
        # or alerts sent by the user themselves (optional)
        return Alert.objects.filter(
            recipients__contains=[user_role]
        ).filter(
            Q(sender__profile__role=opposite_role) | Q(sender=user)
        ).exclude(
            id__in=deleted_alert_ids
        ).order_by('-timestamp')

class AccessCodeVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        code = request.data.get('code')
        user = request.user
        auth_header = request.headers.get('Authorization', 'No Authorization header')
        logger.debug(f"AccessCodeVerifyView called by user: {user.email}, Authorization: {auth_header}, code: {code}")

        if not code:
            logger.error("No code provided in verification request")
            return Response({"error": "Access code is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            access_code = AccessCode.objects.get(code=code)
        except AccessCode.DoesNotExist:
            logger.warning(f"Access code not found: {code}")
            return Response({"error": "Invalid access code"}, status=status.HTTP_404_NOT_FOUND)

        # Estate-based restriction check
        user_estate = getattr(request.user.profile, 'estate', None)
        access_code_estate = getattr(access_code.creator.profile, 'estate', None)
        if user_estate != access_code_estate:
            logger.warning(f"User {request.user.email} from estate {user_estate} attempted to verify access code from estate {access_code_estate}")
            return Response({"error": "You are not authorized to verify access codes from this estate."}, status=status.HTTP_403_FORBIDDEN)

        now = timezone.now().astimezone(WAT)
        if now < access_code.valid_from:
            logger.warning(f"Access code not yet valid: {code}, Now: {now}, Valid from: {access_code.valid_from}")
            return Response(
                {"error": f"Access code is not yet valid: {access_code.valid_from}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if now > access_code.valid_to:
            logger.warning(f"Access code expired: {code}, Now: {now}, Valid to: {access_code.valid_to}")
            return Response(
                {"error": f"Access code has expired: {access_code.valid_to}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not access_code.is_active:
            logger.warning(f"Access code is inactive: {code}")
            return Response({"error": "Access code is disabled"}, status=status.HTTP_400_BAD_REQUEST)
        if access_code.current_uses >= access_code.max_uses:
            logger.warning(f"Access code max uses reached: {code}")
            return Response({"error": "Access code has reached its maximum usage limit"}, status=status.HTTP_400_BAD_REQUEST)

        # Update current_uses and deactivate if max_uses reached
        access_code.current_uses += 1
        if access_code.current_uses >= access_code.max_uses:
            access_code.is_active = False
        access_code.save()

        # Optionally send notification if notify_on_use is True
        if access_code.notify_on_use:
            # Implement notification logic (e.g., email or push notification)
            pass

        return Response({
            'visitorName': access_code.visitor_name,
            'visitorEmail': access_code.visitor_email,
            'visitorPhone': access_code.visitor_phone,
            'hostName': access_code.creator.get_full_name() or access_code.creator.email,
            'status': 'valid',
            'accessArea': access_code.gate,
            'code': access_code.code,
            'validFrom': access_code.valid_from.isoformat(),
            'validTo': access_code.valid_to.isoformat(),
            'verified_count': access_code.current_uses,
            'unapproved_count': 0 if access_code.current_uses > 0 else 1,
        }, status=status.HTTP_200_OK)

    def get(self, request, code):
        try:
            access_code = AccessCode.objects.get(code=code)
        except AccessCode.DoesNotExist:
            logger.warning(f"Access code not found: {code}")
            return Response({"error": "Invalid access code"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AccessCodeSerializer(access_code)
        response_data = {
            "code": access_code.code,
            "visitorName": access_code.visitor_name,
            "visitorEmail": access_code.visitor_email,
            "visitorPhone": access_code.visitor_phone,
            "hostName": access_code.creator.get_full_name() or access_code.creator.email,
            "status": "Verified" if access_code.current_uses > 0 else "Pending",
            "accessArea": access_code.gate,
            "validFrom": access_code.valid_from.isoformat(),
            "validTo": access_code.valid_to.isoformat(),
        }
        return Response(response_data, status=status.HTTP_200_OK)
    
class AccessCodeVerifiedCountView(APIView):
    def get(self, request):
        verified_count = AccessCode.objects.filter(current_uses__gt=0).count()
        return Response({"verified_count": verified_count}, status=status.HTTP_200_OK)

class AccessCodeUnapprovedCountView(APIView):
    def get(self, request):
        unapproved_count = AccessCode.objects.filter(current_uses=0).count()
        return Response({"unapproved_count": unapproved_count}, status=status.HTTP_200_OK)
    
class AlertCreateView(generics.CreateAPIView):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user_estate = getattr(self.request.user.profile, 'estate', None)
        serializer.save(sender=self.request.user, estate=user_estate)

class AlertListView(generics.ListAPIView):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['alert_type', 'urgency_level', 'recipients']

    def get_queryset(self):
        from django.db.models import Q

        user = self.request.user
        user_id_str = str(user.id)
        estate = self.request.query_params.get('estate')
        if not estate:
            try:
                estate = getattr(user.profile, 'estate', None)
                user_role = user.profile.role
            except Exception:
                user_role = None
                estate = None
        else:
            try:
                user_role = user.profile.role
            except Exception:
                user_role = None

        if not user_id_str or not user_role or not estate:
            return Alert.objects.none()

        deleted_alert_ids = user.deleted_alerts.values_list('alert_id', flat=True)

        if user_role.lower() == 'security personnel':
            # Return all alerts in the specified estate except those deleted by the user
            return Alert.objects.filter(
                sender__profile__estate=estate
            ).exclude(
                id__in=deleted_alert_ids
            ).order_by('-timestamp')

        # For other roles, filter alerts where recipients contain user ID or user role and estate matches
        return Alert.objects.filter(
            (Q(recipients__contains=[user_id_str]) | Q(recipients__contains=[user_role])) &
            Q(sender__profile__estate=estate)
        ).exclude(
            id__in=deleted_alert_ids
        ).order_by('-timestamp')


class GeneralAlertListView(generics.ListAPIView):
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['alert_type', 'urgency_level', 'recipients']

    def get_queryset(self):
        user = self.request.user
        deleted_alert_ids = user.deleted_alerts.values_list('alert_id', flat=True)
        return Alert.objects.exclude(
            id__in=deleted_alert_ids
        ).order_by('-timestamp')

from rest_framework.parsers import MultiPartParser, FormParser

class LostFoundItemCreateView(generics.CreateAPIView):
    queryset = LostFoundItem.objects.all()
    serializer_class = LostFoundItemSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def perform_create(self, serializer):
        user_estate = getattr(self.request.user.profile, 'estate', None)
        serializer.save(sender=self.request.user, estate=user_estate)

class LostFoundItemListView(generics.ListAPIView):
    serializer_class = LostFoundItemSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['item_type', 'description', 'location', 'contact_info']

    def get_queryset(self):
        estate = self.request.query_params.get('estate')
        if not estate:
            estate = getattr(self.request.user.profile, 'estate', None)
        if not estate:
            return LostFoundItem.objects.none()
        return LostFoundItem.objects.filter(sender__profile__estate=estate).order_by('-date_reported')

class LostFoundItemListAllView(generics.ListAPIView):
    serializer_class = LostFoundItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return LostFoundItem.objects.all().order_by('-date_reported')

class LostFoundItemListAllView(generics.ListAPIView):
    serializer_class = LostFoundItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return LostFoundItem.objects.all().order_by('-date_reported')

class LostFoundItemListAllView(generics.ListAPIView):
    serializer_class = LostFoundItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return LostFoundItem.objects.all().order_by('-date_reported')

from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .serializers import UserSerializer

class LostFoundItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = LostFoundItem.objects.all()
    serializer_class = LostFoundItemSerializer
    permission_classes = [IsAuthenticated]
    
class VisitorCheckinListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        estate = self.request.query_params.get('estate')
        if not estate:
            return AccessCode.objects.none()
        return AccessCode.objects.filter(current_uses__gt=0, creator__profile__estate=estate).order_by('-created_at')

    def list(self, request, *args, **kwargs):
        estate = request.query_params.get('estate')
        if not estate:
            return Response({'error': 'Estate parameter is required'}, status=status.HTTP_400_BAD_REQUEST)
        queryset = self.get_queryset()
        serializer = AccessCodeSerializer(queryset, many=True)
        response_data = {
            'count': queryset.count(),
            'visitors': [
                {
                    'visitorName': item['visitor_name'],
                    'accessCode': item['code'],
                    'hostName': item['creator_name'],
                    'checkInTime': item['created_at'],
                    'expectedCheckOutTime': item['valid_to'],
                    'accessArea': item['gate'],
                    'estate': item.get('creator_profile', {}).get('estate', '')  # Add estate field here
                } for item in serializer.data
            ]
        }
        return Response(response_data)
    
    

# New GeneralVisitorCheckinListView without estate filtering
class GeneralVisitorCheckinListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return AccessCode.objects.filter(current_uses__gt=0).order_by('-created_at')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = AccessCodeSerializer(queryset, many=True)
        response_data = {
            'count': queryset.count(),
            'visitors': [
                {
                    'visitorName': item['visitor_name'],
                    'accessCode': item['code'],
                    'hostName': item['creator_name'],
                    'checkInTime': item['created_at'],
                    'expectedCheckOutTime': item['valid_to'],
                    'accessArea': item['gate'],
                    'estate': item.get('creator_profile', {}).get('estate', '')  # Add estate field here
                } for item in serializer.data
            ]
        }
        return Response(response_data)

    


class ResidenceUsersListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        estate = self.request.query_params.get('estate')
        if not estate:
            user = self.request.user
            estate = getattr(user.profile, 'estate', None)
        if not estate:
            return User.objects.none()
        return User.objects.filter(
            profile__role='Residence',
            profile__is_email_verified=True,
            profile__estate=estate
        )


class ResidenceUsersListAllView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(profile__role='Residence', profile__is_email_verified=True)

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import PrivateMessage
from .serializers import PrivateMessageSerializer
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Q

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Q
from django.contrib.auth.models import User
from .models import PrivateMessage
from .serializers import PrivateMessageSerializer

class PrivateMessageListView(generics.ListCreateAPIView):
    serializer_class = PrivateMessageSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        other_user_id = self.request.query_params.get('user_id')
        if not other_user_id:
            return PrivateMessage.objects.none()
        # Get estates of both users
        try:
            user_estate = user.profile.estate
            other_user = User.objects.get(id=other_user_id)
            other_user_estate = other_user.profile.estate
        except Exception:
            return PrivateMessage.objects.none()
        # Only allow messages if both users belong to the same estate
        if user_estate != other_user_estate:
            return PrivateMessage.objects.none()
        return PrivateMessage.objects.filter(
            Q(sender=user, receiver_id=other_user_id) | Q(sender_id=other_user_id, receiver=user)
        ).order_by('timestamp')

    def perform_create(self, serializer):
        receiver = serializer.validated_data.get('receiver')
        if receiver is None:
            raise serializers.ValidationError({"receiver": "This field is required."})
        # Check estate match
        try:
            sender_estate = self.request.user.profile.estate
            receiver_estate = receiver.profile.estate
        except Exception:
            raise serializers.ValidationError({"receiver": "Invalid receiver or estate mismatch."})
        if sender_estate != receiver_estate:
            raise serializers.ValidationError({"receiver": "Receiver must belong to the same estate."})
        serializer.save(sender=self.request.user, receiver=receiver)

class PrivateMessageCreateView(generics.CreateAPIView):
    serializer_class = PrivateMessageSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        receiver = serializer.validated_data.get('receiver')
        if receiver is None:
            raise serializers.ValidationError({"receiver": "This field is required."})
        # Check estate match
        try:
            sender_estate = self.request.user.profile.estate
            receiver_estate = receiver.profile.estate
        except Exception:
            raise serializers.ValidationError({"receiver": "Invalid receiver or estate mismatch."})
        if sender_estate != receiver_estate:
            raise serializers.ValidationError({"receiver": "Receiver must belong to the same estate."})
        serializer.save(sender=self.request.user, receiver=receiver)

class SecurityPersonnelUsersListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        estate = self.request.query_params.get('estate')
        if not estate:
            user = self.request.user
            estate = getattr(user.profile, 'estate', None)
        if not estate:
            return User.objects.none()
        return User.objects.filter(
            profile__role='Security Personnel',  # Verify this role value
            profile__is_email_verified=True,
            profile__estate=estate
        )


class SecurityPersonnelUsersListAllView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(profile__role='Security Personnel', profile__is_email_verified=True)

class ResidenceUsersCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        count = User.objects.filter(profile__role='Residence', profile__is_email_verified=True).count()
        return Response({'count': count})

class SecurityPersonnelUsersCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        count = User.objects.filter(profile__role='Security Personnel', profile__is_email_verified=True).count()
        return Response({'count': count})
class AccessCodeByUserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Retrieve a list of access codes created by the authenticated user.
        Automatically deactivate expired access codes.
        """
        try:
            now = timezone.now().astimezone(WAT)
            # Filter access codes by the authenticated user and order by creation date
            access_codes = AccessCode.objects.filter(creator=request.user).order_by('-created_at')

            # Deactivate expired access codes
            expired_codes = access_codes.filter(valid_to__lt=now, is_active=True)
            expired_codes.update(is_active=False)

            # Refresh the queryset after update
            access_codes = AccessCode.objects.filter(creator=request.user).order_by('-created_at')

            # Prepare response with the authenticated user's details
            user = request.user
            result = {
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': f"{user.first_name} {user.last_name}".strip()
                },
                'access_codes': AccessCodeSerializer(access_codes, many=True).data
            }
            
            logger.info(f"Retrieved {len(result['access_codes'])} access codes for user {user.email}")
            return Response([result], status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error retrieving access codes for user {request.user.email}: {str(e)}")
            return Response({'error': 'Failed to retrieve access codes'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
          
class AccessCodeDeactivateView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, code):
        """
        Deactivate an access code by setting is_active to False.
        Only the creator can deactivate their own access code.
        """
        try:
            access_code = AccessCode.objects.get(code=code)
            if access_code.creator != request.user:
                logger.warning(f"User {request.user.email} attempted to deactivate code {code} not owned by them")
                return Response({"error": "You can only deactivate your own access codes"}, status=status.HTTP_403_FORBIDDEN)
            
            access_code.is_active = False
            access_code.save()
            logger.info(f"Access code {code} deactivated by {request.user.email}")
            return Response(AccessCodeSerializer(access_code).data, status=status.HTTP_200_OK)
        
        except AccessCode.DoesNotExist:
            logger.warning(f"Access code not found: {code}")
            return Response({"error": "Access code not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error deactivating access code {code}: {str(e)}")
            return Response({"error": "Failed to deactivate access code"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@method_decorator(csrf_exempt, name='dispatch')


class VerifyAndCreditView(APIView):
    def post(self, request):
        try:
            reference = request.data.get('reference')
            user_id = request.data.get('user_id')
            plan = request.data.get('plan')  
            if not reference:
                return Response(
                    {'error': 'Transaction reference is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not user_id:
                return Response(
                    {'error': 'User ID is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not plan:
                return Response(
                    {'error': 'Plan type is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            secret_key = 'sk_live_43fc893ff9d7a6dd07302e43aae78602c0dc62c8'
            headers = {'Authorization': f'Bearer {secret_key}'}
            paystack_url = f'https://api.paystack.co/transaction/verify/{reference}'
            response = requests.get(paystack_url, headers=headers)
            response_data = response.json()
            print(f'Paystack response: status={response.status_code}, body={response_data}')

            if response.status_code == 200 and response_data['status']:
                transaction_status = response_data['data'].get('status')
                if transaction_status == 'success':
                    amount = Decimal(response_data['data']['amount']) / Decimal('100')
                    from django.contrib.auth.models import User
                    from django.utils import timezone
                    try:
                        user = User.objects.get(id=user_id)
                    except User.DoesNotExist:
                        return Response(
                            {'error': f'User with id {user_id} not found'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    # Idempotency check: prevent double crediting
                    if not hasattr(user.profile, 'last_transaction_reference') or user.profile.last_transaction_reference != reference:
                        user.profile.wallet_balance += amount
                        user.profile.last_transaction_reference = reference
                        # Set subscription start and expiry dates based on plan
                        now = timezone.now()
                        user.profile.plan = plan
                        user.profile.subscription_start_date = now
                        if plan.lower() == 'monthly':
                            user.profile.subscription_expiry_date = now + timezone.timedelta(days=30)
                        elif plan.lower() == 'annual':
                            user.profile.subscription_expiry_date = now + timezone.timedelta(days=365)
                        else:
                            # For free or unknown plans, set expiry 30 days from now
                            user.profile.subscription_expiry_date = now + timezone.timedelta(days=30)
                        user.profile.save(update_fields=['wallet_balance', 'last_transaction_reference', 'plan', 'subscription_start_date', 'subscription_expiry_date'])
                        print(f'Updated wallet balance and subscription for user {user_id}: {user.profile.wallet_balance}, plan: {plan}')
                    else:
                        print(f'Transaction {reference} already processed for user {user_id}')

                    return Response(
                        {'message': 'Wallet credited and subscription updated successfully', 'balance': float(user.profile.wallet_balance)},
                        status=status.HTTP_200_OK
                    )
                elif transaction_status == 'abandoned':
                    # Log abandoned transaction for monitoring
                    logger.warning(f'Transaction abandoned: reference={reference}, user_id={user_id}')
                    return Response(
                        {'error': 'Transaction was abandoned and not completed. Please try again or contact support.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    return Response(
                        {'error': f'Transaction status {transaction_status} not supported'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {'error': 'Transaction verification failed. Please check your payment and try again.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            logger.error(f'Error in VerifyAndCreditView: {str(e)}')
            return Response(
                {'error': f'Something went wrong. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class PrivateMessageMarkSeenView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        other_user_id = request.data.get('user_id')
        if not other_user_id:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Mark all messages sent to the current user by other_user_id as seen
        messages = PrivateMessage.objects.filter(
            sender_id=other_user_id,
            receiver=user,
            seen=False
        )
        updated_count = messages.update(seen=True)
        return Response({'marked_seen_count': updated_count}, status=status.HTTP_200_OK)

class PrivateMessageDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        message = get_object_or_404(PrivateMessage, pk=pk)
        # Only allow sender or receiver to delete the message
        if message.sender != request.user and message.receiver != request.user:
            return Response({'error': 'You do not have permission to delete this message.'}, status=status.HTTP_403_FORBIDDEN)
        message.delete()
        return Response({'message': 'Message deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if not current_password or not new_password:
            return Response({'error': 'Current password and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(current_password):
            return Response({'error': 'Current password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        # Return JSON response explicitly
        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        # Return JSON response explicitly
        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
