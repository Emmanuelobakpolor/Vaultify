import uuid
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Alert, PrivateMessage, UserProfile, AccessCode, LostFoundItem, Transaction
from django.contrib.auth.hashers import make_password
import logging

logger = logging.getLogger(__name__)

class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ['id', 'user', 'date', 'reference', 'status', 'amount']
        read_only_fields = ['id', 'user', 'date']

class SubscriptionUserSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    email = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    payment_amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    subscription_type = serializers.CharField()
    payment_date = serializers.DateTimeField(allow_null=True)
    
class AccessCodeSerializer(serializers.ModelSerializer):
    creator_name = serializers.CharField(source='creator.get_full_name', read_only=True)

    class Meta:
        model = AccessCode
        fields = [
            'code', 'visitor_name', 'visitor_email', 'visitor_phone',
            'valid_from', 'valid_to', 'max_uses', 'current_uses',
            'gate', 'creator', 'creator_name', 'is_active', 'notify_on_use',
            'created_at'
        ]

    def validate_code(self, value):
        if AccessCode.objects.filter(code=value).exists():
            raise serializers.ValidationError("An access code with this value already exists.")
        return value

    def validate(self, data):
        if data.get('valid_from') and data.get('valid_to'):
            if data['valid_from'] >= data['valid_to']:
                raise serializers.ValidationError({
                    'valid_to': "Valid to date must be after valid from date."
                })
        if 'visitor_email' not in data or not data['visitor_email']:
            raise serializers.ValidationError({
                'visitor_email': "This field is required."
            })
        return data

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['phone_number', 'role', 'estate', 'estate_email', 'house_address', 'pin', 'plan', 'wallet_balance', 'profile_picture', 'subscription_start_date', 'subscription_expiry_date']


    def validate_role(self, value):
        """
        Validate that the role is either 'Residence' or 'Security Personnel'.
        """
        valid_roles = ['Residence', 'Security Personnel']
        if value not in valid_roles:
            logger.error(f"Invalid role provided: {value}")
            raise serializers.ValidationError(
                f"Role must be one of: {', '.join(valid_roles)}"
            )
        return value

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer()
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'profile', 'password']
        extra_kwargs = {
            # Removed read_only for profile to allow nested updates
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Ensure wallet_balance is always included, defaulting to 0.00 if None
        profile_data = data.get('profile', {})
        wallet_balance = profile_data.get('wallet_balance')
        if wallet_balance is None or wallet_balance == '0.00':
            # Fetch actual wallet_balance from instance.profile.wallet_balance if available
            try:
                wallet_balance_value = instance.profile.wallet_balance
                profile_data['wallet_balance'] = str(wallet_balance_value) if wallet_balance_value is not None else '0.00'
            except Exception:
                profile_data['wallet_balance'] = '0.00'
            data['profile'] = profile_data
        else:
            profile_data['wallet_balance'] = wallet_balance
            data['profile'] = profile_data
        return data

    def validate(self, data):
        profile_data = data.get('profile', {})
        if self.instance is None:  # Creation
            if not profile_data.get('role'):
                logger.error("Role is missing in profile data")
                raise serializers.ValidationError({
                    'profile': "Role is required during signup."
                })
            email = data.get('email')
            if User.objects.filter(username=email).exists():
                logger.error(f"User with email {email} already exists")
                raise serializers.ValidationError({
                    'email': "A user with this email already exists."
                })
            if 'password' not in data or not data['password']:
                logger.error("Password is missing in signup data")
                raise serializers.ValidationError({
                    'password': "This field is required."
                })
        else:
            # For updates, if profile is present, validate role if provided
            if 'role' in profile_data and profile_data['role'] not in ['Residence', 'Security Personnel']:
                logger.error(f"Invalid role provided in update: {profile_data['role']}")
                raise serializers.ValidationError({
                    'profile': "Role must be one of: Residence, Security Personnel"
                })
        return data

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', {})
        password = validated_data.pop('password')  # This will now work as password is enforced
        logger.info(f"Creating user with profile data: {profile_data}")
        user = User(
            username=validated_data['email'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        user.set_password(password)
        user.save()
        profile, created = UserProfile.objects.get_or_create(user=user, defaults=profile_data)
        if not created:
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
            logger.info(f"Existing UserProfile updated with role: {profile_data.get('role')}")
        else:
            logger.info(f"UserProfile created with role: {profile_data.get('role')}")
        # Debug log to confirm phone_number saved
        logger.info(f"UserProfile phone_number after save: {profile.phone_number}")
        # Explicitly refresh profile from DB to ensure latest data
        profile.refresh_from_db()
        logger.info(f"UserProfile phone_number after refresh: {profile.phone_number}")
        return user

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})
        password = validated_data.pop('password', None)
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        if password:
            instance.set_password(password)
        instance.save()

        profile = instance.profile
        for attr, value in profile_data.items():
            setattr(profile, attr, value)
        profile.save()
        logger.info(f"User updated with role: {profile.role}, phone_number: {profile.phone_number}")
        return instance
from rest_framework import serializers

class AlertSerializer(serializers.ModelSerializer):
    sender_role = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = ['id', 'message', 'alert_type', 'recipients', 'urgency_level', 'timestamp', 'sender', 'sender_role']
        read_only_fields = ['timestamp', 'sender', 'sender_role']

    def get_sender_role(self, obj):
        try:
            return obj.sender.profile.role
        except Exception:
            return None

    def validate_alert_type(self, value):
        valid_types = [choice[0] for choice in Alert.ALERT_TYPES]
        if value not in valid_types:
            raise serializers.ValidationError("Invalid alert type")
        return value

    def validate_urgency_level(self, value):
        valid_levels = [choice[0] for choice in Alert.URGENCY_LEVELS]
        if value not in valid_levels:
            raise serializers.ValidationError("Invalid urgency level")
        return value

    def validate_recipients(self, value):
        if not isinstance(value, list) or not value:
            raise serializers.ValidationError("Recipients must be a non-empty list")
        return value

    def create(self, validated_data):
        # Remove 'estate' if present to avoid passing it to model create
        validated_data.pop('estate', None)
        return Alert.objects.create(**validated_data)

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Alert, UserProfile, AccessCode, LostFoundItem
from django.contrib.auth.hashers import make_password
import logging
import logging
logger = logging.getLogger(__name__)

from rest_framework import serializers
from .models import LostFoundItem

class LostFoundItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = LostFoundItem
        fields = ['id', 'description', 'item_type', 'location', 'date_reported', 'contact_info', 'sender', 'image']
        read_only_fields = ['date_reported', 'sender']
        extra_kwargs = {
            'image': {'required': False}  # Optional field
        }

    def validate_item_type(self, value):
        valid_types = [choice[0] for choice in LostFoundItem.ITEM_TYPES]
        if value not in valid_types:
            raise serializers.ValidationError("Invalid item type")
        return value

    def create(self, validated_data):
        request = self.context.get('request')
        image = request.FILES.get('image') if request and request.FILES else None
        # Remove 'estate' if present to avoid passing it to model create
        validated_data.pop('estate', None)
        instance = LostFoundItem.objects.create(**validated_data)
        if image:
            instance.image = image
            instance.save()
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        request = self.context.get('request')
        if instance.image and hasattr(instance.image, 'url'):
            representation['image'] = request.build_absolute_uri(instance.image.url) if request else instance.image.url
        return representation
class PrivateMessageSerializer(serializers.ModelSerializer):
    sender = serializers.StringRelatedField(read_only=True)
    receiver = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = PrivateMessage
        fields = ['id', 'sender', 'receiver', 'message', 'timestamp']
        read_only_fields = ['id', 'sender', 'timestamp']
