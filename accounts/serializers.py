import uuid
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Alert, UserProfile, AccessCode, LostFoundItem
from django.contrib.auth.hashers import make_password
import logging

logger = logging.getLogger(__name__)



class AccessCodeSerializer(serializers.ModelSerializer):
    creator_name = serializers.CharField(source='creator.first_name', read_only=True)

    class Meta:
        model = AccessCode
        fields = [
            'id', 'code', 'visitor_name', 'visitor_email', 'visitor_phone',
            'valid_from', 'valid_to', 'max_uses', 'current_uses', 'gate',
            'is_active', 'notify_on_use', 'created_at', 'creator_name'
        ]
        read_only_fields = ['id', 'current_uses', 'created_at', 'creator']

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
        return data

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['phone_number', 'role', 'estate', 'estate_email', 'pin', 'plan', 'wallet_balance']

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
    wallet_balance = serializers.DecimalField(max_digits=10, decimal_places=2, source='profile.wallet_balance', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'profile', 'wallet_balance',
]
        extra_kwargs = {
            # Removed read_only for profile to allow nested updates
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Ensure wallet_balance is always included, defaulting to 0.00 if None
        wallet_balance = data.get('wallet_balance')
        if wallet_balance is None or wallet_balance == '0.00':
            # Fetch actual wallet_balance from instance.profile.wallet_balance if available
            try:
                wallet_balance_value = instance.profile.wallet_balance
                data['wallet_balance'] = str(wallet_balance_value) if wallet_balance_value is not None else '0.00'
            except Exception:
                data['wallet_balance'] = '0.00'
        else:
            data['wallet_balance'] = wallet_balance
        return data

    def validate(self, data):
        profile_data = data.get('profile', {})
        if self.instance is None:
            # Creation requires role in profile
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
        password = validated_data.pop('password')
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
        logger.info(f"User updated with role: {profile.role}")
        return instance

class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ['id', 'message', 'alert_type', 'recipients', 'urgency_level', 'timestamp', 'sender']
        read_only_fields = ['timestamp', 'sender']

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

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Alert, UserProfile, AccessCode, LostFoundItem
from django.contrib.auth.hashers import make_password
import logging

logger = logging.getLogger(__name__)

class LostFoundItemSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()

    class Meta:
        model = LostFoundItem
        fields = ['id', 'description', 'item_type', 'location', 'date_reported', 'contact_info', 'sender', 'image']
        read_only_fields = ['date_reported', 'sender']

    def get_image(self, obj):
        request = self.context.get('request')
        if obj.image and hasattr(obj.image, 'url'):
            return request.build_absolute_uri(obj.image.url) if request else obj.image.url
        return None

    def validate_item_type(self, value):
        valid_types = [choice[0] for choice in LostFoundItem.ITEM_TYPES]
        if value not in valid_types:
            raise serializers.ValidationError("Invalid item type")
        return value
