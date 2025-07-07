from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.validators import MinValueValidator
from decimal import Decimal


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='profile')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    role = models.CharField(max_length=100, blank=True, null=True)
    estate = models.CharField(max_length=100, blank=True, null=True)
    estate_email = models.EmailField(blank=True, null=True)
    house_address = models.CharField(max_length=255, blank=True, null=True)
    pin = models.CharField(max_length=128, blank=True, null=True)  # Hashed PIN
    plan = models.CharField(max_length=50, blank=True, null=True)
    subscription_start_date = models.DateTimeField(blank=True, null=True)
    subscription_expiry_date = models.DateTimeField(blank=True, null=True)
    last_transaction_reference = models.CharField(max_length=255, blank=True, null=True)
    wallet_balance = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'), 
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    profile_picture = models.URLField(max_length=500, blank=True, null=True)
    email_verification_token = models.CharField(max_length=100, blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)
    password_reset_otp = models.CharField(max_length=6, blank=True, null=True)
    password_reset_otp_expiry = models.DateTimeField(blank=True, null=True)
    signup_otp = models.CharField(max_length=6, blank=True, null=True)
    signup_otp_expiry = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

class AccessCode(models.Model):
    code = models.CharField(max_length=10, unique=True)
    visitor_name = models.CharField(max_length=255)
    visitor_email = models.EmailField()
    visitor_phone = models.CharField(max_length=20)
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    max_uses = models.PositiveIntegerField(default=1)
    current_uses = models.PositiveIntegerField(default=0)
    gate = models.CharField(max_length=50)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_codes')
    is_active = models.BooleanField(default=True)
    notify_on_use = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"AccessCode {self.code} for {self.visitor_name}"

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
    # No need to call save() unless there are updates to the profile
    
class Alert(models.Model):
    ALERT_TYPES = [
        ('Visitor Arrival', 'Visitor Arrival'),
        ('Fire Alarm', 'Fire Alarm'),
        ('Security Breach', 'Security Breach'),
        ('others', 'others'),
    ]
    URGENCY_LEVELS = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    message = models.TextField()
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    recipients = models.JSONField()  # Store list of recipients (e.g., ["Security", "Management"])
    urgency_level = models.CharField(max_length=20, choices=URGENCY_LEVELS)
    timestamp = models.DateTimeField(auto_now_add=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.alert_type} - {self.message[:50]}"

class UserDeletedAlert(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='deleted_alerts')
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='deleted_by_users')
    deleted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'alert')

    def __str__(self):
        return f"Deleted Alert {self.alert.id} by User {self.user.username}"

class LostFoundItem(models.Model):
    ITEM_TYPES = [
        ('Lost', 'Lost'),
        ('Found', 'Found'),
    ]

    description = models.TextField()
    item_type = models.CharField(max_length=10, choices=ITEM_TYPES)
    location = models.CharField(max_length=255, blank=True, null=True)
    date_reported = models.DateTimeField(auto_now_add=True)
    contact_info = models.CharField(max_length=255, blank=True, null=True)
    image = models.ImageField(upload_to='lostfound_images/', blank=True, null=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.item_type} Item - {self.description[:50]}"

class PrivateMessage(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    seen = models.BooleanField(default=False)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"Message from {self.sender.username} to {self.receiver.username} at {self.timestamp}"


class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    date = models.DateTimeField(auto_now_add=True)
    reference = models.CharField(max_length=255)
    status = models.CharField(max_length=50)
    amount = models.DecimalField(max_digits=12, decimal_places=2)

    def __str__(self):
        return f"Transaction {self.reference} for {self.user.username} - {self.status} - {self.amount}"
