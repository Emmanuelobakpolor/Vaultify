from rest_framework.test import APITestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework import status
from vaultify.accounts.models import PrivateMessage

class PrivateMessageCreateTests(APITestCase):
    def setUp(self):
        self.user1 = User.objects.create_user(username='user1', password='pass123')
        self.user2 = User.objects.create_user(username='user2', password='pass123')
        self.url = reverse('private-message-send')  # Adjust the URL name as per your urls.py

    def test_create_private_message_success(self):
        self.client.force_authenticate(user=self.user1)
        data = {
            'receiver': self.user2.id,
            'message': 'Hello, this is a test message.'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PrivateMessage.objects.count(), 1)
        self.assertEqual(PrivateMessage.objects.first().message, 'Hello, this is a test message.')

    def test_create_private_message_missing_receiver(self):
        self.client.force_authenticate(user=self.user1)
        data = {
            'message': 'Hello, missing receiver.'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('receiver', response.data)

    def test_create_private_message_invalid_receiver(self):
        self.client.force_authenticate(user=self.user1)
        data = {
            'receiver': 9999,  # Non-existent user id
            'message': 'Hello, invalid receiver.'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_private_message_unauthenticated(self):
        data = {
            'receiver': self.user2.id,
            'message': 'Hello, unauthenticated user.'
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
