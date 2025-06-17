from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from .models import PrivateMessage
from django.db.models import Q

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
