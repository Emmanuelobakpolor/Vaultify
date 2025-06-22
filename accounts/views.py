from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

class UploadProfileImageView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, format=None):
        file_obj = request.FILES.get('image')
        if not file_obj:
            return Response({'error': 'No image file provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Save the file to default storage (e.g., media folder)
        file_path = default_storage.save(f'profile_images/{file_obj.name}', ContentFile(file_obj.read()))
        image_url = default_storage.url(file_path)

        return Response({'image_url': image_url}, status=status.HTTP_200_OK)
