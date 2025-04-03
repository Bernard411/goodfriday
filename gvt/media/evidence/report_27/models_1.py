from django.db import models
from PIL import Image
import face_recognition
import os
from django.conf import settings
from django.db import models
import face_recognition
from django.core.files.base import ContentFile

class Person(models.Model):
    WANTED_STATUS_CHOICES = [
        ('yes', 'Wanted'),
        ('no', 'Not Wanted'),
    ]
    
    name = models.CharField(max_length=100)
    date_of_birth = models.DateField()
    address = models.CharField(max_length=255)
    photo = models.ImageField(upload_to='photos/')
    wanted_status = models.CharField(
        max_length=3,
        choices=WANTED_STATUS_CHOICES,
        default='no',
        help_text='Specify if the person is wanted by the authorities.'
    )
    description = models.TextField(blank=True, null=True)
    last_seen_location = models.CharField(max_length=255, blank=True, null=True)
    known_associates = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

    def get_face_encoding(self):
        if self.photo:
            image = face_recognition.load_image_file(self.photo)
            encodings = face_recognition.face_encodings(image)
            if encodings:
                return encodings[0]
        return None


from django.db import models

class CapturedPhoto(models.Model):
    name = models.CharField(max_length=100)
    photo = models.ImageField(upload_to='captured_photos/')
    date_captured = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
