from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid
# Create your models here.

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    def __str__(self):
        return self.username