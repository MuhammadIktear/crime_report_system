from django.contrib.auth.models import AbstractUser
from django.db import models

class UserAccount(AbstractUser):
    image = models.URLField(max_length=200, default="https://res.cloudinary.com/ds97wytcs/image/upload/v1725001777/m6idyx9e4rwnmxawgu8o.png")
    phone=models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True) 

