from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password

UserModel = get_user_model()

class EmailBackEnd(BaseBackend):
    def authenticate(self, username=None, password=None):
        try:
            users = UserModel.objects.filter(email=username)
            for user in users:
                if check_password(password, user.password):
                    return user
        except UserModel.DoesNotExist:
            return None
    
    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None