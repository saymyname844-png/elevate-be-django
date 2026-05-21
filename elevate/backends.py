from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class UserLoginBackend(BaseBackend):
    """
    Custom authentication backend that authenticates users using the
    `user_login` field instead of Django's default `username` field.
    """

    def authenticate(self, request, user_login=None, password=None, **kwargs):
        if user_login is None or password is None:
            return None

        try:
            user = User.objects.get(user_login=user_login)
        except User.DoesNotExist:
            # Run the default password hasher to mitigate timing attacks.
            User().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user

        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models may not have
        that attribute, so fall back to True.
        """
        return getattr(user, "is_active", True)
