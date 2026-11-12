from django.contrib.auth.models import AbstractUser
from django.db import models


class Account(AbstractUser):
    """A custom user model used by the account-erasure integration tests.

    It is a real ``AUTH_USER_MODEL`` swap: the erasure journal stores its
    primary key as text, and a related model the project owns
    (``AccountProfile``) must still be collected.
    """

    oidc_subject = models.CharField(max_length=64, blank=True, default="", db_index=True)


class AccountProfile(models.Model):
    """OAuth-neutral personal data owned by the project, not by the toolkit."""

    account = models.OneToOneField(Account, on_delete=models.CASCADE, related_name="profile")
    display_name = models.CharField(max_length=255, blank=True, default="")
