from django.apps import AppConfig


class DOTConfig(AppConfig):
    name = "oauth2_provider"
    verbose_name = "Django OAuth Toolkit"

    def ready(self):
        # Connect the receiver that records when each session was authenticated
        # (``sessions``), and the account-erasure guard's receivers, which make a
        # direct ``user.delete()`` revoke credentials unless the deployment opted
        # out (see ACCOUNT_DELETION_GUARD_USER_DELETE).
        from .authorization_server import sessions, user_deletion_hooks  # noqa: F401
        from .settings import oauth2_settings

        if oauth2_settings.ACCOUNT_DELETION_GUARD_USER_DELETE:
            user_deletion_hooks.connect()

        # Import checks to ensure they run.
        from .core import checks  # noqa: F401
