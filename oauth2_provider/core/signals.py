from django.dispatch import Signal


app_authorized = Signal()  # providing_args=["request", "token"]

# Sent once for every refresh token whose credentials are invalidated, by both the
# single-row ``RefreshToken.revoke()`` path (RFC 7009 /revoke/, RP-initiated logout, the
# admin action) and the set-based ``RefreshToken.revoke_family()`` reuse-protection sweep.
# ``QuerySet.update()``/``.delete()`` do not call model ``save()``/``delete()`` or fire the
# ORM ``pre_save``/``post_save``/``post_delete`` signals, so a swapped model that needs to
# react to revocation -- e.g. marking a device session logged out -- cannot rely on those
# hooks alone. Connect here instead and the two paths stay consistent.
#
# The signal is dispatched through ``transaction.on_commit(..., robust=True)``: it fires
# only after the revocation transaction has committed, never on a rollback, and a receiver
# that raises is logged rather than tearing down the already-persisted security state.
#
# providing_args=["refresh_token"]: the revoked refresh-token model instance, re-read after
# the update so it carries the final ``revoked`` timestamp and a nulled ``access_token``.
refresh_token_revoked = Signal()
