Signals
=======

Django-oauth-toolkit sends messages to various signals, depending on the action
that has been triggered.

Import signals from the canonical module ``oauth2_provider.core.signals`` and
attach your own listeners. (The old top-level ``oauth2_provider.signals`` import
path still works but is deprecated and will be removed in 4.0.)

For example:

.. code-block:: python

    from oauth2_provider.core.signals import app_authorized

    def handle_app_authorized(sender, request, token, **kwargs):
        print('App {} was authorized'.format(token.application.name))

    app_authorized.connect(handle_app_authorized)

Currently supported signals are:

* ``oauth2_provider.core.signals.app_authorized`` - fired once an oauth code has been
  authorized and an access token has been granted

* ``oauth2_provider.core.signals.refresh_token_revoked`` - fired once for every refresh
  token whose credentials are invalidated. The keyword argument ``refresh_token`` is the
  revoked model instance, re-read after the write so it carries the final state
  (``revoked`` set, ``access_token`` nulled). It is sent by both revocation paths, so a
  single receiver covers every way a credential can die:

  * ``RefreshToken.revoke()`` - the single-row path used by the RFC 7009 ``/revoke/``
    endpoint, RP-initiated logout, the authorized-token delete view and the admin action.
  * ``RefreshToken.revoke_family()`` - the constant-query, set-based sweep the reuse
    protection runs when a replayed or repudiated token is presented.

  The signal is dispatched through ``transaction.on_commit(..., robust=True)``. It
  therefore fires only **after the revocation transaction commits** - never when the
  transaction rolls back - and a receiver that raises is logged rather than propagated to
  the caller or undoing the already-persisted revocation. Connect a side effect that must
  agree with the security state here, for example marking a device session logged out:

.. code-block:: python

    from oauth2_provider.core.signals import refresh_token_revoked

    def mark_device_session_logged_out(sender, refresh_token, **kwargs):
        DeviceSession.objects.filter(refresh_token=refresh_token).update(
            logged_out_at=refresh_token.revoked
        )

    refresh_token_revoked.connect(mark_device_session_logged_out)

Why a dedicated signal
----------------------

The family sweep writes with ``QuerySet.update()`` and ``QuerySet.delete()`` to stay a
constant number of queries no matter how long a token family has been rotating. Those
set-based operations do **not** call a model's ``save()``/``delete()``/overridden
``revoke()`` and do not emit the ORM ``pre_save``/``post_save``/``post_delete`` signals.
A swapped refresh-token model that reacts to revocation cannot therefore rely on those
per-row hooks alone: they run for ``revoke()`` but are silently skipped by
``revoke_family()``. Subscribing to ``refresh_token_revoked`` keeps the two paths
consistent without giving up the batch query advantage - the sweep reads the rows it
invalidated in a single query and announces them after commit.

