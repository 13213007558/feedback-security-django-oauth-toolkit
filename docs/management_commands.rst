Management commands
===================

Django OAuth Toolkit exposes some useful management commands that can be run via shell or by other means such as cron
or :doc:`Celery <tutorial/tutorial_05>`.

.. _cleartokens:

cleartokens
~~~~~~~~~~~

The ``cleartokens`` management command allows the user to remove refresh tokens that can no longer be
used:

* those that have been idle longer than ``REFRESH_TOKEN_EXPIRE_SECONDS`` -- i.e. whose paired access
  token expired more than ``REFRESH_TOKEN_EXPIRE_SECONDS`` ago (see ``REFRESH_TOKEN_EXPIRE_SECONDS``
  for the idle-expiry semantics);
* orphaned refresh tokens -- non-revoked refresh tokens whose access token was deleted out of band,
  leaving nothing to refresh against. These are removed unconditionally, regardless of
  ``REFRESH_TOKEN_EXPIRE_SECONDS``; and
* revoked refresh tokens once their retention period has passed (see below).

It also deletes expired grants, expired stored authorization requests, and expired access and ID
tokens.

It is important that this command is run regularly (eg: via cron) to avoid cluttering the
database with expired refresh tokens.

If ``cleartokens`` runs daily the maximum delay before a refresh token is
removed is its retention period (``REFRESH_TOKEN_EXPIRE_SECONDS`` for expired
tokens, the retention period for revoked ones) + 1 day. This
is normally not a problem since refresh tokens are long lived.

Note that ``REFRESH_TOKEN_EXPIRE_SECONDS`` is also enforced when a refresh token is presented, so a
refresh token past its lifetime is rejected even if ``cleartokens`` has not yet removed it.

To prevent the CPU and RAM high peaks during deletion process use ``CLEAR_EXPIRED_TOKENS_BATCH_SIZE`` and
``CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL`` settings to adjust the process speed.

**Revocation evidence is not an ordinary expiry.** With
``REFRESH_TOKEN_REUSE_PROTECTION`` enabled, a revoked refresh token is what lets the server
recognize a replay of a rotated token and revoke its family (RFC 9700 §4.14.2). Deleting those rows
on the plain grace-period schedule would silently disable that judgment. ``cleartokens`` therefore
keeps them for the longest of:

* ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS`` (so a client retrying within the grace window still works);
* ``REFRESH_TOKEN_EXPIRE_SECONDS`` when ``REFRESH_TOKEN_REUSE_PROTECTION`` is on, which an explicit
  ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` may lengthen but never shorten; and
* ``REFRESH_TOKEN_EVIDENCE_RETENTION_SECONDS`` as a privacy retention cap when reuse protection is
  off (a row is then not evidence for any live decision), bounded below by the grace period.

When reuse protection is on, refresh tokens never age-expire, and no evidence retention is set,
revoked tokens are kept indefinitely -- the same as before this option existed.

.. _cleartokens-resume:

**Resumable runs.** ``cleartokens`` deletes in phases and in bounded batches, and checkpoints
progress in a ``TokenCleanupRun`` row after every batch. If a run is interrupted (deploy, timeout,
Ctrl-C), run it again with ``--resume`` to continue from the phase it was in; without ``--resume`` a
new run starts and the interrupted one is marked as such. Every phase is an idempotent deletion
guarded by the same cutoff, so restarting from any point reaches the same state. Deleting rows
earlier can only make *more* data eligible, never make a credential usable again: revoked tokens
that still back a security judgment stay, and everything deleted is past a cutoff that validation
already enforces.

The command reports only counts and the cleanup run id -- never token values, checksums, user
identifiers or client secrets. Use ``--format=json`` for cron/monitoring ingestion::

    {"run_id": 12, "status": "completed", "phase": "expired_revocation_evidence", ...,
     "counts": {"expired_grants": 0, "revoked_refresh_tokens": 4, ...}}

.. _cleartokens-account-deletion:

**Account deletion and minimal evidence.** Deleting a Django user cascades through
``RefreshToken.user``, which removes every refresh token the account owned -- including the revoked
rows reuse detection needs. Call ``oauth2_provider.models.purge_user_credentials(user)`` *before*
deleting the user. It deletes every access token, refresh token, ID token, grant and device grant,
and, when ``REFRESH_TOKEN_REUSE_PROTECTION`` is on, first copies for each revoked refresh token
still inside its retention period a single ``RevokedTokenEvidence`` row containing only:

* the token's SHA-256 checksum (recognizes a replay, does not yield a usable token);
* the token family id and the client id (both non-secret, needed for the family sweep);
* ``revoked_at`` and ``retain_until``.

No raw token, user reference, scope or application foreign key is kept. A replay of a purged token
is still rejected: ``validate_refresh_token`` finds the evidence and revokes the family exactly as
for a live row -- but the purged token itself is never honored. Live (non-revoked) tokens need no
evidence: once deleted, a replay is an unknown token and rejected as ``invalid_grant``. With reuse
protection off, no evidence is kept at all: a revoked row backs no live decision, so retaining it
would be personal data with no security purpose. ``cleartokens`` prunes evidence rows past
``retain_until`` (``NULL``, keep indefinitely, is never pruned).

Note: Refresh tokens need to expire before AccessTokens can be removed from the
database. Using ``cleartokens`` without ``REFRESH_TOKEN_EXPIRE_SECONDS`` has limited effect.
When ``REFRESH_TOKEN_EXPIRE_SECONDS`` is unset (or ``0``), ``cleartokens`` prints a warning to
stderr to make this easy to notice: only revoked and orphaned refresh tokens are removed, and
expired access and ID tokens that are still bound to a refresh token are retained as long as that
refresh token lives. (Expired access tokens with no refresh token, and their ID tokens, are still
cleared regardless of ``REFRESH_TOKEN_EXPIRE_SECONDS``.) Set ``REFRESH_TOKEN_EXPIRE_SECONDS`` to
enable expiry-based cleanup.

.. _clearcimdapplications:

clearcimdapplications
~~~~~~~~~~~~~~~~~~~~~

The ``clearcimdapplications`` management command deletes :doc:`CIMD-registered <cimd>` applications
(``registration_source="cimd"``) whose cached metadata has expired (``cimd_expires_at`` in the past)
and that hold no live access token, ID token, grant, or unrevoked refresh token. Because CIMD rows
are created automatically on first sight of a client URL — and re-created the same way if the client
returns — deleting them only reclaims storage. Run it regularly (eg: via cron, alongside
``cleartokens``) when CIMD is enabled, since the application store is otherwise attacker-mintable
(see :ref:`the CIMD security model <cimd-security>`).

Deletion is batched (``--batch-size``, default 1000). Each batch's liveness check and delete run in
one transaction with the application rows locked, so a token minted concurrently cannot slip in
between the check and the delete and be cascade-deleted with its application; batching keeps the
number of rows locked at once bounded.

.. _cleardcrapplications:

cleardcrapplications
~~~~~~~~~~~~~~~~~~~~

The ``cleardcrapplications`` management command deletes
:doc:`DCR-registered <views/dynamic_client_registration>` applications
(``registration_source="dcr"``) that hold no live access token, ID token, grant, or unrevoked
refresh token and were last registered or modified at least ``--min-unmodified-days`` days ago
(default 7). DCR clients such as editors and MCP tools sometimes re-register without deregistering
their previous client, so
tokenless "ghost" applications accumulate; because a client simply re-registers on its next request,
deleting a tokenless ghost only reclaims storage. Run it regularly (eg: via cron) when
:doc:`DCR <views/dynamic_client_registration>` is enabled, after ``cleartokens``: an unrevoked
refresh token counts as live even once it has expired under ``REFRESH_TOKEN_EXPIRE_SECONDS``, so
running ``cleartokens`` first lets this command prune applications whose only remaining token is
an expired refresh token.

The RFC 7592 registration access token issued to every DCR application at registration does not
count as a live token: it is created with a far-future expiry by default
(``DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS = None``) and grants nothing but management of the very
application being considered, so counting it would spare every ghost forever. A token that also
carries a further scope beyond ``DCR_REGISTRATION_SCOPE`` is treated as a normal token and does keep
its application.

The ``--min-unmodified-days`` grace period avoids racing a client that has just registered but has
not yet completed its first authorization, and so does not hold a token yet. It is anchored on
``updated`` rather than ``created``: a ghost is never touched after registration, so the two are
equal and the default behaviour is the same, but an application that is still being re-configured
through the :doc:`RFC 7592 <views/dynamic_client_registration>` management endpoint keeps renewing
its grace period. Pass ``--min-unmodified-days 0`` to delete every tokenless DCR application
regardless of age.

Deletion is batched (``--batch-size``, default 1000). Each batch's liveness check and delete run in
one transaction with the application rows locked, so a token minted concurrently cannot slip in
between the check and the delete and be cascade-deleted with its application; batching keeps the
number of rows locked at once bounded.

.. _createapplication:

createapplication
~~~~~~~~~~~~~~~~~

The ``createapplication`` management command provides a shortcut to create a new application in a programmatic way.

.. code-block:: text

    usage: manage.py createapplication [-h] [--client-id CLIENT_ID] [--user USER]
                                       [--redirect-uris REDIRECT_URIS]
                                       [--post-logout-redirect-uris POST_LOGOUT_REDIRECT_URIS]
                                       [--client-secret CLIENT_SECRET]
                                       [--name NAME] [--skip-authorization]
                                       [--can-introspect | --no-can-introspect]
                                       [--algorithm ALGORITHM] [--version]
                                       [-v {0,1,2,3}] [--settings SETTINGS]
                                       [--pythonpath PYTHONPATH] [--traceback]
                                       [--no-color] [--force-color]
                                       [--skip-checks]
                                       client_type authorization_grant_type

    Shortcut to create a new application in a programmatic way

    positional arguments:
      client_type           The client type, one of: confidential, public
      authorization_grant_type
                            The type of authorization grant to be used, one of:
                            authorization-code, implicit, password, client-
                            credentials, openid-hybrid

    optional arguments:
      -h, --help            show this help message and exit
      --client-id CLIENT_ID
                            The ID of the new application
      --user USER           The user the application belongs to
      --redirect-uris REDIRECT_URIS
                            The redirect URIs, this must be a space separated
                            string e.g 'URI1 URI2'
      --post-logout-redirect-uris POST_LOGOUT_REDIRECT_URIS
                            The post logout redirect URIs, this must be a space
                            separated string e.g 'URI1 URI2'
      --client-secret CLIENT_SECRET
                            The secret for this application
      --name NAME           The name this application
      --skip-authorization  If set, completely bypass the authorization form, even
                            on the first use of the application
      --can-introspect, --no-can-introspect
                            Allow or refuse calls to the token introspection
                            endpoint (RFC 7662) by this application; if neither
                            is given, the model default (allow) applies
      --algorithm ALGORITHM
                            The OIDC token signing algorithm for this application,
                            one of: RS256, HS256
      --version             Show program's version number and exit.
      -v {0,1,2,3}, --verbosity {0,1,2,3}
                            Verbosity level; 0=minimal output, 1=normal output,
                            2=verbose output, 3=very verbose output
      --settings SETTINGS   The Python path to a settings module, e.g.
                            "myproject.settings.main". If this isn't provided, the
                            DJANGO_SETTINGS_MODULE environment variable will be
                            used.
      --pythonpath PYTHONPATH
                            A directory to add to the Python path, e.g.
                            "/home/djangoprojects/myproject".
      --traceback           Raise on CommandError exceptions.
      --no-color            Don't colorize the command output.
      --force-color         Force colorization of the command output.
      --skip-checks         Skip system checks.

If you let ``createapplication`` auto-generate the secret then it displays the value before hashing it.

Use ``--no-can-introspect`` for a client that should not call the token introspection endpoint
(see :ref:`introspection-authorization`).
