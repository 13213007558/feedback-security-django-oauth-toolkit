.. _account-deletion:

Account Erasure
===============

Deleting an end-user account is two requirements in tension: the personal data
must go, and every credential that is still live must stop working *before* the
account row -- and with it the credential's foreign key -- disappears.

A plain ``user.delete()`` does not meet the second requirement on its own:

* ``AccessToken.user`` and ``IDToken.user`` are nullable.  A collector that is
  not allowed to cascade (a database router, a swapped model with a different
  ``on_delete``, or a restricted collector) can leave the row behind and clear
  ``user``.  ``AccessToken.user = NULL`` is exactly the shape of a
  client-credentials token: introspection omits ``username`` and bearer
  validation hands ``request.user = None`` to the resource server.  A stranded
  user token would silently become a client token.
* ``RefreshToken.user`` is ``CASCADE`` but ``RefreshToken.access_token`` is
  ``SET_NULL``.  If the access token goes first, the refresh token survives as a
  live orphan that can mint a new access token; if it goes through the collector,
  the refresh tombstone is the one credential row the collector never removes.

The integration therefore revokes by **credential identity**, not by the
presence of a user.  It covers all four credential families:

======================  =========================================================
Credential              What the erasure does
======================  =========================================================
Authorization code      Row deleted; its digest is in the revocation ledger, so a
(``Grant``)             stranded code cannot be exchanged.
Device authorization    Row deleted; the ledger refuses RFC 8628 polling for the
grant (``DeviceGrant``) ``device_code`` even if the row survived.
Access token            Row deleted; the ledger refuses introspection and bearer
                        validation by ``token_checksum``.
Refresh token           Row deleted (not left as a reuse tombstone, so its
                        unique ``token_checksum`` does not accumulate forever);
                        the whole ``token_family`` is recorded on the ledger so
                        a stranded rotated sibling cannot be exchanged either.
ID token                Row deleted; the ledger refuses an ID token by ``jti``.
======================  =========================================================

Recommended integration
-----------------------

.. code-block:: python

    from oauth2_provider.authorization_server.account_deletion import delete_account

    delete_account(user)                          # revoke, then delete the account
    delete_account(user, delete_account_row=False)  # revoke now, erase later

``delete_account()`` runs four committed checkpoints, recorded on an
``AccountDeletion`` row:

#. **requested** -- a job row exists.
#. **snapshotted** -- one ``CredentialRevocation`` row per credential, recording
   its SHA-256 digest (for access and refresh tokens the same ``token_checksum``
   the token table keeps), the row's primary key, and the client identifier.
   No credential value and no personal data is written.
#. **credentials-revoked** -- every recorded credential row is deleted, plus a
   sweep for credentials minted since the snapshot (for example a concurrent
   refresh).  Rows are addressed by their recorded primary keys, never by the
   user FK, which is what makes a later resume work after the account is gone.
#. **account-erased** then **completed** -- the user row is deleted and the
   evidence purge deadline is stamped.

Each checkpoint commits separately.  A crash between any two leaves a row that
:func:`~oauth2_provider.authorization_server.account_deletion.resume_account_deletion`
continues from, including after the account row is already gone.  Both calls
are idempotent.

If your own policy requires a retention period between "credentials off" and
"account gone", use ``delete_account_row=False``.  The OAuth credentials are
revoked and deleted immediately; the account stays.  Later:

.. code-block:: python

    from oauth2_provider.models import AccountDeletion
    from oauth2_provider.authorization_server.account_deletion import resume_account_deletion

    resume_account_deletion(
        AccountDeletion.objects.get(pk=job_pk), delete_account_row=True
    )

A resumed job looks the account up from the stored primary key; after the
account is gone it only finishes the credential cleanup and the evidence
deadline.

A plain ``user.delete()``
-------------------------

``ACCOUNT_DELETION_GUARD_USER_DELETE`` (on by default) connects
``pre_delete``/``post_delete`` receivers to ``AUTH_USER_MODEL``.  A bare
``user.delete()`` anywhere in the project then:

* snapshots the account's credentials into the ledger *before* Django's
  collector runs (so a nullable FK the collector clears is still refused), and
* removes the credential rows the collector stranded, addressed through the
  ledger's recorded primary keys, and completes the job.

The receivers never block the account deletion: they log and leave the journal
row for an operator to resume.  An account with no OAuth credentials creates no
journal row.

What is really deleted, and what is retained
--------------------------------------------

**Deleted immediately:** the user row (unless ``delete_account_row=False``),
every ``Grant``, ``DeviceGrant``, ``AccessToken``, ``RefreshToken`` and
``IDToken`` row owned by the account, and -- through Django's collector --
whatever the project itself cascades from the user (sessions, a profile model,
...).  OAuth credentials not modelled here are not touched; if you keep
application-specific personal data, remove it in the same transaction or with a
``post_delete`` receiver of your own.

**Retained for a bounded period:** ``AccountDeletion`` (the user's primary key
as text, the model label, checkpoint timestamps and per-kind counts) and one
``CredentialRevocation`` row per credential (SHA-256 digest, client ID, the
row's former primary key, refresh ``token_family``, and the purge deadline).
None of it can be used to authenticate.  ``cleartokens`` deletes entries whose
``ACCOUNT_DELETION_REVOCATION_RETENTION_SECONDS`` (default seven days) has
passed; after that the credentials themselves are long gone and still fail
their own lookup.

**Never recorded:** credential values, usernames, e-mail addresses or any other
personal attribute -- including in the job's ``summary``, which counts rows per
credential kind only.

Behaviour changes
-----------------

* Introspection returns ``{"active": false}`` for an access token whose
  revocation is evidenced, and for an ownerless token issued to a client that is
  not registered for ``client_credentials`` (such a client never legitimately
  holds one).  A genuine client-credentials token still returns ``active: true``
  without a ``username`` member.
* Bearer validation refuses those same tokens instead of passing
  ``request.user = None`` to the resource server.  A stranded refresh token or
  authorization code is refused by digest (and, for a refresh token, by
  ``token_family``), and a device authorization grant is refused at RFC 8628
  polling by the ledger entry for its ``device_code``.
* Refresh-token validation refuses a token whose own digest *or* whose
  ``token_family`` is evidenced, and a row with no user.
