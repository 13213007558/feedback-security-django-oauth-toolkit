"""Resource-identifier matching policy versions.

The toolkit historically matched a token's RFC 8707 resource indicators against
the request URI as a URL prefix: an audience such as
``https://api.example.com/v1`` authorized every path below ``/v1``. A policy
switch to **exact resource identifiers** changes that rule for tokens issued
from then on, but it must not reinterpret tokens already issued.

Every authorization grant, access token and refresh token therefore records the
policy it was issued under in ``resource_policy``. The field is blank on rows
that predate the field; those are legacy (version 1, prefix matching). Keeping
the policy on the row, instead of looking only at the current setting, is what
lets a resource server tell which rule applies to a token it validates, and
lets a refresh stay on the policy the user actually consented to.

The constants live in ``core`` because both the authorization-server issuance
path and the resource-server validation path use them, and importing them from
``resource_server.validators`` would pull the app registry into ``models`` at
import time.
"""

#: Rows written before the policy field existed. They mean prefix matching and
#: are deliberately not rewritten by an upgrade.
RESOURCE_POLICY_LEGACY = ""

#: Version 1: the audience URI is a base URI; every path below it matches.
RESOURCE_POLICY_PREFIX = "prefix"

#: Version 2: the request URI must be the same resource identifier as an
#: audience. Syntax-only differences are normalized away; path differences are
#: permission differences and do not match.
RESOURCE_POLICY_EXACT = "exact"

#: Policies that can be selected for newly issued authorizations and tokens.
SELECTABLE_RESOURCE_POLICIES = (RESOURCE_POLICY_PREFIX, RESOURCE_POLICY_EXACT)


def selected_resource_policy(policy: str) -> str:
    """Return the effective policy for a stored value.

    A blank value is a row from before the field existed, so it takes the
    version 1 prefix rule rather than whatever policy is configured now. This
    is the boundary that prevents an upgrade from retroactively narrowing
    already-issued tokens.
    """
    return policy or RESOURCE_POLICY_PREFIX
