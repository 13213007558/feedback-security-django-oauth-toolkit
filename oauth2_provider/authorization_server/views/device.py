import json

from django import forms, http
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import DetailView, FormView, View
from oauthlib.common import Request as OAuthlibRequest
from oauthlib.common import urlencode
from oauthlib.oauth2 import DeviceApplicationServer

from oauth2_provider.authorization_server.views.mixins import AuthorizationServerViewMixin
from oauth2_provider.core.compat import login_not_required
from oauth2_provider.core.scopes import get_scopes_backend
from oauth2_provider.core.views import FormEncodedRequestMixin
from oauth2_provider.models import (
    AbstractDeviceGrant,
    DeviceCodeResponse,
    DeviceRequest,
    create_device_grant,
    get_application_model,
    get_device_grant_model,
)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class DeviceAuthorizationView(FormEncodedRequestMixin, AuthorizationServerViewMixin, View):
    server_class = DeviceApplicationServer
    form_encoded_endpoint = "The OAuth 2.0 device authorization endpoint (RFC 8628 section 3.1)"

    def post(self, request, *args, **kwargs):
        headers, response, status = self.create_device_authorization_response(request)

        if status != 200:
            return http.JsonResponse(data=json.loads(response), status=status, headers=headers)

        client_id = request.POST["client_id"]
        requested_scope = request.POST.get("scope", "").strip()
        if requested_scope:
            scope = requested_scope
        else:
            Application = get_application_model()
            try:
                application = Application.objects.get(client_id=client_id)
            except Application.DoesNotExist:
                return http.JsonResponse(
                    {"error": "invalid_client", "error_description": "No application found for client_id."},
                    status=401,
                    headers=headers,
                )
            core = self.get_oauthlib_core()
            uri = request.build_absolute_uri()
            http_method = request.method
            body = urlencode(core.extract_body(request))
            req_headers = core.extract_headers(request)
            oauthlib_request = OAuthlibRequest(uri, http_method=http_method, body=body, headers=req_headers)
            oauthlib_request.client_id = client_id
            oauthlib_request.client = application
            validator = core.server.request_validator
            scope = " ".join(validator.get_default_scopes(client_id, oauthlib_request))
        device_request = DeviceRequest(client_id=client_id, scope=scope)
        device_response = DeviceCodeResponse(**response)
        create_device_grant(device_request, device_response)

        return http.JsonResponse(data=response, status=status, headers=headers)


def _expire_pending_grant(model, pk: int) -> None:
    """
    Move a still-pending grant whose deadline has passed to EXPIRED.

    Conditional so it cannot rewrite a decision another request already
    recorded: a grant that was authorized or denied before the deadline
    keeps its terminal state.
    """
    model.objects.filter(
        pk=pk,
        status=model.AUTHORIZATION_PENDING,
        expires__lte=timezone.now(),
    ).update(status=model.EXPIRED)


class DeviceGrantForm(forms.Form):
    user_code = forms.CharField(required=True)

    def __init__(self, *args, request_user_id: int | None = None, **kwargs) -> None:
        self.request_user_id = request_user_id
        super().__init__(*args, **kwargs)

    def clean_user_code(self):
        """
        Performs validation on the user_code provided by the user and adds to the cleaned_data dict
        the "device_grant" object associated with the user_code, which is useful to process the
        response in the DeviceUserCodeView.

        It can raise one of the following ValidationErrors, with the associated codes:

        * incorrect_user_code: if a device grant associated with the user_code does not exist
        * expired_user_code: if the device grant associated with the user_code has expired
        * user_code_already_used: if the device grant associated with the user_code has been already
         approved or denied. The only accepted state of the device grant is AUTHORIZATION_PENDING.
        * user_code_already_claimed: if the device grant has already been claimed by a different
         signed-in user at the user-code step.
        """
        cleaned_data = super().clean()
        user_code: str = cleaned_data["user_code"]
        device_grant_model = get_device_grant_model()
        try:
            device_grant: AbstractDeviceGrant = device_grant_model.objects.get(user_code=user_code)
        except device_grant_model.DoesNotExist:
            raise ValidationError("Incorrect user code", code="incorrect_user_code")

        if device_grant.status == device_grant.EXPIRED:
            raise ValidationError("Expired user code", code="expired_user_code")

        # User of device has already made their decision for this device.
        # Checked before expiry: an authorized/denied grant stays terminal even
        # if its deadline has since passed, and must never be rewritten here.
        if device_grant.status != device_grant.AUTHORIZATION_PENDING:
            raise ValidationError("User code has already been used", code="user_code_already_used")

        if device_grant.expires <= timezone.now():
            _expire_pending_grant(device_grant_model, device_grant.pk)
            raise ValidationError("Expired user code", code="expired_user_code")

        # A grant is bound to the first account that entered its code. Letting a
        # different signed-in account re-enter the code would silently transfer the
        # device's authorization to that account (RFC 8628 §3.3).
        if device_grant.user_id is not None and device_grant.user_id != self.request_user_id:
            raise ValidationError("User code has already been claimed", code="user_code_already_claimed")

        # Make the device_grant available to the View, saving one additional db call.
        cleaned_data["device_grant"] = device_grant

        return user_code


class DeviceUserCodeView(LoginRequiredMixin, FormView):
    """
    The view where the user is instructed (by the device) to come to in order to
    enter the user code. More details in this section of the RFC:
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.3

    Note: it's common to see in other implementations of this RFC that only ask the
    user to sign in after they input the user code but since the user has to be signed
    in regardless, to approve the device login we're making the decision here, for
    simplicity, to require being logged in up front.
    """

    template_name = "oauth2_provider/device/user_code.html"
    form_class = DeviceGrantForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["request_user_id"] = self.request.user.pk
        return kwargs

    def get_success_url(self):
        return reverse(
            "oauth2_provider:device-confirm",
            kwargs={
                "client_id": self.device_grant.client_id,
                "user_code": self.device_grant.user_code,
            },
        )

    def get_initial(self):
        initial = super().get_initial()
        initial["user_code"] = self.request.GET.get("user_code", "")
        return initial

    def form_valid(self, form):
        """
        Sets the device_grant on the instance so that it can be accessed
        in get_success_url. It comes in handy when users want to overwrite
        get_success_url, redirecting to the URL with the URL params pointing
        to the current device.
        """
        device_grant: AbstractDeviceGrant = form.cleaned_data["device_grant"]

        # Claiming is a compare-and-set, not a read-then-write: another tab may
        # have claimed the grant for a different account, ended the decision, or
        # the user code may have expired since the form was validated. Only an
        # unclaimed, still-pending, still-unexpired grant is updated, so a stale
        # form can never take ownership away from the account that already has it.
        model = get_device_grant_model()
        updated = model.objects.filter(
            pk=device_grant.pk,
            user__isnull=True,
            status=model.AUTHORIZATION_PENDING,
            expires__gt=timezone.now(),
        ).update(user=self.request.user)
        if not updated:
            current = model.objects.filter(pk=device_grant.pk).values("user_id", "status", "expires").first()
            if current is not None and current["status"] == model.AUTHORIZATION_PENDING:
                if current["expires"] <= timezone.now():
                    _expire_pending_grant(model, device_grant.pk)
                elif current["user_id"] == self.request.user.pk:
                    # Resubmitting the code in the account that already claimed
                    # it is a no-op claim; only a claim for another account is
                    # refused.
                    self.device_grant = device_grant
                    return super().form_valid(form)
            if current is not None and current["user_id"] not in (None, self.request.user.pk):
                form.add_error(
                    None,
                    ValidationError("User code has already been claimed", code="user_code_already_claimed"),
                )
            else:
                form.add_error(
                    None,
                    ValidationError("User code has already been used", code="user_code_already_used"),
                )
            return self.form_invalid(form)

        device_grant.user = self.request.user
        self.device_grant = device_grant

        return super().form_valid(form)


class DeviceConfirmForm(forms.Form):
    """
    Simple form for the user to approve or deny the device.
    """

    action = forms.CharField(required=True)


class DeviceConfirmView(LoginRequiredMixin, FormView):
    """
    The view where the user approves or denies a device.
    """

    template_name = "oauth2_provider/device/accept_deny.html"
    form_class = DeviceConfirmForm

    def get_object(self):
        """
        Returns the DeviceGrant object in the AUTHORIZATION_PENDING state identified
        by the slugs client_id and user_code and owned by the signed-in user.
        Raises Http404 if the grant is missing, owned by someone else, already
        decided, or past its deadline.

        The result is cached on the instance to avoid redundant queries within the
        same request (e.g. get() validates and get_context_data() reads scopes).
        The POST decision re-reads with a conditional UPDATE; see form_valid().
        """
        if not hasattr(self, "_device_grant"):
            client_id, user_code = self.kwargs.get("client_id"), self.kwargs.get("user_code")
            model = get_device_grant_model()
            device_grant = get_object_or_404(
                model,
                client_id=client_id,
                user_code=user_code,
                user=self.request.user,
            )
            # A terminal decision stays terminal: never let the expiry check
            # rewrite an already authorized or denied grant. Only a pending
            # grant can time out.
            if device_grant.status != model.AUTHORIZATION_PENDING:
                raise Http404
            if device_grant.expires <= timezone.now():
                _expire_pending_grant(model, device_grant.pk)
                raise Http404
            self._device_grant = device_grant
        return self._device_grant

    def get_success_url(self):
        return reverse(
            "oauth2_provider:device-grant-status",
            kwargs={
                "client_id": self.kwargs["client_id"],
                "user_code": self.kwargs["user_code"],
            },
        )

    def get(self, request, *args, **kwargs):
        """
        Enable GET requests for improved user experience. But validate that the URL params
        are correct (i.e. there exists a device grant in the db that corresponds to the URL
        params) by calling .get_object()
        """
        _ = self.get_object()  # raises 404 if URL parameters are incorrect
        return super().get(request, args, kwargs)

    def form_valid(self, form):
        """
        Records the user's decision with a compare-and-set on the still-pending,
        still-unexpired grant owned by the signed-in user.

        Two tabs, or a tab left open past the deadline, can race this write.
        The conditional UPDATE makes the first decision win: a second one can
        neither flip an already authorized/denied grant nor revive an expired
        session, so a stale page cannot overwrite a decision that already
        ended the flow (RFC 8628 §3.3 and §3.5).
        """
        device = self.get_object()
        action = form.cleaned_data["action"]

        if action == "accept":
            target = device.AUTHORIZED
        elif action == "deny":
            target = device.DENIED
        else:
            return http.HttpResponseBadRequest()

        model = get_device_grant_model()
        updated = model.objects.filter(
            pk=device.pk,
            user=self.request.user,
            status=model.AUTHORIZATION_PENDING,
            expires__gt=timezone.now(),
        ).update(status=target)
        if not updated:
            # Keep the terminal state: if the deadline passed during the
            # interaction, record EXPIRED; an already-decided grant is untouched.
            _expire_pending_grant(model, device.pk)
            raise Http404

        device.status = target
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        client_id = self.kwargs.get("client_id")
        context["application"] = get_object_or_404(get_application_model(), client_id=client_id)

        device = self.get_object()
        all_scopes = get_scopes_backend().get_all_scopes()
        scopes = device.scope.split() if device.scope is not None else []
        context["scopes"] = scopes
        context["scopes_descriptions"] = [all_scopes.get(scope, scope) for scope in scopes]

        return context


class DeviceGrantStatusView(LoginRequiredMixin, DetailView):
    """
    The view to display the status of a DeviceGrant.
    """

    template_name = "oauth2_provider/device/device_grant_status.html"

    def get_queryset(self):
        return get_device_grant_model().objects.all()

    def get_object(self):
        client_id, user_code = self.kwargs.get("client_id"), self.kwargs.get("user_code")
        return get_object_or_404(
            self.get_queryset(),
            client_id=client_id,
            user_code=user_code,
            user=self.request.user,
        )
