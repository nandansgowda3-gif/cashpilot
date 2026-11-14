"""Setu Account Aggregator sandbox client."""
import json
import os
from datetime import date
from decimal import Decimal, InvalidOperation
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SANDBOX_BASE = "https://fiu-sandbox.setu.co"
TOKEN_URL = "https://orgservice-prod.setu.co/v1/users/login"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class SetuError(Exception):
    pass


class SetuAAClient:
    def __init__(self, client_id=None, client_secret=None, product_instance_id=None):
        self.client_id = (client_id if client_id is not None else os.environ.get("SETU_CLIENT_ID", "")).strip()
        self.client_secret = (client_secret if client_secret is not None
                              else os.environ.get("SETU_CLIENT_SECRET", "")).strip()
        self.product_instance_id = (product_instance_id if product_instance_id is not None
                                    else os.environ.get("SETU_PRODUCT_INSTANCE_ID", "")).strip()

    @property
    def configured(self):
        return bool(self.client_id and self.client_secret and self.product_instance_id)

    def _json_response(self, request):
        try:
            with urlopen(request, timeout=12) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise SetuError("Setu sandbox returned HTTP %d." % exc.code) from None
        except (URLError, TimeoutError, OSError):
            raise SetuError("Could not reach Setu sandbox. Try again later.") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SetuError("Setu sandbox response exceeded the size limit.")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise SetuError("Setu sandbox returned an invalid response.") from None
        if not isinstance(result, dict):
            raise SetuError("Setu sandbox returned an invalid response.")
        return result

    def _access_token(self):
        if not self.configured:
            raise SetuError("Setu sandbox credentials are not configured on the server.")
        payload = json.dumps({
            "clientID": self.client_id,
            "grant_type": "client_credentials",
            "secret": self.client_secret,
        }).encode("utf-8")
        request = Request(
            TOKEN_URL,
            data=payload,
            headers={"Content-Type": "application/json", "client": "bridge"},
            method="POST",
        )
        response = self._json_response(request)
        token = response.get("access_token")
        if not isinstance(token, str) or not token:
            raise SetuError("Setu sandbox did not return an access token.")
        return token

    def _request(self, method, path, body=None):
        if not path.startswith("/v2/"):
            raise SetuError("Invalid Setu sandbox API path.")
        payload = None if body is None else json.dumps(body).encode("utf-8")
        headers = {
            "Authorization": "Bearer " + self._access_token(),
            "Content-Type": "application/json",
            "x-product-instance-id": self.product_instance_id,
        }
        request = Request(SANDBOX_BASE + path, data=payload, headers=headers, method=method)
        return self._json_response(request)

    def create_consent(self, vua, data_range):
        return self._request("POST", "/v2/consents", {
            "vua": vua,
            "consentDuration": {"unit": "MONTH", "value": "1"},
            "dataRange": data_range,
            "context": [],
        })

    def get_consent(self, consent_id):
        return self._request("GET", "/v2/consents/" + consent_id)

    def create_data_session(self, consent_id, data_range):
        return self._request("POST", "/v2/sessions", {
            "consentId": consent_id,
            "dataRange": data_range,
            "format": "json",
        })

    def get_data_session(self, session_id):
        return self._request("GET", "/v2/sessions/" + session_id)

    def revoke_consent(self, consent_id):
        return self._request("POST", "/v2/consents/" + consent_id + "/revoke")


def extract_transactions(payload):
    """Return only transaction fields needed by CashPilot, excluding profile PII."""
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise SetuError("Setu sandbox returned an invalid data session.")
    fips = data.get("fips")
    if not isinstance(fips, list):
        raise SetuError("Setu sandbox response did not contain account data.")

    transactions = []
    for fip in fips:
        if not isinstance(fip, dict):
            raise SetuError("Setu sandbox returned an invalid account record.")
        accounts = fip.get("accounts")
        if not isinstance(accounts, list):
            raise SetuError("Setu sandbox response did not contain account data.")
        for account in accounts:
            if not isinstance(account, dict):
                raise SetuError("Setu sandbox returned an invalid account record.")
            account_data = account.get("data") or account.get("decryptedFI") or {}
            if not isinstance(account_data, dict):
                raise SetuError("Setu sandbox returned an invalid account record.")
            if isinstance(account_data.get("decryptedFI"), dict):
                account_data = account_data["decryptedFI"]
            account_root = account_data.get("account", account_data)
            if not isinstance(account_root, dict):
                raise SetuError("Setu sandbox returned an invalid account record.")
            tx_data = account_root.get("transactions") or {}
            if not isinstance(tx_data, dict):
                raise SetuError("Setu sandbox returned invalid transactions.")
            rows = tx_data.get("transaction", [])
            if not isinstance(rows, list):
                raise SetuError("Setu sandbox returned invalid transactions.")
            masked = account.get("maskedAccNumber", "")
            if not isinstance(masked, str):
                masked = ""
            for row in rows:
                if not isinstance(row, dict):
                    raise SetuError("Setu sandbox returned an invalid transaction.")
                try:
                    amount = abs(Decimal(str(row["amount"])))
                    if not amount.is_finite():
                        raise InvalidOperation
                except (KeyError, InvalidOperation, ValueError):
                    raise SetuError("Setu sandbox returned an invalid transaction amount.") from None
                kind = str(row.get("type", "")).upper()
                if kind not in ("CREDIT", "DEBIT"):
                    raise SetuError("Setu sandbox returned an unknown transaction type.")
                date_value = row.get("transactionTimestamp") or row.get("valueDate")
                if not isinstance(date_value, str):
                    raise SetuError("Setu sandbox returned a transaction without a date.")
                try:
                    transaction_date = date.fromisoformat(date_value[:10]).isoformat()
                except ValueError:
                    raise SetuError("Setu sandbox returned an invalid transaction date.") from None
                description = row.get("narration", "")
                if not isinstance(description, str):
                    description = ""
                transaction_id = row.get("txnId") or row.get("reference") or ""
                if not isinstance(transaction_id, str):
                    transaction_id = str(transaction_id)
                signed_amount = amount if kind == "CREDIT" else -amount
                transactions.append({
                    "id": transaction_id[:100],
                    "date": transaction_date,
                    "description": description[:240],
                    "amount": format(signed_amount, "f"),
                    "maskedAccount": masked[:32],
                })
                if len(transactions) > 5000:
                    raise SetuError("Setu sandbox returned too many transactions.")

    return sorted(transactions, key=lambda item: (item["date"], item["id"]))
