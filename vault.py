#!/usr/bin/env python
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import hvac  # type: ignore
import urllib.parse

OIDC_CALLBACK_PORT = 8250
OIDC_REDIRECT_URI = f'http://localhost:{OIDC_CALLBACK_PORT}/oidc/callback'
ROLE = None

SELF_CLOSING_PAGE = '''
<!doctype html>
<html>
<head>
<script>
window.onload = function load() {
  window.open('', '_self', '');
  window.close();
};
</script>
</head>
<body>
  <p>Authentication successful, you can close the browser now.</p>
  <script>
    setTimeout(function() {
          window.close()
    }, 5000);
  </script>
</body>
</html>
'''

def get_vault_client():
    return hvac.Client(
        url="https://vault.thermofisher.com",
        verify=True
    )

def vault_auth():
    client = get_vault_client()

    if client.is_authenticated():
        return client

    auth_url_response = client.auth.oidc.oidc_authorization_url_request(
        role=ROLE,
        redirect_uri=OIDC_REDIRECT_URI,
    )

    auth_url = auth_url_response['data']['auth_url']
    if not auth_url:
        return None

    params = urllib.parse.parse_qs(auth_url.split('?')[1])
    auth_url_nonce = params['nonce'][0]
    auth_url_state = params['state'][0]

    webbrowser.open(auth_url)
    token = login_oidc_get_token()

    auth_result = client.auth.oidc.oidc_callback(
        code=token,
        path='oidc',
        nonce=auth_url_nonce,
        state=auth_url_state,
    )

    new_token = auth_result['auth']['client_token']
    client.token = new_token
    return client


def login_oidc_get_token():
    class HttpServ(HTTPServer):
        def __init__(self, *args, **kwargs):
            HTTPServer.__init__(self, *args, **kwargs)
            self.token = None

    class AuthHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            params = urllib.parse.parse_qs(self.path.split('?')[1])
            self.server.token = params['code'][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(str.encode(SELF_CLOSING_PAGE))

    server_address = ('', OIDC_CALLBACK_PORT)
    httpd = HttpServ(server_address, AuthHandler)
    httpd.handle_request()
    return httpd.token


class VaultKeychain:
    def __init__(self):
        self.__client_token = vault_auth()

    account_keys = {}

    def get_all_group_roles(self, group: str) -> list[str]:
        try:
            return [
                role
                for role in self.__client_token.secrets.aws.list_roles()["data"]["keys"]
                if role.startswith(f"{group}-")
            ]
        except Exception as e:
            print(f"Failed to get roles for group {group}. Exception {e}")
            return []

    def get_all_roles(self) -> list[str]:
        try:
            return self.__client_token.secrets.aws.list_roles()["data"]["keys"]
        except Exception as e:
            print(f"Failed to list roles. Exception: {e}")
            return []

    def get_account_creds(self, role: str):
        try:
            vault_response = self.__client_token.read(f'aws/creds/{role}')
            vault_data = vault_response['data']
            vault_data['lease_id'] = vault_response['lease_id']
            self.account_keys[role] = vault_data
        except Exception as e:
            print(f'Failure to generate credentials for {role}. Exception: {e}')

    def get_multi_account_creds(self, roles: list[str]):
        for role in roles:
            self.get_account_creds(role)

    def revoke_lease(self, account: str):
        try:
            lease_id = self.account_keys[account]['lease_id']
            self.__client_token.sys.revoke_lease(lease_id)
        except Exception as e:
            print(f"Failed to revoke for {account}. Exception {e}")
        finally:
            # Always remove from account_keys whether revoke succeeded or not.
            # Without this, failed revokes leave stale entries that get
            # re-processed in the next batch causing duplicate runs.
            self.account_keys.pop(account, None)

    def revoke_all_leases(self):
        accounts = list(self.account_keys.keys())
        for account in accounts:
            self.revoke_lease(account)