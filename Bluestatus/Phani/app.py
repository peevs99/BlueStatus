import os
import json
from datetime import datetime
from functools import wraps

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from flask import Flask, render_template, session, redirect, url_for, request
import msal

# Load environment variables
load_dotenv()

# Azure AD Configuration
AZURE_SETTINGS = {
    'client_id': os.getenv('AZURE_CLIENT_ID'),
    'client_secret': os.getenv('AZURE_CLIENT_SECRET'),
    'tenant_id': os.getenv('AZURE_TENANT_ID'),
    'admin_group_id': os.getenv('AZURE_ADMIN_GROUP_ID'),
    'authority': f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}",
    'scope': ['User.Read', 'GroupMember.Read.All'],
    'redirect_path': '/getAToken',
}

# Create Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

def create_requests_session():
    """Create a requests session with retry and timeout strategy."""
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET']
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s = requests.Session()
    s.mount("https://", adapter)
    return s

def _build_msal_app():
    """Build MSAL application instance."""
    return msal.ConfidentialClientApplication(
        AZURE_SETTINGS['client_id'],
        authority=AZURE_SETTINGS['authority'],
        client_credential=AZURE_SETTINGS['client_secret']
    )

def _get_token_from_cache(scope=None):
    """
    Use MSAL's acquire_token_silent() to retrieve (or refresh) an access token.
    Returns a list-like structure so admin_required can use token[0]["access_token"].
    """
    msal_app = _build_msal_app()
    if not session.get("user"):
        return None
    username = session["user"].get("preferred_username")
    accounts = msal_app.get_accounts(username=username)
    if not accounts:
        return None
    result = msal_app.acquire_token_silent(
        scopes=scope or AZURE_SETTINGS['scope'],
        account=accounts[0]
    )
    if result and "access_token" in result:
        return [{"access_token": result["access_token"]}]
    return None

def login_required(f):
    """Decorator to enforce login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            session["flow"] = _build_msal_app().initiate_auth_code_flow(
                AZURE_SETTINGS['scope'],
                redirect_uri=url_for('authorized', _external=True)
            )
            return redirect(session["flow"]["auth_uri"])
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to enforce admin access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))

        if not session.get('is_admin'):
            token = _get_token_from_cache(AZURE_SETTINGS['scope'])
            if not token:
                return redirect(url_for('login'))
            try:
                access_token = token[0]["access_token"]
                url_graph = f'https://graph.microsoft.com/v1.0/users/{session["user"]["preferred_username"]}/memberOf'
                graph_data = requests.get(
                    url_graph,
                    headers={'Authorization': f'Bearer {access_token}'},
                ).json()
                is_admin = any(
                    group['id'] == AZURE_SETTINGS['admin_group_id']
                    for group in graph_data.get('value', [])
                )
                if not is_admin:
                    return redirect(url_for('unauthorized'))
                session['is_admin'] = True
            except Exception:
                return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return decorated_function

def parse_last_check(last_check_value):
    """
    Attempt to parse 'last_check' whether it's a Unix timestamp or a date string.
    Returns a formatted date/time string or 'Unknown'.
    """
    if not last_check_value:
        return "Unknown"

    if str(last_check_value).isdigit():
        try:
            dt = datetime.fromtimestamp(int(last_check_value))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError):
            pass

    try:
        dt = datetime.strptime(last_check_value, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return last_check_value

def get_nagios_data():
    """Fetch and process Nagios XI API data."""
    api_key = os.getenv('NAGIOS_API_KEY')
    base_url = "https://nagiosxi.dcwater.com/nagiosxi/api/v1"

    try:
        host_url = f"{base_url}/objects/hoststatus?apikey={api_key}&pretty=1"
        response = requests.get(host_url, verify=True)
        response.raise_for_status()

        hosts_data = response.json()
        formatted_hosts = []
        status_map = {0: 'Online', 1: 'Warning', 2: 'Critical', 3: 'Unknown'}

        recordcount = hosts_data.get('recordcount', 0)
        if recordcount > 0:
            for host in hosts_data.get('hoststatus', []):
                host_name = host.get('host_name')
                host_current_state = int(host.get('current_state', 3))

                services_url = (
                    f"{base_url}/objects/servicestatus?apikey={api_key}&pretty=1"
                    f"&host_name={host_name}"
                )
                services_response = requests.get(services_url, verify=True)
                services_response.raise_for_status()
                services_data = services_response.json()

                formatted_services = []
                svc_recordcount = services_data.get('recordcount', 0)
                if svc_recordcount > 0:
                    for service in services_data.get('servicestatus', []):
                        service_description = service.get('service_description', 'Unknown Service')
                        current_state = int(service.get('current_state', 3))
                        service_status = status_map.get(current_state, 'Unknown')

                        formatted_services.append({
                            'service_name': service_description,
                            'status': service_status,
                            'status_output': service.get('plugin_output', 'No output available'),
                            'last_check': parse_last_check(service.get('last_check'))
                        })

                formatted_hosts.append({
                    'host_name': host_name or 'Unknown Host',
                    'display_name': host.get('alias', host_name or 'Unknown Host'),
                    'host_status': status_map.get(host_current_state, 'Unknown'),
                    'services': formatted_services
                })

        return formatted_hosts

    except requests.exceptions.RequestException:
        return []

@app.route('/')
def index():
    return redirect(url_for('user_view'))

@app.route('/login')
def login():
    session.clear()
    flow = _build_msal_app().initiate_auth_code_flow(
        AZURE_SETTINGS['scope'],
        redirect_uri=url_for('authorized', _external=True)
    )
    session["flow"] = flow
    return redirect(flow["auth_uri"])

@app.route('/getAToken')
def authorized():
    try:
        msal_app = _build_msal_app()
        result = msal_app.acquire_token_by_auth_code_flow(
            session.get('flow', {}),
            request.args
        )
        if "error" in result:
            return render_template("error.html", result=result)
        session["user"] = result.get("id_token_claims")
        return redirect(url_for("user_view"))
    except ValueError:
        return redirect(url_for("login"))

@app.route('/logout')
def logout():
    session.clear()
    logout_url = (
        f"{AZURE_SETTINGS['authority']}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={url_for('index', _external=True)}"
    )
    return redirect(logout_url)

@app.route('/user')
@login_required
def user_view():
    hosts = get_nagios_data()
    return render_template('user.html', hosts=hosts)

@app.route('/admin')
@login_required
@admin_required
def admin_view():
    hosts = get_nagios_data()
    return render_template('admin.html', hosts=hosts)

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

@app.route('/error')
def error():
    return render_template('error.html')

if __name__ == '__main__':
    app.run(debug=False, host='bluestatus.dcwater.com', port=80)
