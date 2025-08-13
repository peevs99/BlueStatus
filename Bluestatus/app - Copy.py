import os
import datetime
from collections import defaultdict
from functools import wraps

import requests
import urllib3
from dotenv import load_dotenv
from flask import Flask, render_template, session, redirect, url_for, request
import msal

# Load environment variables from .env
load_dotenv()

# Nagios API key (from your original snippet)
API_KEY = os.environ.get('NAGIOS_API_KEY')
if not API_KEY:
    raise ValueError("NAGIOS_API_KEY environment variable is not set")

# Azure AD / MSAL settings (make sure your app registration is configured to include group claims)
AZURE_SETTINGS = {
    'client_id': os.environ.get('AZURE_CLIENT_ID'),
    'client_secret': os.environ.get('AZURE_CLIENT_SECRET'),
    'tenant_id': os.environ.get('AZURE_TENANT_ID'),
    'admin_group_id': os.environ.get('AZURE_ADMIN_GROUP_ID'),  # This should be the Object ID of the admin group
    'authority': f"https://login.microsoftonline.com/{os.environ.get('AZURE_TENANT_ID')}",
    'scope': ['User.Read'],  # We don't need to request Graph scopes if group claims are included in the token
    'redirect_path': '/getAToken',
}

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key')

# Disable SSL warnings for dev/test (remove in production if possible)
urllib3.disable_warnings()

# Nagios XI service status API endpoint
API_URL = 'https://bpl-nagiosxi.dcwasa.com/nagiosxi/api/v1/objects/servicestatus'

def _build_msal_app():
    return msal.ConfidentialClientApplication(
        AZURE_SETTINGS['client_id'],
        authority=AZURE_SETTINGS['authority'],
        client_credential=AZURE_SETTINGS['client_secret']
    )

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            flow = _build_msal_app().initiate_auth_code_flow(
                AZURE_SETTINGS['scope'],
                redirect_uri=url_for('authorized', _external=True)
            )
            session["flow"] = flow
            return redirect(flow["auth_uri"])
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        # Check the groups claim from the ID token. Ensure your app registration includes group claims.
        groups = session["user"].get("groups", [])
        if AZURE_SETTINGS["admin_group_id"] not in groups:
            return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return decorated_function

def fetch_service_data():
    """Fetch service data from the Nagios XI API."""
    try:
        response = requests.get(
            API_URL,
            params={'apikey': API_KEY},
            timeout=10,
            verify=False  # For dev/test; switch to True in production
        )
        response.raise_for_status()
        return response.json().get('servicestatus', [])
    except requests.RequestException:
        return []

def process_services(services, selected_hosts=None, host_display_names=None, selected_service=None):
    """Group services by host (from your original snippet)."""
    hosts_dict = defaultdict(list)
    for service in services:
        try:
            service_name = service.get('service_description', 'Unknown Service')
            host_name = service.get('host_name', 'Unknown Host')
            current_state = service.get('current_state', '3')  # '3' means Unknown
            status_output = service.get('output', 'No output')

            if selected_hosts and host_name not in selected_hosts:
                continue
            if selected_service and service_name != selected_service:
                continue

            last_check_raw = service.get('last_check', 'Unknown Time')
            try:
                dt = datetime.datetime.strptime(last_check_raw, '%Y-%m-%d %H:%M:%S')
                last_check = dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                last_check = 'Unknown Time'

            if current_state == '0':
                status = 'Online'
            elif current_state == '1':
                status = 'Warning'
            elif current_state == '2':
                status = 'Critical'
            else:
                status = 'Unknown'

            service_info = {
                'service_name': service_name,
                'status': status,
                'status_output': status_output,
                'last_check': last_check
            }
            hosts_dict[host_name].append(service_info)
        except Exception:
            pass

    host_list = []
    for host_name, services_list in hosts_dict.items():
        display_name = (host_display_names.get(host_name) if host_display_names else host_name)
        host_status = 'Online'
        if any(svc['status'] == 'Critical' for svc in services_list):
            host_status = 'Critical'
        elif any(svc['status'] == 'Warning' for svc in services_list):
            host_status = 'Warning'
        host_list.append({
            'host_name': host_name,
            'display_name': display_name,
            'services': services_list,
            'host_status': host_status
        })
    return host_list

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
        # Save the user's ID token claims (which include groups if configured) in the session
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

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

@app.route('/admin')
@login_required
@admin_required
def admin_view():
    services = fetch_service_data()
    host_list = process_services(services)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('admin.html', hosts=host_list, timestamp=timestamp)

@app.route('/user')
@login_required
def user_view():
    services = fetch_service_data()
    selected_hosts = [
        'www.dcwater.com',
        'konasso.dcwater.com',
        'maximo.dcwasa.com',
        'bpl-dgisesri.dcwasa.com',
        'Genesys-BPL Router',
        'bpl-ravpn-01.dcwasa.com'
    ]
    host_display_names = {
        'www.dcwater.com': 'DC Water Website',
        'konasso.dcwater.com': 'Kona',
        'maximo.dcwasa.com': 'Maximo',
        'bpl-dgisesri.dcwasa.com': 'GIS',
        'Genesys-BPL Router': 'Genesys',
        'bpl-ravpn-01.dcwasa.com': 'VPN'
    }
    host_list = process_services(
        services,
        selected_hosts=selected_hosts,
        host_display_names=host_display_names,
        selected_service='Ping'
    )
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template('user.html', hosts=host_list, timestamp=timestamp)

if __name__ == '__main__':
    app.run(debug=False, host='bluestatus.dcwater.com', port=80)
