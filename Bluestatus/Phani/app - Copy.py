from flask import Flask, render_template, session, redirect, url_for, request
from dotenv import load_dotenv
import msal
import os
import requests
import json
from datetime import datetime
from functools import wraps
 
# Load environment variables
load_dotenv()
 
# Create Flask app instance
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
 
# Azure AD Config
azure_settings = {
    'client_id': os.getenv('AZURE_CLIENT_ID'),
    'client_secret': os.getenv('AZURE_CLIENT_SECRET'),
    'tenant_id': os.getenv('AZURE_TENANT_ID'),
    'admin_group_id': os.getenv('AZURE_ADMIN_GROUP_ID'),
    'authority': f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}",
    'scope': ['User.Read', 'GroupMember.Read.All'],
    'redirect_path': '/getAToken',
}
 
# Initialize MSAL
def _build_msal_app():
    return msal.ConfidentialClientApplication(
        azure_settings['client_id'],
        authority=azure_settings['authority'],
        client_credential=azure_settings['client_secret']
    )
 
def _get_token_from_cache(scope=None):
    msal_app = _build_msal_app()
    cache = msal_app.token_cache
    if session.get("user"):
        accounts = cache.find(msal.TokenCache.CredentialType.ID_TOKEN_CACHE,
                            target=[azure_settings['client_id']],
                            query={"home_account_id": session["user"]["home_account_id"]})
        return cache.find(msal.TokenCache.CredentialType.ACCESS_TOKEN_CACHE,
                         target=scope or azure_settings['scope'],
                         query={"home_account_id": session["user"]["home_account_id"]})
 
# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            session["flow"] = _build_msal_app().initiate_auth_code_flow(
                azure_settings['scope'],
                redirect_uri=url_for('authorized', _external=True)
            )
            return redirect(session["flow"]["auth_uri"])
        return f(*args, **kwargs)
    return decorated_function
 
# Admin role check decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
       
        if not session.get('is_admin'):
            # Check if user is in admin group
            token = _get_token_from_cache(azure_settings['scope'])
            if not token:
                return redirect(url_for('login'))
           
            graph_data = requests.get(
                f'https://graph.microsoft.com/v1.0/users/{session["user"]["preferred_username"]}/memberOf',
                headers={'Authorization': f'Bearer {token[0]["access_token"]}'},
            ).json()
           
            is_admin = any(group['id'] == azure_settings['admin_group_id']
                         for group in graph_data.get('value', []))
           
            if not is_admin:
                return redirect(url_for('unauthorized'))
           
            session['is_admin'] = True
       
        return f(*args, **kwargs)
    return decorated_function
 
def get_nagios_data():
    """Fetch data from Nagios XI API"""
    api_key = os.getenv('NAGIOS_API_KEY')
    base_url = "https://nagiosxi.dcwater.com/nagiosxi/api/v1"
   
    try:
        # Get host status
        host_url = f"{base_url}/objects/hoststatus?apikey={api_key}&pretty=1"
        response = requests.get(host_url)
        response.raise_for_status()
       
        hosts_data = response.json()
       
        # Process and format the data
        formatted_hosts = []
        for host in hosts_data.get('data', {}).get('hoststatus', []):
            # Get services for this host
            services_url = f"{base_url}/objects/servicestatus?apikey={api_key}&pretty=1&host_name={host['host_name']}"
            services_response = requests.get(services_url)
            services_response.raise_for_status()
            services_data = services_response.json()
           
            # Map Nagios status codes to readable status
            status_map = {
                0: 'Online',
                1: 'Warning',
                2: 'Critical',
                3: 'Unknown'
            }
           
            host_status = status_map.get(int(host.get('current_state', 3)), 'Unknown')
           
            formatted_services = []
            for service in services_data.get('data', {}).get('servicestatus', []):
                service_status = status_map.get(int(service.get('current_state', 3)), 'Unknown')
                last_check = datetime.fromtimestamp(int(service.get('last_check', 0)))
               
                formatted_services.append({
                    'service_name': service.get('service_description', 'Unknown Service'),
                    'status': service_status,
                    'status_output': service.get('plugin_output', 'No output available'),
                    'last_check': last_check.strftime('%Y-%m-%d %H:%M:%S')
                })
           
            formatted_hosts.append({
                'host_name': host.get('host_name', 'Unknown Host'),
                'display_name': host.get('host_display_name', host.get('host_name', 'Unknown Host')),
                'host_status': host_status,
                'services': formatted_services
            })
       
        return formatted_hosts
       
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Nagios data: {e}")
        return []
 
@app.route('/')
def index():
    return redirect(url_for('user_view'))
 
@app.route('/login')
def login():
    session.clear()
    session["flow"] = _build_msal_app().initiate_auth_code_flow(
        azure_settings['scope'],
        redirect_uri=url_for('authorized', _external=True)
    )
    return redirect(session["flow"]["auth_uri"])
 
@app.route('/getAToken')
def authorized():
    try:
        result = _build_msal_app().acquire_token_by_auth_code_flow(
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
    return redirect(
        f"{azure_settings['authority']}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={url_for('index', _external=True)}"
    )
 
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
    app.run(host='0.0.0.0', port=80)  # Production settings