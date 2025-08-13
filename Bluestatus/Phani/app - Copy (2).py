import os
import json
import logging
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

# Configure logging
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('flask_app.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("app")

logger = setup_logging()

# Azure AD Configuration
AZURE_SETTINGS = {
    'client_id': os.getenv('AZURE_CLIENT_ID'),
    'client_secret': os.getenv('AZURE_CLIENT_SECRET'),  # Not safe to log
    'tenant_id': os.getenv('AZURE_TENANT_ID'),
    'admin_group_id': os.getenv('AZURE_ADMIN_GROUP_ID'),
    'authority': f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID')}",
    'scope': ['User.Read', 'GroupMember.Read.All'],
    'redirect_path': '/getAToken',
}

# Log the loaded environment values (EXCEPT the client secret)
logger.info("AZURE_SETTINGS loaded:")
logger.info("  tenant_id: %s", AZURE_SETTINGS['tenant_id'])
logger.info("  admin_group_id: %s", AZURE_SETTINGS['admin_group_id'])
logger.info("  client_id: %s", AZURE_SETTINGS['client_id'])
logger.info("  authority: %s", AZURE_SETTINGS['authority'])
logger.info("  scope: %s", AZURE_SETTINGS['scope'])

# Create Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
logger.info("Flask app created. Secret key loaded (not logged).")

def create_requests_session():
    """Create a requests session with retry and timeout strategy."""
    logger.info("Creating a requests session with retry logic.")
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET']
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s = requests.Session()
    s.mount("https://", adapter)
    logger.info("Requests session created with retry strategy.")
    return s

def _build_msal_app():
    """Build MSAL application instance."""
    logger.info("Building MSAL ConfidentialClientApplication.")
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
    logger.info("Entering _get_token_from_cache with scope=%s", scope)
    msal_app = _build_msal_app()

    if not session.get("user"):
        logger.warning("No user in session; cannot retrieve token from cache.")
        return None

    username = session["user"].get("preferred_username")
    logger.info("Looking for accounts in MSAL cache matching username=%s", username)
    accounts = msal_app.get_accounts(username=username)
    if not accounts:
        logger.warning("No matching accounts found in MSAL cache for %s", username)
        return None

    logger.info("Found %d account(s) in cache. Attempting acquire_token_silent.", len(accounts))
    result = msal_app.acquire_token_silent(
        scopes=scope or AZURE_SETTINGS['scope'],
        account=accounts[0]
    )

    if result:
        if "access_token" in result:
            logger.info("Successfully acquired token silently.")
            # Return in list form to remain compatible with admin_required usage
            return [{"access_token": result["access_token"]}]
        else:
            logger.warning("acquire_token_silent returned result but no 'access_token' in it. result=%s", result)
    else:
        logger.warning("acquire_token_silent returned None; no valid token found.")
    return None

def login_required(f):
    """Decorator to enforce login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info("login_required decorator called for endpoint: %s", f.__name__)
        if not session.get('user'):
            logger.info("No user in session. Initiating auth code flow.")
            session["flow"] = _build_msal_app().initiate_auth_code_flow(
                AZURE_SETTINGS['scope'],
                redirect_uri=url_for('authorized', _external=True)
            )
            logger.info("Flow dict created: %s", session["flow"])
            return redirect(session["flow"]["auth_uri"])
        logger.info("User is in session. Proceeding to the view.")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to enforce admin access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info("admin_required decorator called for endpoint: %s", f.__name__)
        if not session.get('user'):
            logger.warning("No user in session; redirecting to login.")
            return redirect(url_for('login'))

        logger.info("Checking if user is_admin in session.")
        if not session.get('is_admin'):
            logger.info("User is not marked as admin yet; retrieving token.")
            token = _get_token_from_cache(AZURE_SETTINGS['scope'])
            if not token:
                logger.warning("Could not retrieve token from cache; redirecting to login.")
                return redirect(url_for('login'))

            try:
                access_token = token[0]["access_token"]
                logger.info("Making Graph API call for group membership. Admin group ID is %s", AZURE_SETTINGS['admin_group_id'])
                url = f'https://graph.microsoft.com/v1.0/users/{session["user"]["preferred_username"]}/memberOf'
                logger.info("Request URL: %s", url)
                graph_data = requests.get(
                    url,
                    headers={'Authorization': f'Bearer {access_token}'},
                ).json()
                logger.info("Graph response: %s", json.dumps(graph_data, indent=2))

                is_admin = any(
                    group['id'] == AZURE_SETTINGS['admin_group_id']
                    for group in graph_data.get('value', [])
                )
                logger.info("Is user in admin group? %s", is_admin)

                if not is_admin:
                    logger.warning("User not in admin group; redirecting to unauthorized.")
                    return redirect(url_for('unauthorized'))

                logger.info("User is now marked as admin.")
                session['is_admin'] = True
            except Exception as e:
                logger.error(f"Admin check failed with exception: {e}", exc_info=True)
                return redirect(url_for('unauthorized'))

        logger.info("User is_admin. Proceeding to the view.")
        return f(*args, **kwargs)
    return decorated_function

def parse_last_check(last_check_value):
    """
    Attempt to parse 'last_check' whether it's a Unix timestamp or a date string.
    Returns a formatted date/time string or 'Unknown'.
    """
    logger.debug("Parsing last_check value: %s", last_check_value)
    if not last_check_value:
        return "Unknown"

    # 1. Try numeric (Unix epoch)
    if str(last_check_value).isdigit():
        try:
            dt = datetime.fromtimestamp(int(last_check_value))
            formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
            logger.debug("Parsed last_check as Unix timestamp: %s", formatted_time)
            return formatted_time
        except (ValueError, OSError):
            logger.debug("Failed to parse as Unix timestamp. Will try date string.")

    # 2. Otherwise, parse as YYYY-MM-DD HH:MM:SS
    try:
        dt = datetime.strptime(last_check_value, '%Y-%m-%d %H:%M:%S')
        formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
        logger.debug("Parsed last_check as date string: %s", formatted_time)
        return formatted_time
    except ValueError:
        logger.debug("Could not parse last_check as date string. Returning original or 'Unknown'.")
        return last_check_value

def get_nagios_data():
    """Fetch and process Nagios XI API data."""
    logger.info("Entering get_nagios_data().")
    api_key = os.getenv('NAGIOS_API_KEY')
    base_url = "https://nagiosxi.dcwater.com/nagiosxi/api/v1"
    logger.info("Nagios API key: %s", api_key)  # WARNING: logs API key
    logger.info("Nagios base_url: %s", base_url)

    try:
        # Fetch host status
        host_url = f"{base_url}/objects/hoststatus?apikey={api_key}&pretty=1"
        logger.info("Requesting host status from: %s", host_url)
        response = requests.get(host_url, verify=True)
        response.raise_for_status()

        hosts_data = response.json()
        logger.info("Raw hosts data received: %s", json.dumps(hosts_data, indent=2))

        formatted_hosts = []
        status_map = {0: 'Online', 1: 'Warning', 2: 'Critical', 3: 'Unknown'}

        recordcount = hosts_data.get('recordcount', 0)
        logger.info("Hosts recordcount=%s", recordcount)
        if recordcount > 0:
            for host in hosts_data.get('hoststatus', []):
                host_name = host.get('host_name')
                host_current_state = int(host.get('current_state', 3))
                logger.info("Processing host: %s, state=%s", host_name, host_current_state)

                # Fetch services for each host
                services_url = (
                    f"{base_url}/objects/servicestatus?apikey={api_key}&pretty=1"
                    f"&host_name={host_name}"
                )
                logger.info("Requesting services from: %s", services_url)
                services_response = requests.get(services_url, verify=True)
                services_response.raise_for_status()
                services_data = services_response.json()
                logger.info("Raw services data for %s: %s", host_name, json.dumps(services_data, indent=2))

                formatted_services = []
                svc_recordcount = services_data.get('recordcount', 0)
                logger.info("Services recordcount for host %s: %s", host_name, svc_recordcount)

                if svc_recordcount > 0:
                    for service in services_data.get('servicestatus', []):
                        service_description = service.get('service_description', 'Unknown Service')
                        current_state = int(service.get('current_state', 3))
                        logger.info("Service: %s, current_state=%s", service_description, current_state)
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

        logger.info("Formatted %d hosts with their services.", len(formatted_hosts))
        return formatted_hosts

    except requests.exceptions.RequestException as e:
        logger.error("Error fetching Nagios data: %s", e, exc_info=True)
        return []

# Flask routes
@app.route('/')
def index():
    logger.info("GET / => redirect to /user.")
    return redirect(url_for('user_view'))

@app.route('/login')
def login():
    logger.info("GET /login => clearing session and initiating auth code flow.")
    session.clear()
    flow = _build_msal_app().initiate_auth_code_flow(
        AZURE_SETTINGS['scope'],
        redirect_uri=url_for('authorized', _external=True)
    )
    session["flow"] = flow
    logger.info("Flow stored in session: %s", flow)
    return redirect(flow["auth_uri"])

@app.route('/getAToken')
def authorized():
    logger.info("GET /getAToken => exchanging auth code for token.")
    try:
        msal_app = _build_msal_app()
        result = msal_app.acquire_token_by_auth_code_flow(
            session.get('flow', {}),
            request.args
        )
        logger.info("acquire_token_by_auth_code_flow result: %s", result)
        if "error" in result:
            logger.error("Error in token acquisition: %s", result)
            return render_template("error.html", result=result)
        session["user"] = result.get("id_token_claims")
        logger.info("User claims stored in session: %s", session["user"])
        return redirect(url_for("user_view"))
    except ValueError:
        logger.error("ValueError in authorized(). Possibly missing or invalid auth code.")
        return redirect(url_for("login"))

@app.route('/logout')
def logout():
    logger.info("GET /logout => clearing session and redirecting to Azure logout.")
    session.clear()
    logout_url = (
        f"{AZURE_SETTINGS['authority']}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={url_for('index', _external=True)}"
    )
    logger.info("Logout URL: %s", logout_url)
    return redirect(logout_url)

@app.route('/user')
@login_required
def user_view():
    logger.info("GET /user => retrieving Nagios data for user view.")
    hosts = get_nagios_data()
    logger.info("Rendering user view with %d hosts", len(hosts))
    return render_template('user.html', hosts=hosts)

@app.route('/admin')
@login_required
@admin_required
def admin_view():
    logger.info("GET /admin => retrieving Nagios data for admin view.")
    hosts = get_nagios_data()
    logger.info("Rendering admin view with %d hosts", len(hosts))
    return render_template('admin.html', hosts=hosts)

@app.route('/unauthorized')
def unauthorized():
    logger.warning("GET /unauthorized => rendering unauthorized page.")
    return render_template('unauthorized.html')

@app.route('/error')
def error():
    logger.error("GET /error => rendering error page.")
    return render_template('error.html')

if __name__ == '__main__':
    logger.info("Starting Flask app on host=bluestatus.dcwater.com, port=80.")
    app.run(debug=False, host='bluestatus.dcwater.com', port=80)
