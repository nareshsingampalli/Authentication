import os
import json
import requests
import time
import logging
import threading
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional, List
from urllib.parse import parse_qs, urlparse
import redis
import jwt
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("auth_service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class UpstoxAuthManager:
    def __init__(self, creds_file: str = "credentials.json", tokens_file: str = "tokens.json"):
        self.creds_file = creds_file
        self.tokens_file = tokens_file
        self.file_lock = threading.Lock()
        self.credentials = self._load_json(creds_file)
        self.tokens = self._load_json(tokens_file)
        
        # Redis Connection
        self.redis_host = os.getenv("REDIS_HOST", "140.245.8.242")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        self.redis_password = os.getenv("REDIS_PASSWORD", "yourpassword123")
        self.redis_client = None
        
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                password=self.redis_password,
                decode_responses=True,
                socket_timeout=5
            )
            self.redis_client.ping()
            logger.info("Connected to Redis successfully.")
            self.sync_tokens_to_redis()
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
        
        # Start background refresher
        self.stop_event = threading.Event()
        self.refresher_thread = threading.Thread(target=self._background_refresher, daemon=True)
        self.refresher_thread.start()

        # Start background heartbeat lock reclaimer
        self.reclaimer_thread = threading.Thread(target=self._background_lock_reclaimer, daemon=True)
        self.reclaimer_thread.start()

        # OTP submission state (for headless browser waiting on VM)
        self.otp_events: Dict[str, threading.Event] = {}
        self.otp_values: Dict[str, str] = {}
        self.pending_otp_accounts: set = set()

    def sync_tokens_to_redis(self):
        if not self.redis_client:
            return
        try:
            logger.info("Syncing tokens from tokens.json to Redis...")
            active_account_ids = []
            
            for account_id in self.credentials:
                token_data = self.tokens.get(account_id, {})
                access_token = token_data.get("access_token")
                
                if access_token:
                    expires_at = None
                    try:
                        decoded = jwt.decode(access_token, options={"verify_signature": False})
                        expires_at = decoded.get("exp")
                    except Exception as e:
                        logger.warning(f"Failed to decode JWT for {account_id}: {e}")
                    
                    # Verify validity locally (token is active and not expired)
                    is_valid = False
                    if expires_at and expires_at > time.time():
                        is_valid = True
                        
                    if is_valid:
                        redis_data = {
                            "access_token": access_token,
                            "extended_token": token_data.get("extended_token", ""),
                            "user_name": token_data.get("user_name", account_id),
                            "user_id": token_data.get("user_id", ""),
                            "broker": token_data.get("broker", "UPSTOX"),
                            "email": token_data.get("email", ""),
                            "timestamp": str(token_data.get("timestamp", time.time())),
                            "expires_at": str(expires_at)
                        }
                        
                        # Convert all values to strings for Redis hash
                        self.redis_client.hset(f"token:{account_id}", mapping=redis_data)
                        logger.info(f"Token saved to Redis for {account_id} (Expires at: {expires_at})")
                        active_account_ids.append(account_id)
                    else:
                        logger.warning(f"Token for {account_id} is expired or invalid. Clearing from Redis if exists.")
                        # Clean up stale/expired token details if any exist in Redis
                        self.redis_client.delete(f"token:{account_id}")
                        self.redis_client.lrem("available_tokens", 0, account_id)
                        self.redis_client.srem("tokens_in_use", account_id)
            
            # Check what is currently in available_tokens and tokens_in_use
            current_queue = self.redis_client.lrange("available_tokens", 0, -1)
            current_in_use = self.redis_client.smembers("tokens_in_use")
            
            # Reset queue if empty to ensure self-healing pool
            if not current_queue and not current_in_use:
                logger.info("Redis token queue is empty. Initializing available_tokens pool...")
                for acc_id in active_account_ids:
                    self.redis_client.lpush("available_tokens", acc_id)
                    logger.info(f"Initialized available_tokens pool with '{acc_id}'")
            else:
                # Top up active tokens not in queue and not in use
                for acc_id in active_account_ids:
                    if acc_id not in current_queue and acc_id not in current_in_use:
                        self.redis_client.lpush("available_tokens", acc_id)
                        logger.info(f"Added '{acc_id}' to Redis available_tokens queue.")
        except Exception as e:
            logger.error(f"Error syncing tokens to Redis: {e}")

    def is_token_expired_soon(self, token: str, buffer_seconds: int = 300) -> bool:
        if not token:
            return True
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get("exp")
            if not exp:
                return True
            return (exp - time.time()) < buffer_seconds
        except Exception as e:
            logger.error(f"Error decoding token for expiry: {e}")
            return True

    def _load_json(self, filepath: str) -> Dict[str, Any]:
        with self.file_lock:
            if not os.path.exists(filepath):
                return {}
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading {filepath}: {e}")
                return {}

    def _save_json(self, filepath: str, data: Dict[str, Any]):
        with self.file_lock:
            temp_file = filepath + ".tmp"
            try:
                with open(temp_file, 'w') as f:
                    json.dump(data, f, indent=4)
                os.replace(temp_file, filepath)
            except Exception as e:
                logger.error(f"Error saving {filepath}: {e}")

    def is_token_valid(self, token: str) -> bool:
        if not token:
            return False
        try:
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            response = requests.get(
                "https://api.upstox.com/v2/user/profile", headers=headers, timeout=5
            )
            return response.status_code == 200
        except:
            return False

    def refresh_token(self, account_id: str):
        creds = self.credentials.get(account_id)
        if not creds:
            return False
        
        # Note: Upstox tokens are usually valid for 24h and don't use standard OAuth2 refresh tokens
        # Instead, we perform a health check and log if it needs manual re-auth
        token_data = self.tokens.get(account_id, {})
        access_token = token_data.get("access_token")
        
        # Proactively check JWT expiry locally first to avoid broker API overhead
        if access_token and not self.is_token_expired_soon(access_token, buffer_seconds=300):
            logger.info(f"Token for {account_id} is still valid (checked locally).")
            return True
            
        # Fallback to API verification
        if self.is_token_valid(access_token):
            logger.info(f"Token for {account_id} is still valid (verified via API).")
            return True
        else:
            logger.warning(f"Token for {account_id} is invalid or expired. Removing from Redis.")
            # Clean up expired token from Redis
            if self.redis_client:
                try:
                    self.redis_client.delete(f"token:{account_id}")
                    self.redis_client.lrem("available_tokens", 0, account_id)
                    self.redis_client.srem("tokens_in_use", account_id)
                    logger.info(f"Cleared expired token for {account_id} from Redis.")
                except Exception as re:
                    logger.error(f"Failed to clear expired token from Redis: {re}")
            return False

    def get_all_tokens_status(self) -> Dict[str, str]:
        status = {}
        for acc_id in self.credentials:
            token_data = self.tokens.get(acc_id, {})
            access_token = token_data.get("access_token")
            if not access_token:
                status[acc_id] = "Missing"
                if self.redis_client:
                    self.redis_client.delete(f"token:{acc_id}")
                    self.redis_client.lrem("available_tokens", 0, acc_id)
                    self.redis_client.srem("tokens_in_use", acc_id)
            elif not self.is_token_expired_soon(access_token, buffer_seconds=300):
                status[acc_id] = "Valid"
            elif self.is_token_valid(access_token):
                status[acc_id] = "Valid"
            else:
                status[acc_id] = "Expired"
                if self.redis_client:
                    try:
                        self.redis_client.delete(f"token:{acc_id}")
                        self.redis_client.lrem("available_tokens", 0, acc_id)
                        self.redis_client.srem("tokens_in_use", acc_id)
                        logger.info(f"Cleared expired token for {acc_id} from Redis during status check.")
                    except Exception as re:
                        logger.error(f"Failed to clear expired token from Redis during status check: {re}")
        return status

    def _background_refresher(self):
        logger.info("Background token refresher started.")
        while not self.stop_event.is_set():
            # Check every 5 minutes (300 seconds)
            for account_id in list(self.credentials.keys()):
                token_data = self.tokens.get(account_id, {})
                access_token = token_data.get("access_token")
                
                # Warn and perform active validation if expiring in under 15 minutes
                if not access_token or self.is_token_expired_soon(access_token, buffer_seconds=900):
                    logger.warning(f"Token for {account_id} is missing, expired, or expiring within 15 minutes!")
                    self.refresh_token(account_id)
                else:
                    logger.info(f"Token for {account_id} is healthy (verified locally).")
            self.stop_event.wait(300)

    def _background_lock_reclaimer(self):
        logger.info("Background heartbeat lock reclaimer started.")
        while not self.stop_event.is_set():
            if self.redis_client:
                try:
                    # Get all currently marked in-use tokens in Redis
                    in_use_accounts = self.redis_client.smembers("tokens_in_use")
                    for account_id in in_use_accounts:
                        # Check if heartbeat key exists
                        hb_exists = self.redis_client.exists(f"token_heartbeat:{account_id}")
                        if not hb_exists:
                            logger.warning(f"⚠️ Stale lock detected for {account_id}! Heartbeat key 'token_heartbeat:{account_id}' does not exist (app likely hard-killed). Reclaiming token...")
                            
                            # Remove from tokens_in_use
                            self.redis_client.srem("tokens_in_use", account_id)
                            
                            # To avoid duplicate entries in queue, verify it is not already in queue
                            current_queue = self.redis_client.lrange("available_tokens", 0, -1)
                            if account_id not in current_queue:
                                self.redis_client.lpush("available_tokens", account_id)
                                logger.info(f"♻️ Reclaimed token for '{account_id}' and pushed it back to available_tokens queue.")
                            else:
                                logger.info(f"Token '{account_id}' was already in available_tokens queue.")
                except Exception as e:
                    logger.error(f"Error in lock reclaimer: {e}")
            self.stop_event.wait(15)  # Sweep every 15 seconds

    def wait_for_otp(self, account_id: str, timeout: int = 300) -> Optional[str]:
        """Block until OTP is submitted via the dashboard, or timeout."""
        event = threading.Event()
        self.otp_events[account_id] = event
        self.pending_otp_accounts.add(account_id)
        logger.info(f"Waiting for OTP submission for {account_id} via dashboard...")
        got_otp = event.wait(timeout=timeout)
        self.pending_otp_accounts.discard(account_id)
        self.otp_events.pop(account_id, None)
        if got_otp:
            return self.otp_values.pop(account_id, None)
        logger.warning(f"OTP timeout for {account_id}")
        return None

    def submit_otp(self, account_id: str, otp: str):
        """Called by HTTP handler when user submits OTP from dashboard."""
        self.otp_values[account_id] = otp
        event = self.otp_events.get(account_id)
        if event:
            event.set()
            logger.info(f"OTP received and signalled for {account_id}")
        else:
            logger.warning(f"submit_otp called for {account_id} but no waiting event found")

    def add_account(self, account_id: str, api_key: str, api_secret: str, redirect_uri: str, pin: str = "", phone: str = ""):
        self.credentials[account_id] = {
            "api_key": api_key,
            "api_secret": api_secret,
            "redirect_uri": redirect_uri,
            "pin": pin,
            "phone": phone
        }
        self._save_json(self.creds_file, self.credentials)
        logger.info(f"Account '{account_id}' added/updated.")

    def exchange_code_for_token(self, account_id: str, code: str):
        creds = self.credentials.get(account_id)
        if not creds:
            logger.error(f"Credentials not found for {account_id}")
            return None

        url = "https://api.upstox.com/v2/login/authorization/token"
        payload = {
            'code': code,
            'client_id': creds['api_key'],
            'client_secret': creds['api_secret'],
            'redirect_uri': creds['redirect_uri'],
            'grant_type': 'authorization_code'
        }
        headers = {'accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            response = requests.post(url, headers=headers, data=payload)
            if response.status_code == 200:
                data = response.json()
                self.tokens[account_id] = {
                    "access_token": data['access_token'],
                    "timestamp": time.time(),
                    "user_name": data.get('user_name', account_id)
                }
                self._save_json(self.tokens_file, self.tokens)
                logger.info(f"Token successfully updated for {account_id}")
                
                 # Save and publish to Redis
                if self.redis_client:
                    try:
                        expires_at = None
                        try:
                            decoded = jwt.decode(data['access_token'], options={"verify_signature": False})
                            expires_at = decoded.get("exp")
                        except Exception as je:
                            logger.warning(f"Failed to decode JWT for {account_id}: {je}")

                        # Check validity before pushing to Redis
                        is_valid = False
                        if expires_at and expires_at > time.time():
                            if self.is_token_valid(data['access_token']):
                                is_valid = True
                        
                        if is_valid:
                            redis_data = {
                                "access_token": data['access_token'],
                                "extended_token": data.get('extended_token', ''),
                                "user_name": data.get('user_name', account_id),
                                "user_id": data.get('user_id', ''),
                                "broker": "UPSTOX",
                                "timestamp": str(time.time()),
                                "expires_at": str(expires_at or 0)
                            }
                            self.redis_client.hset(f"token:{account_id}", mapping=redis_data)
                            
                            # Publish update
                            self.redis_client.publish(f"token_updates:{account_id}", json.dumps({"access_token": data['access_token']}))
                            
                            # Add to available queue if not in queue and not in use
                            current_queue = self.redis_client.lrange("available_tokens", 0, -1)
                            current_in_use = self.redis_client.smembers("tokens_in_use")
                            if account_id not in current_queue and account_id not in current_in_use:
                                self.redis_client.lpush("available_tokens", account_id)
                                logger.info(f"Pushed '{account_id}' to available_tokens queue.")
                                
                            logger.info(f"Redis updated and published for {account_id}")
                        else:
                            logger.error(f"Newly acquired token for {account_id} is invalid or expired. Skipping Redis push.")
                    except Exception as re:
                        logger.error(f"Failed to update Redis: {re}")
                
                return data['access_token']
            else:
                logger.error(f"Failed to exchange code for {account_id}: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error exchanging code for {account_id}: {e}")
            return None

    def auto_login_headless(self, account_id: str):
        """Perform a headless login using Playwright"""
        from playwright.sync_api import sync_playwright
        
        creds = self.credentials.get(account_id)
        if not creds or not creds.get("pin"):
            logger.error(f"Cannot auto-login {account_id}: Missing PIN or credentials.")
            return

        logger.info(f"Starting headless auto-login for {account_id}...")
        
        # Run headless only if on Linux (VM), run visible on Windows (local)
        import platform
        is_headless = (platform.system() == "Linux")
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=is_headless) 
            context = browser.new_context()
            page = context.new_page()
            
            import urllib.parse
            encoded_uri = urllib.parse.quote(creds['redirect_uri'])
            auth_url = (
                "https://api.upstox.com/v2/login/authorization/dialog"
                f"?client_id={creds['api_key']}&redirect_uri={encoded_uri}&response_type=code&state={account_id}"
            )

            
            page.goto(auth_url)
            
            otp_entered = False
            try:
                # Increased timeout to 15 seconds to ensure slow page loads don't skip the phone step
                phone_input = page.wait_for_selector("input[type='text'], input#mobileNum", timeout=15000)
                if phone_input and creds.get("phone"):
                    logger.info("Phone page detected. Entering phone number...")
                    phone_input.fill(creds["phone"])
                    page.click("button#getOtp, button:has-text('Get OTP')")
                    logger.info("OTP sent. Waiting for user to submit OTP via dashboard...")

                    # Wait for OTP from the user (submitted via dashboard UI)
                    otp = self.wait_for_otp(account_id, timeout=300)
                    if otp:
                        logger.info(f"Entering OTP for {account_id}...")
                        try:
                            otp_input = page.wait_for_selector(
                                "input[type='text'][maxlength], input[type='number'], input[placeholder*='OTP'], input[placeholder*='otp'], input[id*='otp'], input[name*='otp']",
                                timeout=10000
                            )
                            if otp_input:
                                otp_input.fill(otp)
                                time.sleep(0.3)
                                page.click("button:has-text('Continue'), button:has-text('Verify'), button[type='submit']")
                                otp_entered = True
                                logger.info(f"OTP entered for {account_id}")
                        except Exception as e:
                            logger.warning(f"Could not find OTP input field, trying keyboard: {e}")
                            page.keyboard.type(otp)
                            page.keyboard.press("Enter")
                            otp_entered = True
                    else:
                        logger.error(f"No OTP received for {account_id}. Aborting.")
                        browser.close()
                        return
            except Exception:
                logger.info("Phone page not detected, checking for PIN page...")

            try:
                pin_input = page.wait_for_selector("input[type='password'], input#pinCode", timeout=300000)
                if pin_input:
                    logger.info("PIN page detected. Entering PIN...")
                    time.sleep(1)
                    
                    # Click to focus the PIN field
                    pin_input.click()
                    time.sleep(0.3)
                    
                    # Type using keyboard (fires browser-level key events React always picks up)
                    page.keyboard.type(creds["pin"], delay=150)
                    time.sleep(0.3)
                    
                    # Also dispatch input/change events via JS as safety net for React
                    page.evaluate("""(el) => {
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                    }""", pin_input)
                    
                    # Wait for React to re-render and enable the Continue button
                    time.sleep(0.8)
                    
                    # Wait for Continue button to become ENABLED, then click it
                    try:
                        # Wait up to 5s for the button to be enabled
                        page.wait_for_function("""() => {
                            const selectors = [
                                'button#submitPin',
                                'button[type="submit"]'
                            ];
                            for (const sel of selectors) {
                                const btn = document.querySelector(sel);
                                if (btn && !btn.disabled) return true;
                            }
                            // Also check any button with Continue text
                            const btns = Array.from(document.querySelectorAll('button'));
                            return btns.some(b => b.textContent.trim().includes('Continue') && !b.disabled);
                        }""", timeout=5000)
                        logger.info("Continue button is now enabled. Clicking...")
                    except Exception:
                        logger.warning("Timed out waiting for button to enable. Trying anyway...")
                    
                    # Click the enabled button
                    clicked = False
                    for selector in [
                        "button#submitPin:not([disabled])",
                        "button[type='submit']:not([disabled])",
                        "button:has-text('Continue')",
                        "button:has-text('Verify')",
                        "button:has-text('Login')",
                    ]:
                        try:
                            btn = page.query_selector(selector)
                            if btn and btn.is_visible():
                                btn.click()
                                clicked = True
                                logger.info(f"Clicked button: {selector}")
                                break
                        except Exception:
                            continue
                    
                    # Fallback: press Enter on the PIN field
                    if not clicked:
                        logger.info("No button found, pressing Enter on PIN field...")
                        pin_input.press("Enter")
                    
                    # Wait for any redirect away from the login page
                    try:
                        page.wait_for_url("**alertsv03.in**", timeout=30000)
                        logger.info(f"Auto-login successful for {account_id}!")
                    except Exception:
                        page.wait_for_url("**127.0.0.1**", timeout=10000)
                        logger.info(f"Auto-login successful for {account_id}!")
                        
            except Exception as e:
                logger.error(f"Auto-login failed for {account_id}: {e}")
            
            browser.close()

class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]

        # 1. Handle OAuth Callback (any path that has code and state)
        if code and state:
            logger.info(f"Received auth code for {state}")
            token = self.server.manager.exchange_code_for_token(state, code)
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            if token:
                self.wfile.write(f"<html><body style='background:#1a1a2e;color:white;text-align:center;padding-top:50px;font-family:sans-serif;'><h2>✅ Success!</h2><p>Account <b>{state}</b> authenticated.</p><script>setTimeout(() => window.location.href='.', 2000);</script></body></html>".encode())
            else:
                self.wfile.write(f"<html><body style='background:#1a1a2e;color:white;text-align:center;padding-top:50px;font-family:sans-serif;'><h2>❌ Error</h2><p>Failed to exchange code for {state}.</p><button onclick=\"window.location.href='.'\">Back</button></body></html>".encode())
            return

        # 2. Handle Dashboard
        if parsed.path == "/" or parsed.path == "":
            status = self.server.manager.get_all_tokens_status()
            has_valid_token = any(s == "Valid" for s in status.values())
            
            # Read next_url from query parameter or cookie
            next_url = params.get('next', [None])[0]
            cookie_header = self.headers.get('Cookie', '')
            cookie_next = None
            if cookie_header:
                from http.cookies import SimpleCookie
                try:
                    cookie = SimpleCookie(cookie_header)
                    if 'next_url' in cookie:
                        cookie_next = cookie['next_url'].value
                except Exception as ce:
                    logger.error(f"Error parsing cookies: {ce}")
            
            target_next = next_url or cookie_next
            
            if has_valid_token and target_next:
                from urllib.parse import urlparse as ul_urlparse, urlunparse as ul_urlunparse, parse_qsl as ul_parse_qsl, urlencode as ul_urlencode
                try:
                    u = ul_urlparse(target_next)
                    q = ul_parse_qsl(u.query)
                    q = [item for item in q if item[0] != 'auth_checked']
                    q.append(('auth_checked', 'true'))
                    new_query = ul_urlencode(q)
                    redirect_url = ul_urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))
                    
                    logger.info(f"Redirecting user to next page: {redirect_url}")
                    self.send_response(302)
                    self.send_header("Location", redirect_url)
                    self.send_header("Set-Cookie", "next_url=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
                    self.end_headers()
                    return
                except Exception as ex:
                    logger.error(f"Error redirecting to next_url: {ex}")
            
            accounts = self.server.manager.credentials
            html = self._generate_ui(accounts, status)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            if next_url:
                self.send_header("Set-Cookie", f"next_url={next_url}; Path=/; HttpOnly; SameSite=Lax")
            self.end_headers()
            self.wfile.write(html.encode())
            
        # 3. Handle Auto-Login Trigger
        elif "auto-login-trigger" in parsed.path:
            account_id = params.get("account_id", [""])[0]
            if account_id:
                import platform
                creds = self.server.manager.credentials.get(account_id, {})
                if platform.system() != "Linux":
                    # On Windows (local): redirect user's own browser tab directly to Upstox OAuth URL
                    import urllib.parse
                    encoded_uri = urllib.parse.quote(creds.get('redirect_uri', ''))
                    auth_url = (
                        "https://api.upstox.com/v2/login/authorization/dialog"
                        f"?client_id={creds.get('api_key', '')}&redirect_uri={encoded_uri}&response_type=code&state={account_id}"
                    )
                    self.send_response(302)
                    self.send_header("Location", auth_url)
                    self.end_headers()
                else:
                    # On Linux/VM: launch headless Playwright, then show OTP entry page
                    threading.Thread(target=self.server.manager.auto_login_headless, args=(account_id,), daemon=True).start()
                    # Give it ~4s to enter phone and send OTP before showing the OTP form
                    html = self._generate_otp_page(account_id, creds.get('phone', ''))
                    self.send_response(200)
                    self.send_header("Content-type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(html.encode())

        # 4. Handle OTP Submission
        elif "submit-otp" in parsed.path:
            account_id = params.get("account_id", [""])[0]
            otp = params.get("otp", [""])[0].strip()
            if account_id and otp:
                self.server.manager.submit_otp(account_id, otp)
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"""
                    <html><body style='background:#0f172a;color:white;text-align:center;padding-top:80px;font-family:sans-serif;'>
                    <h2 style='color:#4ade80'>✅ OTP Submitted!</h2>
                    <p style='color:#94a3b8'>The headless browser is now completing login for <b>{account_id}</b>.<br>You'll be redirected to the dashboard shortly.</p>
                    <script>setTimeout(() => window.location.href = '/token-manager/', 4000);</script>
                    </body></html>
                """.encode())
            else:
                self.send_response(400)
                self.end_headers()

        # 5. Handle OTP status check (for polling)
        elif "otp-status" in parsed.path:
            account_id = params.get("account_id", [""])[0]
            pending = account_id in self.server.manager.pending_otp_accounts
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(f'{{"pending": {str(pending).lower()}}}'.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/add-account":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            acc_id = params.get('account_id', [None])[0]
            api_key = params.get('api_key', [None])[0]
            api_secret = params.get('api_secret', [None])[0]
            r_uri = params.get('redirect_uri', ['http://127.0.0.1:8000/oauth/callback'])[0]
            pin = params.get('pin', [''])[0]
            phone = params.get('phone', [''])[0]
            
            if acc_id and api_key and api_secret:
                self.server.manager.add_account(acc_id, api_key, api_secret, r_uri, pin, phone)
                self.send_response(303)
                referer = self.headers.get('Referer', './')
                self.send_header('Location', referer)
                self.end_headers()

    def _generate_otp_page(self, account_id: str, phone: str) -> str:
        masked_phone = f"XXXXXX{phone[-4:]}" if len(phone) >= 4 else phone
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enter OTP — {account_id}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Outfit', sans-serif;
            background: #0f172a;
            background-image: radial-gradient(circle at 30% 30%, rgba(131,58,180,0.2) 0%, transparent 50%),
                              radial-gradient(circle at 70% 70%, rgba(252,176,69,0.1) 0%, transparent 50%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }}
        .card {{
            background: rgba(30,41,59,0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 24px;
            padding: 48px 40px;
            width: 420px;
            text-align: center;
        }}
        .icon {{ font-size: 3rem; margin-bottom: 16px; }}
        h1 {{ font-size: 1.6rem; font-weight: 600; margin-bottom: 8px; }}
        .subtitle {{ color: #94a3b8; font-size: 0.95rem; margin-bottom: 8px; }}
        .phone {{ color: #f8fafc; font-weight: 600; margin-bottom: 32px; font-size: 1rem; }}
        .status-msg {{
            background: rgba(131,58,180,0.15);
            border: 1px solid rgba(131,58,180,0.3);
            border-radius: 12px;
            padding: 12px 16px;
            color: #c4b5fd;
            font-size: 0.88rem;
            margin-bottom: 28px;
        }}
        .countdown {{ font-weight: 600; color: #a78bfa; }}
        .otp-input {{
            width: 100%;
            padding: 18px;
            font-size: 1.8rem;
            letter-spacing: 12px;
            text-align: center;
            background: rgba(15,23,42,0.8);
            border: 2px solid rgba(131,58,180,0.4);
            border-radius: 16px;
            color: white;
            font-family: 'Outfit', monospace;
            outline: none;
            transition: border-color 0.3s;
            margin-bottom: 20px;
        }}
        .otp-input:focus {{ border-color: #833ab4; }}
        .btn {{
            width: 100%;
            padding: 16px;
            background: linear-gradient(45deg, #833ab4, #fd1d1d, #fcb045);
            border: none;
            border-radius: 14px;
            color: white;
            font-size: 1.05rem;
            font-weight: 600;
            font-family: 'Outfit', sans-serif;
            cursor: pointer;
            transition: opacity 0.2s;
        }}
        .btn:hover {{ opacity: 0.9; }}
        .btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
        .back-link {{ display: block; margin-top: 20px; color: #64748b; font-size: 0.85rem; text-decoration: none; }}
        .back-link:hover {{ color: #94a3b8; }}
        #form-section {{ opacity: 0; transition: opacity 0.6s ease; }}
        #form-section.visible {{ opacity: 1; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">📲</div>
        <h1>Enter OTP</h1>
        <p class="subtitle">OTP sent to your registered phone</p>
        <p class="phone">{masked_phone}</p>
        <div class="status-msg" id="status-msg">
            ⏳ Sending OTP via headless browser&hellip; ready in <span class="countdown" id="counter">5</span>s
        </div>
        <div id="form-section">
            <input
                type="text"
                id="otp"
                class="otp-input"
                maxlength="6"
                placeholder="• • • • • •"
                inputmode="numeric"
                autofocus
            >
            <button class="btn" id="submit-btn" onclick="submitOTP()">Submit OTP →</button>
        </div>
        <a class="back-link" href="/token-manager/">← Back to Dashboard</a>
    </div>
    <script>
        let count = 5;
        const counter = document.getElementById('counter');
        const statusMsg = document.getElementById('status-msg');
        const formSection = document.getElementById('form-section');
        const otpInput = document.getElementById('otp');

        const timer = setInterval(() => {{
            count--;
            counter.textContent = count;
            if (count <= 0) {{
                clearInterval(timer);
                statusMsg.innerHTML = '✅ OTP SMS has been sent. Enter it below:';
                statusMsg.style.background = 'rgba(34,197,94,0.1)';
                statusMsg.style.borderColor = 'rgba(34,197,94,0.3)';
                statusMsg.style.color = '#4ade80';
                formSection.classList.add('visible');
                otpInput.focus();
            }}
        }}, 1000);

        // Allow Enter key to submit
        otpInput.addEventListener('keydown', (e) => {{
            if (e.key === 'Enter') submitOTP();
        }});

        function submitOTP() {{
            const otp = otpInput.value.trim();
            if (otp.length < 4) {{
                otpInput.style.borderColor = '#ef4444';
                otpInput.placeholder = 'Enter valid OTP';
                return;
            }}
            document.getElementById('submit-btn').disabled = true;
            document.getElementById('submit-btn').textContent = 'Submitting...';
            window.location.href = 'submit-otp?account_id={account_id}&otp=' + encodeURIComponent(otp);
        }}
    </script>
</body>
</html>"""

    def _generate_ui(self, accounts, status):
        cards = ""
        for acc_id in sorted(accounts.keys()):
            s = status.get(acc_id, "Unknown")
            is_valid = s == "Valid"
            status_class = "status-valid" if is_valid else "status-expired" if s == "Expired" else "status-unknown"
            
            phone_val = accounts[acc_id].get('phone', '')
            if phone_val and phone_val != '---':
                display_phone = phone_val[:2] + '*' * (len(phone_val) - 2) if len(phone_val) > 2 else phone_val
            else:
                display_phone = '---'
            
            cards += f"""
            <div class="card">
                <div class="card-header">
                    <span class="account-name">{acc_id}</span>
                    <span class="status-badge {status_class}">{s}</span>
                </div>
                <div class="card-body">
                    <div class="info-row"><span>API Key</span><code>{accounts[acc_id]['api_key'][:12]}...</code></div>
                    <div class="info-row"><span>Phone</span><code>{display_phone}</code></div>
                    <div class="info-row"><span>PIN</span><code>{"● ● ● ● ● ●" if accounts[acc_id].get('pin') else "Not Set"}</code></div>
                    <div class="card-actions">
                        <button onclick="startAuth('{acc_id}', '{accounts[acc_id]['api_key']}', '{accounts[acc_id]['redirect_uri']}')" class="btn btn-primary">Manual Auth</button>
                        <button onclick="window.location.href='auto-login-trigger?account_id={acc_id}'" class="btn btn-auto" title="One-Click Automation">🚀 Auto-Login</button>
                    </div>
                </div>
            </div>
            """

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Upstox Auth Cloud</title>
            <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --primary: #833ab4;
                    --primary-gradient: linear-gradient(45deg, #833ab4, #fd1d1d, #fcb045);
                    --bg: #0f172a;
                    --card-bg: rgba(30, 41, 59, 0.7);
                    --text: #f8fafc;
                    --text-dim: #94a3b8;
                    --border: rgba(255, 255, 255, 0.1);
                }}
                body {{
                    font-family: 'Outfit', sans-serif;
                    background: var(--bg);
                    background-image: radial-gradient(circle at 20% 20%, rgba(131, 58, 180, 0.15) 0%, transparent 40%),
                                      radial-gradient(circle at 80% 80%, rgba(252, 176, 69, 0.1) 0%, transparent 40%);
                    color: var(--text);
                    margin: 0;
                    padding: 40px 20px;
                    min-height: 100vh;
                }}
                .container {{ max-width: 1100px; margin: 0 auto; }}
                header {{ text-align: center; margin-bottom: 50px; }}
                h1 {{ 
                    font-size: 2.5rem; 
                    font-weight: 600; 
                    margin: 0; 
                    background: var(--primary-gradient);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    letter-spacing: -1px;
                }}
                .subtitle {{ color: var(--text-dim); margin-top: 10px; font-weight: 300; }}
                
                .grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); 
                    gap: 25px; 
                    margin-bottom: 50px;
                }}
                
                .card {{ 
                    background: var(--card-bg);
                    backdrop-filter: blur(10px);
                    border: 1px solid var(--border);
                    border-radius: 20px;
                    overflow: hidden;
                    transition: all 0.3s ease;
                }}
                .card:hover {{ transform: translateY(-8px); border-color: rgba(255,255,255,0.2); box-shadow: 0 20px 40px rgba(0,0,0,0.4); }}
                
                .card-header {{ 
                    padding: 20px; 
                    background: rgba(0,0,0,0.2); 
                    display: flex; 
                    justify-content: space-between; 
                    align-items: center;
                    border-bottom: 1px solid var(--border);
                }}
                .account-name {{ font-weight: 600; font-size: 1.2rem; }}
                .status-badge {{ 
                    padding: 5px 12px; 
                    border-radius: 30px; 
                    font-size: 0.75rem; 
                    font-weight: 600; 
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}
                .status-valid {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }}
                .status-expired {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
                .status-unknown {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
                
                .card-body {{ padding: 20px; }}
                .info-row {{ display: flex; justify-content: space-between; margin-bottom: 12px; font-size: 0.9rem; }}
                .info-row span {{ color: var(--text-dim); }}
                .info-row code {{ background: rgba(0,0,0,0.3); padding: 2px 8px; border-radius: 4px; color: #fff; font-family: monospace; }}
                
                .card-actions {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 20px; }}
                .btn {{ 
                    border: none; 
                    padding: 12px; 
                    border-radius: 12px; 
                    cursor: pointer; 
                    font-weight: 600; 
                    font-family: 'Outfit', sans-serif;
                    transition: all 0.2s ease;
                    text-align: center;
                    text-decoration: none;
                    font-size: 0.9rem;
                }}
                .btn-primary {{ background: rgba(255,255,255,0.05); color: white; border: 1px solid var(--border); }}
                .btn-primary:hover {{ background: rgba(255,255,255,0.15); }}
                .btn-auto {{ background: var(--primary-gradient); color: white; box-shadow: 0 4px 15px rgba(131, 58, 180, 0.3); }}
                .btn-auto:hover {{ opacity: 0.9; transform: scale(1.02); }}
                
                .form-section {{ 
                    background: var(--card-bg);
                    backdrop-filter: blur(10px);
                    padding: 30px; 
                    border-radius: 24px; 
                    border: 1px solid var(--border);
                }}
                .form-section h2 {{ margin-top: 0; font-weight: 600; font-size: 1.5rem; }}
                .form-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; }}
                .form-group {{ margin-bottom: 10px; }}
                label {{ display: block; margin-bottom: 8px; color: var(--text-dim); font-size: 0.85rem; font-weight: 400; }}
                input {{ 
                    width: 100%; 
                    padding: 14px; 
                    border-radius: 12px; 
                    border: 1px solid var(--border); 
                    background: rgba(15, 23, 42, 0.6); 
                    color: white; 
                    box-sizing: border-box;
                    font-family: 'Outfit', sans-serif;
                    transition: border-color 0.3s;
                }}
                input:focus {{ outline: none; border-color: #833ab4; background: rgba(15, 23, 42, 0.9); }}
                .submit-btn {{ 
                    width: 100%; 
                    margin-top: 25px; 
                    padding: 16px; 
                    font-size: 1.1rem;
                    background: var(--primary-gradient);
                }}
                .btn-refresh {{
                    margin-top: 16px;
                    padding: 10px 24px;
                    background: rgba(255,255,255,0.07);
                    color: var(--text);
                    border: 1px solid var(--border);
                    font-size: 0.95rem;
                    letter-spacing: 0.5px;
                }}
                .btn-refresh:hover {{ background: rgba(255,255,255,0.15); }}
                .btn-wide {{ width: 100%; background: var(--primary-gradient); color: white; box-shadow: 0 4px 15px rgba(131, 58, 180, 0.3); }}
                .btn-wide:hover {{ opacity: 0.9; }}
                .auth-note {{ color: var(--text-dim); font-size: 0.8rem; text-align: center; margin: 8px 0 0 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>UPSTOX AUTH CLOUD</h1>
                    <p class="subtitle">Multi-Account Centralized Authentication Service</p>
                    <button onclick="window.location.href = (window.location.pathname + '?r=' + Date.now())" class="btn btn-refresh">&#x21bb; Refresh Status</button>
                </header>
                
                <div class="grid">{cards}</div>
                
                <div class="form-section">
                    <h2>Add New Account</h2>
                    <form action="add-account" method="POST">
                        <div class="form-grid">
                            <div class="form-group"><label>Account ID</label><input type="text" name="account_id" placeholder="e.g. Account_1" required></div>
                            <div class="form-group"><label>API Key</label><input type="text" name="api_key" required></div>
                            <div class="form-group"><label>API Secret</label><input type="password" name="api_secret" required></div>
                            <div class="form-group"><label>6-Digit PIN</label><input type="password" name="pin" maxlength="6" placeholder="Auto-entry PIN"></div>
                            <div class="form-group"><label>Phone Number</label><input type="text" name="phone" placeholder="Mobile for OTP"></div>
                            <div class="form-group"><label>Redirect URI</label><input type="text" name="redirect_uri" value="https://alertsv03.in/token-manager/oauth/callback"></div>
                        </div>
                        <button type="submit" class="btn submit-btn btn-auto">Save & Initialize Account</button>
                    </form>
                </div>
            </div>
            <script>
                function startAuth(accId, apiKey, redirectUri) {{
                    const url = `https://api.upstox.com/v2/login/authorization/dialog?client_id=${{apiKey}}&redirect_uri=${{encodeURIComponent(redirectUri)}}&response_type=code&state=${{accId}}`;
                    window.location.href = url;
                }}
            </script>
        </body>
        </html>
        """

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

if __name__ == "__main__":
    manager = UpstoxAuthManager()
    port = 8000
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])
            
    server_address = ("", port)
    httpd = ThreadingHTTPServer(server_address, AuthHandler)
    httpd.manager = manager
    
    shutdown_called = False
    def signal_handler(sig, frame):
        global shutdown_called
        if shutdown_called:
            return
        shutdown_called = True
        logger.info("Graceful shutdown initiated...")
        manager.stop_event.set()
        
        # Start a thread to force exit if shutdown takes too long
        def force_exit():
            time.sleep(2)
            logger.info("Forcing exit...")
            os._exit(0)
        
        threading.Thread(target=force_exit, daemon=True).start()
        
        httpd.shutdown()
        logger.info("Service stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Allow address reuse (solves "Address already in use" on quick restart)
    httpd.allow_reuse_address = True
    
    logger.info(f"Auth Service running on http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
