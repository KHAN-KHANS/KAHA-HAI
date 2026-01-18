import random
import string
import json
import time
import requests
import uuid
import base64
import io
import struct
import sys
import os
import re

# ==========================================
# COLORS AND STYLING
# ==========================================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"

def animated_print(text, delay=0.01, color=GREEN):
    """Prints text with a typewriter animation effect."""
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(duration=3, text="PLEASE WAIT..."):
    """Displays a professional loading animation."""
    chars = ["⠙", "⠘", "⠰", "⠴", "⠤", "⠦", "⠆", "⠃", "⠋", "⠉"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in chars:
            sys.stdout.write(f"\r{CYAN}[{char}] {BOLD}{text}{RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write("\r" + " " * 50 + "\r")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_logo():
    # Enhanced Stylish Logo
    logo_lines = [
            "     ███╗   ██╗ █████╗ ██████╗ ███████╗███████╗███╗   ███╗",
            "     ████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝████╗ ████║",
            "     ██╔██╗ ██║███████║██║  ██║█████╗  █████╗  ██╔████╔██║",
            "     ██║╚██╗██║██╔══██║██║  ██║██╔══╝  ██╔══╝  ██║╚██╔╝██║",
            "     ██║ ╚████║██║  ██║██████╔╝███████╗███████╗██║ ╚═╝ ██║",
            "     ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝",
            "                [ TOKEN GRENADE V7 TOOL v2.2 ]             ",
            "             [ PASSWORD RECOVERY ENABLED ]                "
    ]
    
    colors = [CYAN, BLUE, GREEN, YELLOW, RED, MAGENTA]
    for line in logo_lines:
        color = random.choice(colors)
        print(color + BOLD + line + RESET)
        time.sleep(0.02)
    print(GREEN + "═" * 62 + RESET)

# ==========================================
# CRYPTO CHECK
# ==========================================
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ImportError:
    print(f"{GREEN}Error: 'pycryptodome' module not found.{RESET}")
    print(f"{YELLOW}Run: pip install pycryptodome{RESET}")
    exit()

# ==========================================
# PASSWORD RECOVERY SYSTEM
# ==========================================

class FacebookPasswordRecovery:
    """Handles Facebook password recovery and reset"""
    
    @staticmethod
    def identify_user(email_or_phone):
        """Identify user for password recovery"""
        try:
            url = "https://b-graph.facebook.com/auth/identify_user"
            params = {
                "format": "json",
                "email": email_or_phone,
                "method": "auth.createSession",
                "client_country_code": "US",
                "fb_api_req_friendly_name": "authIdentifyUser",
                "fb_api_caller_class": "com.facebook.auth.login.AuthOperations",
                "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
            }
            
            response = requests.post(url, params=params)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def send_recovery_code(email_or_phone):
        """Send password recovery code"""
        try:
            url = "https://b-graph.facebook.com/auth/send_password_reset_code"
            params = {
                "format": "json",
                "email": email_or_phone,
                "method": "auth.sendPasswordResetCode",
                "client_country_code": "US",
                "fb_api_req_friendly_name": "authSendPasswordResetCode",
                "fb_api_caller_class": "com.facebook.auth.login.AuthOperations",
                "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
            }
            
            response = requests.post(url, params=params)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def verify_recovery_code(email_or_phone, code):
        """Verify recovery code"""
        try:
            url = "https://b-graph.facebook.com/auth/verify_password_reset_code"
            params = {
                "format": "json",
                "email": email_or_phone,
                "code": code,
                "method": "auth.verifyPasswordResetCode",
                "client_country_code": "US",
                "fb_api_req_friendly_name": "authVerifyPasswordResetCode",
                "fb_api_caller_class": "com.facebook.auth.login.AuthOperations",
                "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
            }
            
            response = requests.post(url, params=params)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def reset_password(email_or_phone, code, new_password):
        """Reset password with recovery code"""
        try:
            url = "https://b-graph.facebook.com/auth/reset_password"
            params = {
                "format": "json",
                "email": email_or_phone,
                "code": code,
                "new_password": new_password,
                "method": "auth.resetPassword",
                "client_country_code": "US",
                "fb_api_req_friendly_name": "authResetPassword",
                "fb_api_caller_class": "com.facebook.auth.login.AuthOperations",
                "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
            }
            
            response = requests.post(url, params=params)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

# ==========================================
# PERMISSION MANAGER
# ==========================================

class FacebookPermissionManager:
    """Manages Facebook app permissions automatically"""
    
    @staticmethod
    def get_all_permissions(access_token):
        """Get all available permissions for the token"""
        try:
            url = "https://graph.facebook.com/me/permissions"
            params = {
                "access_token": access_token
            }
            
            response = requests.get(url, params=params)
            data = response.json()
            
            if "data" in data:
                return [perm["permission"] for perm in data["data"] if perm["status"] == "granted"]
            return []
        except Exception:
            return []
    
    @staticmethod
    def request_permissions(access_token, permissions):
        """Request additional permissions"""
        try:
            # List of all possible permissions
            all_permissions = [
                "email", "public_profile", "user_friends", "user_about_me",
                "user_actions.books", "user_actions.fitness", "user_actions.music",
                "user_actions.news", "user_actions.video", "user_activities",
                "user_birthday", "user_education_history", "user_events",
                "user_games_activity", "user_groups", "user_hometown",
                "user_likes", "user_location", "user_managed_groups",
                "user_photos", "user_posts", "user_relationships",
                "user_relationship_details", "user_religion_politics",
                "user_status", "user_tagged_places", "user_videos",
                "user_website", "user_work_history", "read_custom_friendlists",
                "read_insights", "read_audience_network_insights",
                "read_page_mailboxes", "manage_pages", "publish_pages",
                "publish_actions", "rsvp_event", "pages_show_list",
                "pages_manage_cta", "pages_manage_instant_articles",
                "ads_read", "ads_management", "business_management",
                "pages_messaging", "pages_messaging_phone_number",
                "pages_messaging_subscriptions", "instagram_basic",
                "instagram_manage_comments", "instagram_manage_insights"
            ]
            
            # Request each permission
            granted_permissions = []
            for perm in all_permissions:
                try:
                    # Try to request permission through login review
                    url = f"https://graph.facebook.com/v12.0/me/permissions"
                    data = {
                        "permission": perm,
                        "access_token": access_token
                    }
                    response = requests.post(url, data=data)
                    if response.status_code == 200:
                        granted_permissions.append(perm)
                except:
                    continue
            
            return granted_permissions
        except Exception:
            return []
    
    @staticmethod
    def get_extended_token(access_token):
        """Get long-lived access token"""
        try:
            url = "https://graph.facebook.com/v12.0/oauth/access_token"
            params = {
                "grant_type": "fb_exchange_token",
                "client_id": "350685531728",
                "client_secret": "62f8ce9f74b12f84c123cc23437a4a32",
                "fb_exchange_token": access_token
            }
            
            response = requests.get(url, params=params)
            data = response.json()
            
            if "access_token" in data:
                return data["access_token"]
            return access_token
        except Exception:
            return access_token

# ==========================================
# PASSWORD GENERATOR
# ==========================================

class PasswordGenerator:
    """Generates strong passwords"""
    
    @staticmethod
    def generate_strong_password(length=12):
        """Generate a strong random password"""
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        password = ''.join(random.choice(characters) for _ in range(length))
        return password
    
    @staticmethod
    def check_password_strength(password):
        """Check password strength"""
        score = 0
        if len(password) >= 8: score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*()" for c in password): score += 1
        
        if score == 5:
            return "Strong"
        elif score >= 3:
            return "Medium"
        else:
            return "Weak"

# ==========================================
# CORE CLASSES
# ==========================================

class FacebookPasswordEncryptor:
    @staticmethod
    def get_public_key():
        try:
            url = 'https://b-graph.facebook.com/pwd_key_fetch'
            params = {
                'version': '2',
                'flow': 'CONTROLLER_INITIALIZATION',
                'method': 'GET',
                'fb_api_req_friendly_name': 'pwdKeyFetch',
                'fb_api_caller_class': 'com.facebook.auth.login.AuthOperations',
                'access_token': '438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28'
            }
            response = requests.post(url, params=params).json()
            return response.get('public_key'), str(response.get('key_id', '25'))
        except Exception as e:
            raise Exception(f"Public key fetch error: {e}")

    @staticmethod
    def encrypt(password, public_key=None, key_id="25"):
        if public_key is None:
            public_key, key_id = FacebookPasswordEncryptor.get_public_key()

        try:
            rand_key = get_random_bytes(32)
            iv = get_random_bytes(12)
            
            pubkey = RSA.import_key(public_key)
            cipher_rsa = PKCS1_v1_5.new(pubkey)
            encrypted_rand_key = cipher_rsa.encrypt(rand_key)
            
            cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
            current_time = int(time.time())
            cipher_aes.update(str(current_time).encode("utf-8"))
            encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode("utf-8"))
            
            buf = io.BytesIO()
            buf.write(bytes([1, int(key_id)]))
            buf.write(iv)
            buf.write(struct.pack("<h", len(encrypted_rand_key)))
            buf.write(encrypted_rand_key)
            buf.write(auth_tag)
            buf.write(encrypted_passwd)
            
            encoded = base64.b64encode(buf.getvalue()).decode("utf-8")
            return f"#PWD_FB4A:2:{current_time}:{encoded}"
        except Exception as e:
            raise Exception(f"Encryption error: {e}")


class FacebookAppTokens:
    APPS = {
        'FB_ANDROID': {'name': 'Facebook For Android', 'app_id': '350685531728'},
        'CONVO_TOKEN V7': {'name': 'Facebook Messenger For Android', 'app_id': '256002347743983'},
        'FB_LITE': {'name': 'Facebook For Lite', 'app_id': '275254692598279'},
        'MESSENGER_LITE': {'name': 'Facebook Messenger For Lite', 'app_id': '200424423651082'},
        'ADS_MANAGER_ANDROID': {'name': 'Ads Manager App For Android', 'app_id': '438142079694454'},
        'PAGES_MANAGER_ANDROID': {'name': 'Pages Manager For Android', 'app_id': '121876164619130'},
        'INSTAGRAM_ANDROID': {'name': 'Instagram For Android', 'app_id': '567067343352427'},
        'WHATSAPP_BUSINESS': {'name': 'WhatsApp Business', 'app_id': '306645788174'}
    }
    
    @staticmethod
    def get_app_id(app_key):
        app = FacebookAppTokens.APPS.get(app_key)
        return app['app_id'] if app else None
    
    @staticmethod
    def get_all_app_keys():
        return list(FacebookAppTokens.APPS.keys())
    
    @staticmethod
    def extract_token_prefix(token):
        for i, char in enumerate(token):
            if char.islower():
                return token[:i]
        return token


class FacebookLogin:
    API_URL = "https://b-graph.facebook.com/auth/login"
    ACCESS_TOKEN = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
    API_KEY = "882a8490361da98702bf97a021ddc14d"
    SIG = "214049b9f17c38bd767de53752b53946"
    
    BASE_HEADERS = {
        "content-type": "application/x-www-form-urlencoded",
        "x-fb-net-hni": "45201",
        "zero-rated": "0",
        "x-fb-sim-hni": "45201",
        "x-fb-connection-quality": "EXCELLENT",
        "x-fb-friendly-name": "authenticate",
        "x-fb-connection-bandwidth": "78032897",
        "x-tigon-is-retry": "False",
        "authorization": "OAuth null",
        "x-fb-connection-type": "WIFI",
        "x-fb-device-group": "3342",
        "priority": "u=3,i",
        "x-fb-http-engine": "Liger",
        "x-fb-client-ip": "True",
        "x-fb-server-cluster": "True"
    }
    
    def __init__(self, uid_phone_mail, password, machine_id=None, convert_token_to=None, convert_all_tokens=False):
        self.uid_phone_mail = uid_phone_mail
        
        if password.startswith("#PWD_FB4A"):
            self.password = password
        else:
            animated_print("[*] ENCRYPTING PASSWORD...", color=CYAN)
            loading_animation(2, "ENCRYPTING PASSWORD...")
            self.password = FacebookPasswordEncryptor.encrypt(password)
        
        if convert_all_tokens:
            self.convert_token_to = FacebookAppTokens.get_all_app_keys()
        elif convert_token_to:
            self.convert_token_to = convert_token_to if isinstance(convert_token_to, list) else [convert_token_to]
        else:
            self.convert_token_to = []
        
        self.session = requests.Session()
        
        self.device_id = str(uuid.uuid4())
        self.adid = str(uuid.uuid4())
        self.secure_family_device_id = str(uuid.uuid4())
        self.machine_id = machine_id if machine_id else self._generate_machine_id()
        self.jazoest = ''.join(random.choices(string.digits, k=5))
        self.sim_serial = ''.join(random.choices(string.digits, k=20))
        
        self.headers = self._build_headers()
        self.data = self._build_data()
    
    @staticmethod
    def _generate_machine_id():
        return ''.join(random.choices(string.ascii_letters + string.digits, k=24))
    
    def _build_headers(self):
        headers = self.BASE_HEADERS.copy()
        headers.update({
            "x-fb-request-analytics-tags": '{"network_tags":{"product":"350685531728","retry_attempt":"0"},"application_tags":"unknown"}',
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; 23113RKC6C Build/PQ3A.190705.08211809) [FBAN/FB4A;FBAV/417.0.0.33.65;FBPN/com.facebook.katana;FBLC/vi_VN;FBBV/480086274;FBCR/MobiFone;FBMF/Redmi;FBBD/Redmi;FBDV/23113RKC6C;FBSV/9;FBCA/x86:armeabi-v7a;FBDM/{density=1.5,width=1280,height=720};FB_FW/1;FBRV/0;]"
        })
        return headers
    
    def _build_data(self):
        base_data = {
            "format": "json",
            "email": self.uid_phone_mail,
            "password": self.password,
            "credentials_type": "password",
            "generate_session_cookies": "1",
            "locale": "vi_VN",
            "client_country_code": "VN",
            "api_key": self.API_KEY,
            "access_token": self.ACCESS_TOKEN
        }
        
        base_data.update({
            "adid": self.adid,
            "device_id": self.device_id,
            "generate_analytics_claim": "1",
            "community_id": "",
            "linked_guest_account_userid": "",
            "cpl": "true",
            "try_num": "1",
            "family_device_id": self.device_id,
            "secure_family_device_id": self.secure_family_device_id,
            "sim_serials": f'["{self.sim_serial}"]',
            "openid_flow": "android_login",
            "openid_provider": "google",
            "openid_tokens": "[]",
            "account_switcher_uids": f'["{self.uid_phone_mail}"]',
            "fb4a_shared_phone_cpl_experiment": "fb4a_shared_phone_nonce_cpl_at_risk_v3",
            "fb4a_shared_phone_cpl_group": "enable_v3_at_risk",
            "enroll_misauth": "false",
            "error_detail_type": "button_with_disabled",
            "source": "login",
            "machine_id": self.machine_id,
            "jazoest": self.jazoest,
            "meta_inf_fbmeta": "V2_UNTAGGED",
            "advertiser_id": self.adid,
            "encrypted_msisdn": "",
            "currently_logged_in_userid": "0",
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "Fb4aAuthHandler",
            "sig": self.SIG
        })
        
        return base_data
    
    def _convert_token(self, access_token, target_app):
        try:
            app_id = FacebookAppTokens.get_app_id(target_app)
            if not app_id:
                return None
            
            response = requests.post(
                'https://api.facebook.com/method/auth.getSessionforApp',
                data={
                    'access_token': access_token,
                    'format': 'json',
                    'new_app_id': app_id,
                    'generate_session_cookies': '1'
                }
            )
            
            result = response.json()
            
            if 'access_token' in result:
                token = result['access_token']
                prefix = FacebookAppTokens.extract_token_prefix(token)
                
                cookies_dict = {}
                cookies_string = ""
                
                if 'session_cookies' in result:
                    for cookie in result['session_cookies']:
                        cookies_dict[cookie['name']] = cookie['value']
                        cookies_string += f"{cookie['name']}={cookie['value']}; "
                
                return {
                    'token_prefix': prefix,
                    'access_token': token,
                    'cookies': {
                        'dict': cookies_dict,
                        'string': cookies_string.rstrip('; ')
                    }
                }
            return None     
        except:
            return None
    
    def _parse_success_response(self, response_json):
        original_token = response_json.get('access_token')
        original_prefix = FacebookAppTokens.extract_token_prefix(original_token)
        
        result = {
            'success': True,
            'original_token': {
                'token_prefix': original_prefix,
                'access_token': original_token
            },
            'cookies': {}
        }
        
        if 'session_cookies' in response_json:
            cookies_dict = {}
            cookies_string = ""
            for cookie in response_json['session_cookies']:
                cookies_dict[cookie['name']] = cookie['value']
                cookies_string += f"{cookie['name']}={cookie['value']}; "
            result['cookies'] = {
                'dict': cookies_dict,
                'string': cookies_string.rstrip('; ')
            }
        
        if self.convert_token_to:
            result['converted_tokens'] = {}
            for target_app in self.convert_token_to:
                converted = self._convert_token(original_token, target_app)
                if converted:
                    result['converted_tokens'][target_app] = converted
        
        return result
    
    def _show_2fa_menu(self, error_data):
        print("\n" + YELLOW + "═" * 62 + RESET)
        animated_print("         ⚠️  2-FACTOR AUTHENTICATION REQUIRED  ⚠️", color=RED)
        print(YELLOW + "═" * 62 + RESET)
        
        print(f"\n{MAGENTA}Username/Email: {CYAN}{self.uid_phone_mail}{RESET}")
        print(f"{MAGENTA}User ID: {CYAN}{error_data.get('uid', 'N/A')}{RESET}")
        print("\n" + GREEN + "─" * 62 + RESET)
        
        animated_print("📱 FACEBOOK SENT A 6-DIGIT CODE TO YOUR DEVICE:", color=CYAN)
        print("\n" + YELLOW + "┌─────────────────────────────────────────────────────────────┐")
        print("│            SELECT VERIFICATION METHOD:                    │")
        print("├─────────────────────────────────────────────────────────────┤")
        print("│  [1] 📲 Get Code via WhatsApp                              │")
        print("│  [2] ✉️  Get Code via SMS                                   │")
        print("│  [3] 📧 Get Code via Email                                 │")
        print("│  [0] ❌ Cancel & Exit                                       │")
        print("└─────────────────────────────────────────────────────────────┘" + RESET)
        
        while True:
            try:
                choice = input(f"\n{YELLOW}➤ SELECT OPTION [1/2/3/0]: {RESET}").strip()
                
                if choice == '0':
                    return {'success': False, 'error': '2FA Verification Cancelled'}
                
                if choice in ['1', '2', '3']:
                    methods = {
                        '1': 'WhatsApp',
                        '2': 'SMS',
                        '3': 'Email'
                    }
                    
                    animated_print(f"\n📤 SENDING CODE VIA {methods[choice]}...", color=GREEN)
                    loading_animation(3, f"SENDING CODE VIA {methods[choice]}...")
                    
                    print(f"\n{CYAN}✓ Code sent successfully via {methods[choice]}{RESET}")
                    print(f"{YELLOW}⚠️  Check your {methods[choice]} for the 6-digit code{RESET}")
                    print(GREEN + "─" * 62 + RESET)
                    
                    # Get the code from user
                    max_attempts = 3
                    for attempt in range(1, max_attempts + 1):
                        try:
                            print(f"\n{YELLOW}↳ ATTEMPT {attempt}/{max_attempts}{RESET}")
                            otp_code = input(f"{GREEN}➤ ENTER 6-DIGIT CODE: {RESET}").strip()
                            
                            if not otp_code.isdigit() or len(otp_code) != 6:
                                print(f"{RED}✗ Invalid code format. Please enter 6 digits.{RESET}")
                                continue
                                
                            print(f"{CYAN}✓ CODE ENTERED: {otp_code}{RESET}")
                            loading_animation(2, "VERIFYING CODE...")
                            
                            # Verify the code with Facebook
                            result = self._verify_2fa_code(otp_code, error_data)
                            if result:
                                return result
                            else:
                                if attempt < max_attempts:
                                    print(f"{RED}✗ Invalid code. Try again.{RESET}")
                                else:
                                    print(f"{RED}✗ Maximum attempts reached.{RESET}")
                                    return {'success': False, 'error': 'Too many failed attempts'}
                                    
                        except KeyboardInterrupt:
                            return {'success': False, 'error': '2FA Verification Cancelled'}
                    
                else:
                    print(f"{RED}✗ Invalid option. Please choose 1, 2, 3, or 0.{RESET}")
                    
            except KeyboardInterrupt:
                return {'success': False, 'error': '2FA Verification Cancelled'}
    
    def _verify_2fa_code(self, otp_code, error_data):
        try:
            data_2fa = {
                'locale': 'vi_VN',
                'format': 'json',
                'email': self.uid_phone_mail,
                'device_id': self.device_id,
                'access_token': self.ACCESS_TOKEN,
                'generate_session_cookies': 'true',
                'generate_machine_id': '1',
                'twofactor_code': otp_code,
                'credentials_type': 'two_factor',
                'error_detail_type': 'button_with_disabled',
                'first_factor': error_data['login_first_factor'],
                'password': self.password,
                'userid': error_data['uid'],
                'machine_id': error_data['login_first_factor']
            }
            
            response = self.session.post(self.API_URL, data=data_2fa, headers=self.headers)
            response_json = response.json()
            
            if 'access_token' in response_json:
                print(f"\n{GREEN}✓ CODE VERIFIED SUCCESSFULLY!{RESET}")
                loading_animation(2, "GENERATING TOKENS...")
                return self._parse_success_response(response_json)
            elif 'error' in response_json:
                error_msg = response_json['error'].get('message', 'OTP Verification Failed')
                return None
            else:
                return None
                
        except Exception as e:
            print(f"{RED}✗ Verification error: {str(e)}{RESET}")
            return None
    
    def login(self):
        try:
            animated_print("\n[*] INITIATING LOGIN PROCESS...", color=CYAN)
            loading_animation(2, "CONNECTING TO FACEBOOK...")
            
            response = self.session.post(self.API_URL, headers=self.headers, data=self.data)
            response_json = response.json()
            
            if 'access_token' in response_json:
                print(f"\n{GREEN}✓ LOGIN SUCCESSFUL!{RESET}")
                loading_animation(2, "PARSING RESPONSE...")
                return self._parse_success_response(response_json)
            
            if 'error' in response_json:
                error_data = response_json.get('error', {}).get('error_data', {})
                
                if 'login_first_factor' in error_data and 'uid' in error_data:
                    return self._show_2fa_menu(error_data)
                
                error_msg = response_json['error'].get('message', 'Unknown error')
                error_user_msg = response_json['error'].get('error_user_msg', '')
                
                return {
                    'success': False,
                    'error': error_msg,
                    'error_user_msg': error_user_msg
                }
            
            return {'success': False, 'error': 'Unknown response format'}
            
        except json.JSONDecodeError:
            return {'success': False, 'error': 'Invalid JSON response from Facebook'}
        except Exception as e:
            return {'success': False, 'error': f'Connection error: {str(e)}'}

# ==========================================
# PASSWORD FORGET/RECOVERY FUNCTION
# ==========================================

def password_recovery_system():
    """Handle password forget/recovery"""
    print(f"\n{RED}═" * 62)
    animated_print("          🔓 PASSWORD RECOVERY SYSTEM", color=RED)
    print("═" * 62 + RESET)
    
    print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
    print("│                 RECOVERY OPTIONS                         │")
    print("├─────────────────────────────────────────────────────────────┤")
    print("│  [1] 📧 I Forgot My Password                                │")
    print("│  [2] 🔑 I Know My Password (Continue Login)                │")
    print("│  [0] ❌ Exit Tool                                           │")
    print("└─────────────────────────────────────────────────────────────┘" + RESET)
    
    choice = input(f"\n{YELLOW}➤ SELECT OPTION [1/2/0]: {RESET}").strip()
    
    if choice == '0':
        print(f"\n{RED}Exiting tool...{RESET}")
        time.sleep(2)
        exit()
    
    if choice == '1':
        return handle_password_recovery()
    
    return None  # Continue with normal login

def handle_password_recovery():
    """Handle the password recovery process"""
    print(f"\n{BLUE}═" * 62)
    animated_print("         📧 PASSWORD RESET REQUEST", color=BLUE)
    print("═" * 62 + RESET)
    
    email_or_phone = input(f"\n{GREEN}➤ ENTER EMAIL/PHONE NUMBER FOR RECOVERY: {RESET}").strip()
    
    if not email_or_phone:
        print(f"{RED}✗ Email/Phone is required{RESET}")
        return None
    
    # Step 1: Identify user
    animated_print("\n[*] IDENTIFYING USER ACCOUNT...", color=CYAN)
    loading_animation(3, "CHECKING ACCOUNT...")
    
    recovery = FacebookPasswordRecovery()
    identify_result = recovery.identify_user(email_or_phone)
    
    if "error" in identify_result:
        print(f"{RED}✗ Unable to identify account. Please check email/phone.{RESET}")
        return None
    
    print(f"{GREEN}✓ Account identified successfully{RESET}")
    
    # Step 2: Send recovery code
    animated_print("\n[*] SENDING RECOVERY CODE...", color=CYAN)
    loading_animation(4, "SENDING CODE...")
    
    send_result = recovery.send_recovery_code(email_or_phone)
    
    if "error" in send_result:
        print(f"{RED}✗ Failed to send recovery code. Try again later.{RESET}")
        return None
    
    print(f"{GREEN}✓ Recovery code sent successfully{RESET}")
    print(f"{YELLOW}⚠️  Check your email/phone for the 6-digit code{RESET}")
    
    # Step 3: Get recovery code from user
    print(f"\n{BLUE}─" * 62 + RESET)
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        print(f"\n{YELLOW}↳ ATTEMPT {attempt}/{max_attempts}{RESET}")
        recovery_code = input(f"{GREEN}➤ ENTER 6-DIGIT RECOVERY CODE: {RESET}").strip()
        
        if not recovery_code.isdigit() or len(recovery_code) != 6:
            print(f"{RED}✗ Invalid code format. Please enter 6 digits.{RESET}")
            continue
        
        # Step 4: Verify recovery code
        animated_print("\n[*] VERIFYING RECOVERY CODE...", color=CYAN)
        loading_animation(3, "VERIFYING...")
        
        verify_result = recovery.verify_recovery_code(email_or_phone, recovery_code)
        
        if "error" in verify_result:
            print(f"{RED}✗ Invalid recovery code. Try again.{RESET}")
            if attempt < max_attempts:
                continue
            else:
                print(f"{RED}✗ Maximum attempts reached.{RESET}")
                return None
        
        print(f"{GREEN}✓ Recovery code verified successfully{RESET}")
        
        # Step 5: Generate and set new password
        print(f"\n{BLUE}═" * 62)
        animated_print("         🔑 CREATE NEW PASSWORD", color=BLUE)
        print("═" * 62 + RESET)
        
        print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
        print("│             PASSWORD OPTIONS                            │")
        print("├─────────────────────────────────────────────────────────────┤")
        print("│  [1] 🔐 Use Auto-Generated Strong Password               │")
        print("│  [2] ✏️  Enter My Own Password                            │")
        print("└─────────────────────────────────────────────────────────────┘" + RESET)
        
        pass_choice = input(f"\n{YELLOW}➤ SELECT OPTION [1/2]: {RESET}").strip()
        
        if pass_choice == '1':
            # Auto-generate strong password
            new_password = PasswordGenerator.generate_strong_password()
            strength = PasswordGenerator.check_password_strength(new_password)
            print(f"\n{GREEN}✓ Auto-generated password: {new_password}{RESET}")
            print(f"{YELLOW}Password Strength: {strength}{RESET}")
            
            # Show password for user to note
            print(f"\n{MAGENTA}⚠️  IMPORTANT: Please note down your new password:{RESET}")
            print(f"{CYAN}{'='*30}")
            print(f"NEW PASSWORD: {new_password}")
            print(f"{'='*30}{RESET}")
            
            confirm = input(f"\n{YELLOW}➤ Have you noted the password? (y/n): {RESET}").strip().lower()
            if confirm != 'y':
                print(f"{RED}✗ Password reset cancelled{RESET}")
                return None
                
        elif pass_choice == '2':
            # User enters own password
            while True:
                new_password = input(f"\n{GREEN}➤ ENTER NEW PASSWORD: {RESET}").strip()
                confirm_password = input(f"{GREEN}➤ CONFIRM NEW PASSWORD: {RESET}").strip()
                
                if not new_password:
                    print(f"{RED}✗ Password cannot be empty{RESET}")
                    continue
                
                if new_password != confirm_password:
                    print(f"{RED}✗ Passwords do not match. Try again.{RESET}")
                    continue
                
                strength = PasswordGenerator.check_password_strength(new_password)
                if strength == "Weak":
                    print(f"{YELLOW}⚠️  Password is weak. Consider using a stronger password.{RESET}")
                    use_weak = input(f"{YELLOW}➤ Use this weak password anyway? (y/n): {RESET}").strip().lower()
                    if use_weak != 'y':
                        continue
                
                break
        else:
            print(f"{RED}✗ Invalid option{RESET}")
            return None
        
        # Step 6: Reset password
        animated_print("\n[*] RESETTING PASSWORD...", color=CYAN)
        loading_animation(4, "UPDATING PASSWORD...")
        
        reset_result = recovery.reset_password(email_or_phone, recovery_code, new_password)
        
        if "error" in reset_result:
            print(f"{RED}✗ Failed to reset password. Try again.{RESET}")
            return None
        
        print(f"\n{GREEN}═" * 62)
        animated_print("         ✅ PASSWORD RESET SUCCESSFUL!", color=GREEN)
        print("═" * 62 + RESET)
        
        print(f"\n{YELLOW}Your password has been successfully reset!")
        print(f"Please use your new password to login.{RESET}")
        
        # Return credentials for auto-login
        return {
            'email': email_or_phone,
            'password': new_password,
            'recovery_used': True
        }
    
    return None

# ==========================================
# PERMISSION HANDLER FUNCTION
# ==========================================

def handle_permissions(access_token):
    """Automatically handle permissions"""
    print(f"\n{BLUE}═" * 62)
    animated_print("         🔧 AUTO-PERMISSION MANAGER", color=BLUE)
    print("═" * 62 + RESET)
    
    animated_print("[*] CHECKING CURRENT PERMISSIONS...", color=CYAN)
    loading_animation(3, "ANALYZING PERMISSIONS...")
    
    perm_manager = FacebookPermissionManager()
    
    # Get current permissions
    current_perms = perm_manager.get_all_permissions(access_token)
    
    if current_perms:
        print(f"\n{GREEN}✓ Current permissions: {len(current_perms)} granted{RESET}")
        print(f"{CYAN}{', '.join(current_perms[:10])}{'...' if len(current_perms) > 10 else ''}{RESET}")
    else:
        print(f"\n{YELLOW}⚠️  No permissions found or token restricted{RESET}")
    
    # Request additional permissions
    print(f"\n{YELLOW}[*] REQUESTING ADDITIONAL PERMISSIONS...{RESET}")
    loading_animation(4, "REQUESTING PERMISSIONS...")
    
    # Try to get extended token
    extended_token = perm_manager.get_extended_token(access_token)
    if extended_token != access_token:
        print(f"{GREEN}✓ Extended token obtained (60 days){RESET}")
        access_token = extended_token
    
    # Request all possible permissions
    requested_perms = perm_manager.request_permissions(access_token, [])
    
    if requested_perms:
        print(f"{GREEN}✓ {len(requested_perms)} permissions requested successfully{RESET}")
    else:
        print(f"{YELLOW}⚠️  Some permissions may require manual approval{RESET}")
    
    # Get updated permissions
    updated_perms = perm_manager.get_all_permissions(access_token)
    print(f"\n{CYAN}Total permissions after update: {len(updated_perms)}{RESET}")
    
    return access_token

# ==========================================
# MAIN MENU FUNCTION
# ==========================================

def show_main_menu():
    """Display main menu"""
    print(f"\n{WHITE}═" * 62)
    animated_print("              🚀 MAIN MENU - TOKEN GRENADE V7", color=WHITE)
    print("═" * 62 + RESET)
    
    print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
    print("│                 SELECT AN OPTION                         │")
    print("├─────────────────────────────────────────────────────────────┤")
    print("│  [1] 🔑 Login & Generate All Tokens                        │")
    print("│  [2] 🔓 Password Recovery (Forgot Password)                │")
    print("│  [3] 🔧 Check & Manage Token Permissions                   │")
    print("│  [4] 📊 View Saved Tokens                                  │")
    print("│  [5] 🛠️  Advanced Settings                                 │")
    print("│  [0] ❌ Exit                                                │")
    print("└─────────────────────────────────────────────────────────────┘" + RESET)

# ==========================================
# TOKEN SAVER FUNCTION
# ==========================================

def save_tokens_to_file(tokens_data, filename="facebook_tokens.txt"):
    """Save tokens to file"""
    try:
        with open(filename, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*60 + "\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Username: {tokens_data.get('username', 'N/A')}\n")
            f.write("="*60 + "\n\n")
            
            # Original token
            f.write("ORIGINAL TOKEN:\n")
            f.write(f"{tokens_data['original_token']['access_token']}\n\n")
            
            # Converted tokens
            if 'converted_tokens' in tokens_data:
                f.write("CONVERTED TOKENS:\n")
                for app, data in tokens_data['converted_tokens'].items():
                    f.write(f"\n{app}:\n")
                    f.write(f"{data['access_token']}\n")
            
            # Cookies
            if tokens_data['cookies'].get('string'):
                f.write("\nCOOKIES:\n")
                f.write(f"{tokens_data['cookies']['string']}\n")
            
            f.write("\n" + "="*60 + "\n\n")
        
        return True
    except Exception as e:
        print(f"{RED}✗ Error saving tokens: {e}{RESET}")
        return False

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    clear_screen()
    show_logo()
    
    while True:
        show_main_menu()
        
        choice = input(f"\n{YELLOW}➤ SELECT OPTION [0-5]: {RESET}").strip()
        
        if choice == '0':
            print(f"\n{RED}Exiting Token Grenade V7... Goodbye!{RESET}")
            time.sleep(2)
            break
        
        elif choice == '1':
            # Normal login
            print(f"\n{GREEN}═" * 62)
            animated_print("         🔑 LOGIN & TOKEN GENERATION", color=GREEN)
            print("═" * 62 + RESET)
            
            uid_phone_mail = input(f"\n{GREEN}➤ ENTER EMAIL/PHONE NUMBER: {RESET}").strip()
            password = input(f"{GREEN}➤ ENTER PASSWORD: {RESET}").strip()
            
            print(f"\n{BLUE}─" * 62 + RESET)
            
            # Initialize login
            fb_login = FacebookLogin(
                uid_phone_mail=uid_phone_mail,
                password=password,
                convert_all_tokens=True
            )
            
            # Attempt login
            result = fb_login.login()
            
            # Display results
            if result['success']:
                print(f"\n{GREEN}═" * 62)
                animated_print("         ✅ LOGIN SUCCESSFUL - TOKENS GENERATED", color=GREEN)
                print("═" * 62 + RESET)
                
                # Display original token
                print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
                print("│                    ORIGINAL TOKEN                          │")
                print("├─────────────────────────────────────────────────────────────┤{RESET}")
                print(f"{MAGENTA}TYPE: {CYAN}{result['original_token']['token_prefix']}{RESET}")
                print(f"{GREEN}{result['original_token']['access_token']}{RESET}")
                print(f"{YELLOW}└─────────────────────────────────────────────────────────────┘{RESET}")
                
                # Display converted tokens
                if 'converted_tokens' in result and result['converted_tokens']:
                    print(f"\n{CYAN}═" * 62)
                    animated_print("           🔄 CONVERTED APPLICATION TOKENS", color=CYAN)
                    print("═" * 62 + RESET)
                    
                    for app_key, token_data in result['converted_tokens'].items():
                        print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
                        print(f"│  APP: {app_key: <48}│")
                        print(f"│  TYPE: {token_data['token_prefix']: <48}│")
                        print("├─────────────────────────────────────────────────────────────┤{RESET}")
                        print(f"{GREEN}{token_data['access_token']}{RESET}")
                        print(f"{YELLOW}└─────────────────────────────────────────────────────────────┘{RESET}")
                
                # Display cookies
                if result['cookies'].get('string'):
                    print(f"\n{BLUE}═" * 62)
                    animated_print("           🍪 SESSION COOKIES (NETSCAPE FORMAT)", color=BLUE)
                    print("═" * 62 + RESET)
                    print(f"\n{MAGENTA}{result['cookies']['string']}{RESET}")
                
                # Auto handle permissions
                handle_permissions(result['original_token']['access_token'])
                
                # Save tokens to file
                save_result = save_tokens_to_file({
                    'username': uid_phone_mail,
                    **result
                })
                
                if save_result:
                    print(f"\n{GREEN}✓ Tokens saved to 'facebook_tokens.txt'{RESET}")
                
                # Success message
                print(f"\n{GREEN}═" * 62)
                animated_print("        🎉 ALL TOKENS SUCCESSFULLY GENERATED!", color=GREEN)
                animated_print("        💾 SAVE YOUR TOKENS SECURELY!", color=YELLOW)
                print("═" * 62 + RESET)
                
                input(f"\n{YELLOW}Press Enter to continue...{RESET}")
                
            else:
                print(f"\n{RED}═" * 62)
                animated_print("             ❌ LOGIN FAILED", color=RED)
                print("═" * 62 + RESET)
                
                print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
                print("│                     ERROR DETAILS                         │")
                print("├─────────────────────────────────────────────────────────────┤{RESET}")
                print(f"{MAGENTA}ERROR:{RESET} {RED}{result.get('error', 'Unknown error')}{RESET}")
                if result.get('error_user_msg'):
                    print(f"{MAGENTA}MESSAGE:{RESET} {YELLOW}{result.get('error_user_msg')}{RESET}")
                print(f"{YELLOW}└─────────────────────────────────────────────────────────────┘{RESET}")
                
                input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        
        elif choice == '2':
            # Password recovery
            recovery_result = handle_password_recovery()
            
            if recovery_result and recovery_result.get('recovery_used'):
                # Auto-login with new password
                print(f"\n{GREEN}═" * 62)
                animated_print("         🔄 AUTO-LOGIN AFTER PASSWORD RESET", color=GREEN)
                print("═" * 62 + RESET)
                
                fb_login = FacebookLogin(
                    uid_phone_mail=recovery_result['email'],
                    password=recovery_result['password'],
                    convert_all_tokens=True
                )
                
                login_result = fb_login.login()
                
                if login_result['success']:
                    # Display tokens
                    print(f"\n{GREEN}✓ AUTO-LOGIN SUCCESSFUL WITH NEW PASSWORD{RESET}")
                    print(f"{CYAN}Original Token: {login_result['original_token']['access_token'][:50]}...{RESET}")
                    
                    # Handle permissions
                    handle_permissions(login_result['original_token']['access_token'])
            
            input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        
        elif choice == '3':
            # Check permissions
            print(f"\n{BLUE}═" * 62)
            animated_print("         🔍 CHECK TOKEN PERMISSIONS", color=BLUE)
            print("═" * 62 + RESET)
            
            token = input(f"\n{GREEN}➤ ENTER ACCESS TOKEN: {RESET}").strip()
            
            if token:
                handle_permissions(token)
            else:
                print(f"{RED}✗ Token is required{RESET}")
            
            input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        
        elif choice == '4':
            # View saved tokens
            print(f"\n{MAGENTA}═" * 62)
            animated_print("         📁 VIEW SAVED TOKENS", color=MAGENTA)
            print("═" * 62 + RESET)
            
            try:
                with open("facebook_tokens.txt", 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content:
                        print(f"\n{CYAN}{content}{RESET}")
                    else:
                        print(f"{YELLOW}No saved tokens found.{RESET}")
            except FileNotFoundError:
                print(f"{YELLOW}No tokens file found. Generate tokens first.{RESET}")
            
            input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        
        elif choice == '5':
            # Advanced settings
            print(f"\n{CYAN}═" * 62)
            animated_print("         ⚙️  ADVANCED SETTINGS", color=CYAN)
            print("═" * 62 + RESET)
            
            print(f"\n{YELLOW}┌─────────────────────────────────────────────────────────────┐")
            print("│              ADVANCED OPTIONS                             │")
            print("├─────────────────────────────────────────────────────────────┤")
            print("│  [1] 🔄 Force Token Regeneration                           │")
            print("│  [2] 🧹 Clear Saved Tokens File                            │")
            print("│  [3] 📡 Test Connection to Facebook                        │")
            print("│  [4] 🔧 Debug Mode                                         │")
            print("│  [0] ↩️  Back to Main Menu                                  │")
            print("└─────────────────────────────────────────────────────────────┘" + RESET)
            
            adv_choice = input(f"\n{YELLOW}➤ SELECT OPTION: {RESET}").strip()
            
            if adv_choice == '2':
                confirm = input(f"\n{RED}➤ Are you sure you want to clear all saved tokens? (y/n): {RESET}").strip().lower()
                if confirm == 'y':
                    try:
                        with open("facebook_tokens.txt", 'w', encoding='utf-8') as f:
                            f.write("")
                        print(f"{GREEN}✓ All saved tokens cleared{RESET}")
                    except:
                        print(f"{RED}✗ Error clearing tokens{RESET}")
            
            input(f"\n{YELLOW}Press Enter to continue...{RESET}")
        
        else:
            print(f"\n{RED}✗ Invalid option. Please select 0-5.{RESET}")
            time.sleep(1)
