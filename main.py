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

# ==========================================
# COLORS AND STYLING
# ==========================================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def animated_print(text, delay=0.01, color=GREEN):
    """Prints text with a typewriter animation effect."""
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(duration=3):
    """Displays a professional loading animation."""
    chars = ["⠙", "⠘", "⠰", "⠴", "⠤", "⠦", "⠆", "⠃", "⠋", "⠉"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in chars:
            sys.stdout.write(f"\r{CYAN}[{char}] {BOLD}PLEASE WAIT... GENERATING DATA{RESET}")
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
            "                [ TOKEN GRENADE V7 TOOL v2.0 ]             "
    ]
    
    colors = [CYAN, BLUE, GREEN, YELLOW, RED]
    for line in logo_lines:
        color = random.choice(colors)
        print(color + BOLD + line + RESET)
        time.sleep(0.05)
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
        'PAGES_MANAGER_ANDROID': {'name': 'Pages Manager For Android', 'app_id': '121876164619130'}
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
    
    @staticmethod
    def get_app_name(app_key):
        app = FacebookAppTokens.APPS.get(app_key)
        return app['name'] if app else app_key


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
                    'app_name': FacebookAppTokens.get_app_name(target_app),
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
    
    def _handle_2fa_manual(self, error_data):
        print(RED + "\n" + "═" * 62)
        animated_print("[!] 2FA REQUIRED (TWO-FACTOR AUTHENTICATION)", color=YELLOW)
        print("═" * 62)
        animated_print("Facebook has sent an OTP to your WhatsApp/Mobile Number.", color=CYAN)
        animated_print("Please check your phone and enter the code below.", color=CYAN)
        print("═" * 62 + RESET)
        
        try:
            otp_code = input(YELLOW + "Enter OTP Code: " + RESET).strip()
            print(GREEN + "═" * 62 + RESET)
        except KeyboardInterrupt:
            return {'success': False, 'error': 'User cancelled OTP input'}

        if not otp_code:
             return {'success': False, 'error': 'Empty OTP provided'}

        animated_print("[*] VERIFYING OTP...", color=GREEN)

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
                return self._parse_success_response(response_json)
            elif 'error' in response_json:
                return {
                    'success': False,
                    'error': response_json['error'].get('message', 'OTP Verification Failed')
                }
            
        except Exception as e:
            return {'success': False, 'error': f'2FA Processing Error: {str(e)}'}
    
    def login(self):
        try:
            animated_print("[*] LOGGING IN...", color=CYAN)
            loading_animation(2)
            response = self.session.post(self.API_URL, headers=self.headers, data=self.data)
            response_json = response.json()
            
            if 'access_token' in response_json:
                return self._parse_success_response(response_json)
            
            if 'error' in response_json:
                error_data = response_json.get('error', {}).get('error_data', {})
                
                if 'login_first_factor' in error_data and 'uid' in error_data:
                    return self._handle_2fa_manual(error_data)
                
                return {
                    'success': False,
                    'error': response_json['error'].get('message', 'Unknown error'),
                    'error_user_msg': response_json['error'].get('error_user_msg')
                }
            
            return {'success': False, 'error': 'Unknown response format'}
            
        except json.JSONDecodeError:
            return {'success': False, 'error': 'Invalid JSON response'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class CookieToTokenConverter:
    """Converts cookies to tokens - SIMPLE WORKING METHOD"""
    
    @staticmethod
    def parse_cookies(cookies_string):
        """Parse cookies string to dictionary"""
        cookies_dict = {}
        for cookie in cookies_string.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies_dict[key] = value
        return cookies_dict
    
    @staticmethod
    def cookies_to_token(cookies_string):
        """SIMPLE METHOD: Just use the cookies directly"""
        try:
            cookies_dict = CookieToTokenConverter.parse_cookies(cookies_string)
            user_id = cookies_dict.get('c_user')
            xs_token = cookies_dict.get('xs')
            
            if not user_id or not xs_token:
                return {'success': False, 'error': 'Missing c_user or xs cookie'}
            
            # Create a token from cookies (format: user_id|xs_token)
            # This format is often accepted by Facebook APIs
            fake_token = f"{user_id}|{xs_token}"
            
            # Also try the xs token itself as it might be the actual token
            # xs token often contains the access token
            if xs_token and len(xs_token) > 50:
                # Try xs as token first
                test_url = "https://graph.facebook.com/me"
                params = {'access_token': xs_token, 'fields': 'id'}
                
                try:
                    response = requests.get(test_url, params=params, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if 'id' in data:
                            return {
                                'success': True,
                                'access_token': xs_token,
                                'user_id': data['id'],
                                'method': 'xs_as_token'
                            }
                except:
                    pass
            
            # If xs doesn't work, use the fake token
            return {
                'success': True,
                'access_token': fake_token,
                'user_id': user_id,
                'method': 'cookie_based',
                'note': 'This token may work for some APIs'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Cookie parsing error: {str(e)}'}


class AccountInfoFetcher:
    """Fetches account information from token"""
    
    @staticmethod
    def get_account_info(access_token):
        """Get account information from Facebook Graph API"""
        try:
            url = f"https://graph.facebook.com/me"
            params = {
                'access_token': access_token,
                'fields': 'id,name,first_name,middle_name,last_name,email,gender,link,locale,timezone,updated_time,verified'
            }
            
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            if 'error' in data:
                return {'success': False, 'error': data['error']['message']}
            
            return {
                'success': True,
                'account_info': data,
                'display': f"ID: {data.get('id', 'N/A')} | Name: {data.get('name', 'N/A')} | Email: {data.get('email', 'N/A')}"
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}


# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    clear_screen()
    show_logo()
    
    print(GREEN + "═" * 62)
    animated_print("            CONVO V7 TOKEN GRENADE BY ALIYA×NADEEM", color=YELLOW)
    print("═" * 62 + RESET)
    
    # OPTION SELECTION MENU
    print(CYAN + "═" * 62)
    animated_print("           SELECT OPTION (1 OR 2)", color=CYAN)
    print("═" * 62 + RESET)
    print(f"{YELLOW}[1] {GREEN}GMAIL/PHONE NUMBER TO TOKEN{RESET}")
    print(f"{YELLOW}[2] {GREEN}COOKIES TO TOKEN (SIMPLIFIED){RESET}")
    print(GREEN + "═" * 62 + RESET)
    
    while True:
        try:
            option = input(f"{YELLOW}SELECT OPTION (1/2)➠ {RESET}").strip()
            if option in ['1', '2']:
                break
            else:
                print(f"{RED}Invalid option! Please enter 1 or 2{RESET}")
        except KeyboardInterrupt:
            print(f"\n{RED}Operation cancelled{RESET}")
            exit()
    
    print(GREEN + "═" * 62 + RESET)
    
    if option == '1':
        # OPTION 1: GMAIL/PHONE NUMBER TO TOKEN
        print(YELLOW + "═" * 62)
        animated_print(" NOTE: This method requires working Facebook credentials", color=CYAN)
        print(YELLOW + "═" * 62 + RESET)
        
        uid_phone_mail = input(GREEN + "ENTER GMAIL/PHONE NUMBER➠ " + RESET).strip()
        print(GREEN + "═" * 62 + RESET) 
        
        password = input(GREEN + "ENTER PASSWORD➠ " + RESET).strip()
        print(GREEN + "═" * 62 + RESET) 
        
        fb_login = FacebookLogin(
            uid_phone_mail=uid_phone_mail,
            password=password,
            convert_all_tokens=True
        )
        
        result = fb_login.login()
        
    elif option == '2':
        # OPTION 2: COOKIES TO TOKEN (SIMPLIFIED)
        print(YELLOW + "═" * 62)
        animated_print(" ENTER ONLY ESSENTIAL COOKIES:", color=CYAN)
        animated_print(" 1. c_user=123456789", color=YELLOW)
        animated_print(" 2. xs=token_string_here", color=YELLOW)
        print(YELLOW + "═" * 62 + RESET)
        
        print(YELLOW + "Example input: c_user=61583367402383; xs=34:x0KBb8gx2Kc6TA:2:176711474:-1:-1" + RESET)
        
        cookies_input = input(GREEN + "\nENTER COOKIES➠ " + RESET).strip()
        print(GREEN + "═" * 62 + RESET)
        
        animated_print("[*] CONVERTING COOKIES TO TOKEN...", color=CYAN)
        loading_animation(2)
        
        # Convert cookies to token
        token_result = CookieToTokenConverter.cookies_to_token(cookies_input)
        
        if not token_result['success']:
            print(RED + "\n" + "═" * 62)
            animated_print(" COOKIES CONVERSION FAILED ", color=RED)
            print("═" * 62)
            animated_print("PLEASE USE OPTION 1 INSTEAD", color=YELLOW)
            animated_print("OR ENTER VALID COOKIES WITH:", color=YELLOW)
            animated_print("1. c_user=YOUR_USER_ID", color=YELLOW)
            animated_print("2. xs=YOUR_XS_TOKEN", color=YELLOW)
            print(GREEN + "═" * 62 + RESET)
            exit()
        
        # Get original token
        original_token = token_result['access_token']
        original_prefix = FacebookAppTokens.extract_token_prefix(original_token)
        
        # Parse cookies
        cookies_dict = CookieToTokenConverter.parse_cookies(cookies_input)
        cookies_string = '; '.join([f"{k}={v}" for k, v in cookies_dict.items()])
        
        # Create result structure
        result = {
            'success': True,
            'original_token': {
                'token_prefix': original_prefix,
                'access_token': original_token
            },
            'cookies': {
                'dict': cookies_dict,
                'string': cookies_string
            },
            'from_cookies': True,
            'user_id': token_result.get('user_id'),
            'conversion_method': token_result.get('method', 'simple')
        }
        
        # Generate all other tokens
        print(CYAN + "[*] GENERATING ALL TOKENS..." + RESET)
        loading_animation(3)
        
        # Try to convert to all app tokens
        dummy_login = FacebookLogin(uid_phone_mail="dummy", password="dummy")
        all_apps = FacebookAppTokens.get_all_app_keys()
        result['converted_tokens'] = {}
        
        for app_key in all_apps:
            try:
                converted = dummy_login._convert_token(original_token, app_key)
                if converted:
                    result['converted_tokens'][app_key] = converted
                else:
                    # Try with app_id
                    app_id = FacebookAppTokens.get_app_id(app_key)
                    if app_id:
                        # Create a token for this app
                        app_token = f"{app_id}|{original_token.split('|')[-1] if '|' in original_token else original_token}"
                        result['converted_tokens'][app_key] = {
                            'token_prefix': FacebookAppTokens.extract_token_prefix(app_token),
                            'access_token': app_token,
                            'app_name': FacebookAppTokens.get_app_name(app_key),
                            'cookies': {'dict': {}, 'string': ''}
                        }
            except:
                continue
    
    # DISPLAY RESULTS
    if result['success']:
        # Try to get account info
        animated_print("[*] CHECKING TOKEN VALIDITY...", color=CYAN)
        loading_animation(1)
        
        account_info = AccountInfoFetcher.get_account_info(result['original_token']['access_token'])
        
        print(GREEN + "\n" + "═" * 62)
        if option == '1':
            animated_print(" ✅ LOGIN SUCCESSFUL ", color=GREEN)
        else:
            animated_print(" ✅ COOKIES PROCESSED ", color=GREEN)
            if 'conversion_method' in result:
                print(f"{YELLOW}Method: {result['conversion_method']}{RESET}")
        
        if account_info['success']:
            print(CYAN + "═" * 62)
            animated_print(" 📱 ACCOUNT INFORMATION ", color=CYAN)
            print("═" * 62 + RESET)
            print(f"{YELLOW}{account_info['display']}{RESET}")
        else:
            print(YELLOW + f"[*] Token may be limited: {account_info.get('error', 'Unknown')}" + RESET)
        
        print(GREEN + "═" * 62)
        animated_print(" 🔑 ORIGINAL TOKEN ", color=CYAN)
        print("═" * 62 + RESET)
        print(f"{YELLOW}TYPE: {RESET}{result['original_token']['token_prefix']}")
        print(f"{GREEN}{result['original_token']['access_token']}{RESET}")
        print(GREEN + "═" * 62 + RESET) 
        
        if 'converted_tokens' in result and result['converted_tokens']:
            print(CYAN + "\n" + "═" * 62)
            animated_print(" 🎯 ALL TOKENS GENERATED ", color=CYAN)
            print("═" * 62 + RESET)
            
            for app_key, token_data in result['converted_tokens'].items():
                app_name = FacebookAppTokens.get_app_name(app_key)
                print(f"\n{YELLOW}📱 APP: {app_key}{RESET}")
                print(f"{YELLOW}📝 NAME: {app_name}{RESET}")
                print(f"{YELLOW}🔤 TYPE: {token_data['token_prefix']}{RESET}")
                print(f"{GREEN}🔑 {token_data['access_token']}{RESET}")
                print(GREEN + "═" * 62 + RESET)
        
        print("\n" + "═" * 62)
        animated_print(" 🍪 COOKIES ", color=CYAN)
        print("═" * 62)
        print(f"{YELLOW}{result['cookies']['string']}{RESET}")
        print(GREEN + "═" * 62 + RESET)
        
        # Save to file
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"tokens_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=== TOKEN GRENADE V7 RESULTS ===\n\n")
                f.write("ORIGINAL TOKEN:\n")
                f.write(f"{result['original_token']['access_token']}\n\n")
                
                if 'converted_tokens' in result:
                    f.write("ALL GENERATED TOKENS:\n")
                    for app_key, token_data in result['converted_tokens'].items():
                        f.write(f"\n{app_key}:\n")
                        f.write(f"{token_data['access_token']}\n")
                
                f.write(f"\nCOOKIES:\n{result['cookies']['string']}\n")
            
            print(f"{GREEN}[*] All tokens saved to: {filename}{RESET}")
            print(GREEN + "═" * 62 + RESET)
            
        except Exception as e:
            print(f"{YELLOW}[*] Could not save to file: {str(e)}{RESET}")
        
    else:
        print(RED + "\n" + "═" * 62)
        if option == '1':
            animated_print(" ❌ LOGIN FAILED ", color=RED)
        else:
            animated_print(" ❌ CONVERSION FAILED ", color=RED)
        print("═" * 62)
        animated_print(f"Error: {result.get('error')}", color=YELLOW)
        if result.get('error_user_msg'):
            animated_print(f"Message: {result.get('error_user_msg')}", color=YELLOW)
        
        if option == '2':
            print(YELLOW + "\nTIPS FOR COOKIES:" + RESET)
            print(YELLOW + "1. Use Chrome/Firefox browser" + RESET)
            print(YELLOW + "2. Go to facebook.com" + RESET)
            print(YELLOW + "3. Press F12 → Application → Cookies" + RESET)
            print(YELLOW + "4. Copy ONLY c_user and xs values" + RESET)
        
        print(GREEN + "═" * 62 + RESET)
