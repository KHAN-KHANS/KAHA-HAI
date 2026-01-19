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
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(duration=2):
    chars = ["⠙", "⠘", "⠰", "⠴", "⠤", "⠦", "⠆", "⠃", "⠋", "⠉"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in chars:
            sys.stdout.write(f"\r{CYAN}[{char}] {BOLD}PROCESSING DATA...{RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write("\r" + " " * 50 + "\r")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_logo():
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

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ImportError:
    print(f"{GREEN}Error: 'pycryptodome' module not found.{RESET}")
    print(f"{YELLOW}Run: pip install pycryptodome{RESET}")
    exit()

# ==========================================
# CORE CLASSES (Fixed & Enhanced)
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
        'CONVO_TOKEN_V7': {'name': 'Facebook Messenger', 'app_id': '256002347743983'},
        'FB_LITE': {'name': 'Facebook For Lite', 'app_id': '275254692598279'},
        'MESSENGER_LITE': {'name': 'Messenger Lite', 'app_id': '200424423651082'},
        'ADS_MANAGER': {'name': 'Ads Manager', 'app_id': '438142079694454'},
        'BUSINESS_SUITE': {'name': 'Business Suite', 'app_id': '121876164619130'}
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
        if not token: return "N/A"
        for i, char in enumerate(token):
            if char.islower(): return token[:i]
        return token[:10]

    @staticmethod
    def get_app_name(app_key):
        app = FacebookAppTokens.APPS.get(app_key)
        return app['name'] if app else app_key

class FacebookLogin:
    API_URL = "https://b-graph.facebook.com/auth/login"
    ACCESS_TOKEN = "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
    
    def __init__(self, uid_phone_mail, password, machine_id=None, convert_all_tokens=True):
        self.uid_phone_mail = uid_phone_mail
        self.password = password if password.startswith("#PWD_FB4A") else FacebookPasswordEncryptor.encrypt(password)
        self.convert_all_tokens = convert_all_tokens
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        self.machine_id = machine_id or ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        
    def _build_headers(self):
        return {
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; 23113RKC6C Build/PQ3A.190705.08211809) [FBAN/FB4A;FBAV/417.0.0.33.65;FBPN/com.facebook.katana;FBLC/vi_VN;FBBV/480086274;FBCR/MobiFone;FBMF/Redmi;FBBD/Redmi;FBDV/23113RKC6C;FBSV/9;FBCA/x86:armeabi-v7a;FBDM/{density=1.5,width=1280,height=720};FB_FW/1;FBRV/0;]",
            "content-type": "application/x-www-form-urlencoded",
            "x-fb-connection-type": "WIFI",
            "x-fb-http-engine": "Liger"
        }

    def _convert_token(self, access_token, target_app):
        try:
            app_id = FacebookAppTokens.get_app_id(target_app)
            url = 'https://graph.facebook.com/auth/create_session_for_app'
            params = {
                'access_token': access_token,
                'format': 'json',
                'new_app_id': app_id,
                'generate_session_cookies': '1'
            }
            res = requests.get(url, params=params).json()
            if 'access_token' in res:
                return {
                    'access_token': res['access_token'],
                    'token_prefix': FacebookAppTokens.extract_token_prefix(res['access_token']),
                    'app_name': FacebookAppTokens.get_app_name(target_app)
                }
            return None
        except: return None

    def login(self):
        data = {
            "email": self.uid_phone_mail,
            "password": self.password,
            "credentials_type": "password",
            "generate_session_cookies": "1",
            "access_token": self.ACCESS_TOKEN,
            "method": "post"
        }
        try:
            response = self.session.post(self.API_URL, data=data, headers=self._build_headers()).json()
            if 'access_token' in response:
                return self._parse_success(response)
            return {'success': False, 'error': response.get('error', {}).get('message', 'Login Failed')}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _parse_success(self, res):
        token = res['access_token']
        results = {
            'success': True,
            'original_token': {'access_token': token, 'token_prefix': FacebookAppTokens.extract_token_prefix(token)},
            'cookies': {'string': "; ".join([f"{c['name']}={c['value']}" for c in res.get('session_cookies', [])])},
            'converted_tokens': {}
        }
        if self.convert_all_tokens:
            for app in FacebookAppTokens.get_all_app_keys():
                conv = self._convert_token(token, app)
                if conv: results['converted_tokens'][app] = conv
        return results

class CookieToTokenConverter:
    @staticmethod
    def cookies_to_token(cookies_string):
        """Fix: Improved Cookie to Token logic using Business Manager Session"""
        try:
            # Clean cookies
            cookie_dict = {c.split('=')[0].strip(): c.split('=')[1].strip() for c in cookies_string.split(';') if '=' in c}
            
            if 'c_user' not in cookie_dict or 'xs' not in cookie_dict:
                return {'success': False, 'error': 'Invalid Cookies: c_user/xs missing'}

            headers = {
                'authority': 'business.facebook.com',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'cookie': cookies_string,
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }

            # Attempt to get EAAG token (Business Token)
            response = requests.get('https://business.facebook.com/business_locations', headers=headers)
            if 'EAAG' in response.text:
                token = "EAAG" + response.text.split('EAAG')[1].split('"')[0]
                return {'success': True, 'access_token': token, 'user_id': cookie_dict['c_user']}
            
            # Alternative: Get EAAI token
            response = requests.get('https://facebook.com/adsmanager/manage/campaigns', headers=headers)
            if 'EAAI' in response.text:
                token = "EAAI" + response.text.split('EAAI')[1].split('"')[0]
                return {'success': True, 'access_token': token, 'user_id': cookie_dict['c_user']}
                
            return {'success': False, 'error': 'Could not extract EAAG/EAAI token from session'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

class AccountInfoFetcher:
    @staticmethod
    def get_account_info(access_token):
        try:
            res = requests.get(f"https://graph.facebook.com/me?access_token={access_token}&fields=id,name,email").json()
            if 'id' in res:
                return {'success': True, 'display': f"ID: {res['id']} | Name: {res['name']}"}
            return {'success': False}
        except: return {'success': False}

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    clear_screen()
    show_logo()
    
    print(f"{YELLOW}[1] {GREEN}GMAIL/PHONE NUMBER TO TOKEN{RESET}")
    print(f"{YELLOW}[2] {GREEN}COOKIES TO TOKEN{RESET}")
    print(GREEN + "═" * 62 + RESET)
    
    option = input(f"{YELLOW}SELECT OPTION (1/2)➠ {RESET}").strip()
    print(GREEN + "═" * 62 + RESET)
    
    result = {'success': False}
    
    if option == '1':
        uid = input(GREEN + "ENTER GMAIL/PHONE NUMBER➠ " + RESET).strip()
        pwd = input(GREEN + "ENTER PASSWORD➠ " + RESET).strip()
        print(GREEN + "═" * 62 + RESET)
        fb = FacebookLogin(uid, pwd)
        result = fb.login()
        
    elif option == '2':
        cookies_input = input(GREEN + "ENTER COOKIES➠ " + RESET).strip()
        print(GREEN + "═" * 62 + RESET)
        loading_animation(2)
        
        token_res = CookieToTokenConverter.cookies_to_token(cookies_input)
        if token_res['success']:
            # Create standard result structure
            orig_token = token_res['access_token']
            result = {
                'success': True,
                'original_token': {'access_token': orig_token, 'token_prefix': FacebookAppTokens.extract_token_prefix(orig_token)},
                'cookies': {'string': cookies_input},
                'converted_tokens': {}
            }
            # Convert to other app tokens
            fb_dummy = FacebookLogin("none", "none")
            for app in FacebookAppTokens.get_all_app_keys():
                conv = fb_dummy._convert_token(orig_token, app)
                if conv: result['converted_tokens'][app] = conv
        else:
            result = {'success': False, 'error': token_res['error']}

    if result.get('success'):
        acc = AccountInfoFetcher.get_account_info(result['original_token']['access_token'])
        print(GREEN + " LOGIN/CONVERSION SUCCESSFUL ✅" + RESET)
        if acc['success']: print(f"{CYAN}{acc['display']}{RESET}")
        
        print(f"\n{YELLOW}ORIGINAL TOKEN ({result['original_token']['token_prefix']}):{RESET}")
        print(f"{GREEN}{result['original_token']['access_token']}{RESET}")
        
        if result['converted_tokens']:
            print(f"\n{BLUE}--- ALL GENERATED TOKENS ---{RESET}")
            for app_key, data in result['converted_tokens'].items():
                print(f"{YELLOW}[+] {data['app_name']} ({data['token_prefix']}):{RESET}")
                print(f"{CYAN}{data['access_token']}{RESET}")
        
        print(f"\n{YELLOW}SESSION COOKIES:{RESET}\n{result['cookies']['string']}")
    else:
        print(f"{RED}FAILED: {result.get('error', 'Unknown Error')}{RESET}")

    print(GREEN + "═" * 62 + RESET)
