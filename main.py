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
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"

def animated_print(text, delay=0.02, color=GREEN):
    """Stylish typewriter effect."""
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(duration=3, label="PROCESSING"):
    """Matrix style loading bar."""
    chars = ["█", "▒", "░", "█"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in chars:
            percent = random.randint(10, 99)
            sys.stdout.write(f"\r{CYAN}[{char}] {BOLD}{label}... {percent}%{RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write("\r" + " " * 60 + "\r")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_logo():
    clear_screen()
    logo = f"""
{CYAN}     ███╗   ██╗ █████╗ ██████╗ ███████╗███████╗███╗   ███╗
{BLUE}     ████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝████╗ ████║
{GREEN}     ██╔██╗ ██║███████║██║  ██║█████╗  █████╗  ██╔████╔██║
{YELLOW}     ██║╚██╗██║██╔══██║██║  ██║██╔══╝  ██╔══╝  ██║╚██╔╝██║
{RED}     ██║ ╚████║██║  ██║██████╔╝███████╗███████╗██║ ╚═╝ ██║
{CYAN}     ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝
{BOLD}{WHITE}             [ TOKEN GRENADE V7 - BY ALIYA×NADEEM ]             {RESET}"""
    print(logo)
    print(GREEN + "═" * 62 + RESET)

# ==========================================
# CRYPTO CHECK
# ==========================================
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ImportError:
    print(f"{RED}Error: 'pycryptodome' missing. Run: pip install pycryptodome{RESET}")
    exit()

# ==========================================
# CORE FACEBOOK LOGIC
# ==========================================

class FacebookPasswordEncryptor:
    @staticmethod
    def get_public_key():
        try:
            url = 'https://b-graph.facebook.com/pwd_key_fetch'
            params = {
                'version': '2',
                'access_token': '438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28'
            }
            res = requests.post(url, params=params).json()
            return res.get('public_key'), str(res.get('key_id', '25'))
        except:
            return None, "25"

    @staticmethod
    def encrypt(password, public_key=None, key_id="25"):
        if not public_key:
            public_key, key_id = FacebookPasswordEncryptor.get_public_key()
        
        rand_key = get_random_bytes(32)
        iv = get_random_bytes(12)
        pubkey = RSA.import_key(public_key)
        cipher_rsa = PKCS1_v1_5.new(pubkey)
        enc_rand_key = cipher_rsa.encrypt(rand_key)
        cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
        ts = int(time.time())
        cipher_aes.update(str(ts).encode())
        enc_pass, auth_tag = cipher_aes.encrypt_and_digest(password.encode())
        
        buf = io.BytesIO()
        buf.write(bytes([1, int(key_id)]))
        buf.write(iv)
        buf.write(struct.pack("<h", len(enc_rand_key)))
        buf.write(enc_rand_key)
        buf.write(auth_tag)
        buf.write(enc_pass)
        return f"#PWD_FB4A:2:{ts}:{base64.b64encode(buf.getvalue()).decode()}"

class FacebookLogin:
    APPS = {
        'FB_ANDROID': '350685531728',
        'MESSENGER': '256002347743983',
        'FB_LITE': '275254692598279',
        'ADS_MANAGER': '438142079694454'
    }

    def __init__(self, identifier, password):
        self.identifier = identifier
        self.raw_password = password
        self.password = FacebookPasswordEncryptor.encrypt(password)
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        self.machine_id = ''.join(random.choices(string.ascii_letters + string.digits, k=24))

    def _get_headers(self):
        return {
            "content-type": "application/x-www-form-urlencoded",
            "x-fb-connection-type": "WIFI",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; Redmi Build/PQ3A.190705.08211809) [FBAN/FB4A;FBAV/417.0.0.33.65;FBPN/com.facebook.katana;FBLC/vi_VN;FBBV/480086274;]"
        }

    def handle_2fa(self, error_data):
        """Infinite loop for 2FA selection and verification."""
        while True:
            show_logo()
            print(f"{RED}╔════════════════════════════════════════════════════════════╗")
            print(f"{RED}║ {BOLD}{WHITE}SECURITY CHECK: TWO-FACTOR AUTHENTICATION REQUIRED {RESET}{RED}      ║")
            print(f"{RED}╚════════════════════════════════════════════════════════════╝{RESET}")
            print(f"{CYAN}[1]{RESET} Get code via {GREEN}WhatsApp{RESET}")
            print(f"{CYAN}[2]{RESET} Get code via {GREEN}SMS (Mobile Number){RESET}")
            print(f"{CYAN}[3]{RESET} Get code via {GREEN}Gmail / Email{RESET}")
            print(f"{CYAN}[0]{RESET} Exit Tool")
            print(GREEN + "═" * 62 + RESET)
            
            choice = input(f"{YELLOW}SELECT OPTION ➠ {RESET}").strip()
            
            if choice == '0': sys.exit()
            if choice in ['1', '2', '3']:
                methods = ["WhatsApp", "SMS", "Email"]
                selected_method = methods[int(choice)-1]
                
                animated_print(f"[*] Requesting OTP link via {selected_method}...", color=CYAN)
                loading_animation(2, "SENDING REQUEST")
                
                print(GREEN + "═" * 62 + RESET)
                otp_code = input(f"{YELLOW}ENTER 6-DIGIT CODE RECEIVED ➠ {RESET}").strip()
                
                loading_animation(2, "VERIFYING CODE")
                
                # Verification attempt
                data_2fa = {
                    'format': 'json', 'email': self.identifier, 'device_id': self.device_id,
                    'access_token': "350685531728|62f8ce9f74b12f84c123cc23437a4a32",
                    'generate_session_cookies': 'true', 'twofactor_code': otp_code,
                    'credentials_type': 'two_factor', 'userid': error_data['uid'],
                    'machine_id': self.machine_id, 'password': self.password,
                    'first_factor': error_data.get('login_first_factor')
                }
                
                try:
                    res = self.session.post("https://b-graph.facebook.com/auth/login", data=data_2fa, headers=self._get_headers()).json()
                    if 'access_token' in res:
                        return res
                    else:
                        print(f"{RED}[!] ERROR: {res.get('error', {}).get('message', 'Wrong Code')}{RESET}")
                        time.sleep(2)
                except Exception as e:
                    print(f"{RED}[!] Connection Error: {e}{RESET}")
                    time.sleep(2)
            else:
                print(f"{RED}[!] Invalid Choice. Try Again.{RESET}")
                time.sleep(1)

    def login_process(self):
        """Initial login attempt."""
        animated_print("[*] SECURE CONNECTION ESTABLISHED...", color=CYAN)
        loading_animation(2, "INJECTING PAYLOAD")
        
        data = {
            "format": "json", "email": self.identifier, "password": self.password,
            "generate_session_cookies": "1", "api_key": "882a8490361da98702bf97a021ddc14d",
            "device_id": self.device_id, "machine_id": self.machine_id,
            "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
        }
        
        try:
            response = self.session.post("https://b-graph.facebook.com/auth/login", data=data, headers=self._get_headers()).json()
            
            if 'access_token' in response:
                return response
            
            if 'error' in response:
                err_data = response.get('error', {}).get('error_data', {})
                if 'login_first_factor' in err_data:
                    # Triggering the 3-option menu
                    return self.handle_2fa(err_data)
                else:
                    return response
        except Exception as e:
            return {'error': {'message': str(e)}}

    def convert_tokens(self, main_token):
        """Generates all other tokens using the main token."""
        converted = {}
        for app_name, app_id in self.APPS.items():
            try:
                r = self.session.post('https://api.facebook.com/method/auth.getSessionforApp', data={
                    'access_token': main_token, 'format': 'json', 'new_app_id': app_id, 'generate_session_cookies': '1'
                }).json()
                if 'access_token' in r:
                    converted[app_name] = r['access_token']
            except:
                continue
        return converted

# ==========================================
# EXECUTION
# ==========================================
if __name__ == "__main__":
    show_logo()
    
    uid = input(f"{GREEN}ENTER GMAIL/PHONE NUMBER ➠ {RESET}").strip()
    pas = input(f"{GREEN}ENTER PASSWORD ➠ {RESET}").strip()
    print(GREEN + "═" * 62 + RESET)
    
    bot = FacebookLogin(uid, pas)
    result = bot.login_process()
    
    if result and 'access_token' in result:
        token_primary = result['access_token']
        clear_screen()
        show_logo()
        print(f"{GREEN}╔════════════════════════════════════════════════════════════╗")
        print(f"{GREEN}║ {BOLD}{WHITE}LOGIN SUCCESSFUL - ACCESS GRANTED {RESET}{GREEN}                   ║")
        print(f"{GREEN}╚════════════════════════════════════════════════════════════╝{RESET}")
        
        loading_animation(3, "DETONATING TOKEN GRENADE")
        
        print(f"\n{YELLOW}PRIMARY TOKEN (FB_ANDROID):{RESET}")
        print(f"{CYAN}{token_primary}{RESET}\n")
        print(GREEN + "═" * 62 + RESET)

        # Generate all other tokens
        other_tokens = bot.convert_tokens(token_primary)
        for app, tkn in other_tokens.items():
            if tkn != token_primary:
                print(f"{YELLOW}TOKEN FOR {app}:{RESET}")
                print(f"{GREEN}{tkn}{RESET}")
                print("-" * 40)
        
        # Cookies
        if 'session_cookies' in result:
            print(f"\n{BLUE}SESSION COOKIES:{RESET}")
            c_str = "; ".join([f"{c['name']}={c['value']}" for c in result['session_cookies']])
            print(f"{WHITE}{c_str}{RESET}")

    else:
        print(f"{RED}LOGIN FAILED PERMANENTLY{RESET}")
        msg = result.get('error', {}).get('message', 'Unknown Error')
        print(f"{YELLOW}Reason: {msg}{RESET}")

    print(f"\n{BOLD}{CYAN}═" * 62)
    print(f"            PROCESS COMPLETED - THANK YOU")
    print(f"═" * 62 + RESET)
