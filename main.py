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

def loading_animation(duration=2, label="GENERATING DATA"):
    chars = ["⠙", "⠘", "⠰", "⠴", "⠤", "⠦", "⠆", "⠃", "⠋", "⠉"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in chars:
            sys.stdout.write(f"\r{CYAN}[{char}] {BOLD}{label}{RESET}")
            sys.stdout.flush()
            time.sleep(0.08)
    sys.stdout.write("\r" + " " * 60 + "\r")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_logo():
    logo = f"""
{CYAN}     ███╗   ██╗ █████╗ ██████╗ ███████╗███████╗███╗   ███╗
{BLUE}     ████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝████╗ ████║
{GREEN}     ██╔██╗ ██║███████║██║  ██║█████╗  █████╗  ██╔████╔██║
{YELLOW}     ██║╚██╗██║██╔══██║██║  ██║██╔══╝  ██╔══╝  ██║╚██╔╝██║
{RED}     ██║ ╚████║██║  ██║██████╔╝███████╗███████╗██║ ╚═╝ ██║
{CYAN}     ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝
{BOLD}{WHITE}                [ TOKEN GRENADE V7 - ADVANCED ]             {RESET}"""
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
# CORE LOGIC
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

class FacebookAppTokens:
    APPS = {
        'FB_ANDROID': '350685531728',
        'MESSENGER': '256002347743983',
        'FB_LITE': '275254692598279',
        'ADS_MANAGER': '438142079694454'
    }

class FacebookLogin:
    def __init__(self, identifier, password):
        self.identifier = identifier
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

    def _convert(self, token, target_id):
        try:
            r = self.session.post('https://api.facebook.com/method/auth.getSessionforApp', data={
                'access_token': token, 'format': 'json', 'new_app_id': target_id, 'generate_session_cookies': '1'
            }).json()
            return r.get('access_token')
        except: return None

    def handle_2fa(self, error_data):
        while True:
            clear_screen()
            show_logo()
            print(f"{RED}╔════════════════════════════════════════════════════════════╗")
            print(f"{RED}║ {BOLD}SECURITY CHECK: TWO-FACTOR AUTHENTICATION REQUIRED {RESET}{RED}      ║")
            print(f"{RED}╚════════════════════════════════════════════════════════════╝{RESET}")
            print(f"{CYAN}[1]{RESET} Get code via {GREEN}WhatsApp{RESET}")
            print(f"{CYAN}[2]{RESET} Get code via {GREEN}SMS (Mobile Number){RESET}")
            print(f"{CYAN}[3]{RESET} Get code via {GREEN}Gmail / Email{RESET}")
            print(f"{CYAN}[0]{RESET} Exit Tool")
            print(GREEN + "═" * 62 + RESET)
            
            choice = input(f"{YELLOW}SELECT OPTION ➠ {RESET}").strip()
            
            if choice == '0': exit()
            if choice in ['1', '2', '3']:
                method = ["WhatsApp", "SMS", "Email"][int(choice)-1]
                animated_print(f"[*] Requesting code via {method}...", color=CYAN)
                loading_animation(2, "SENDING REQUEST")
                
                print(GREEN + "═" * 62 + RESET)
                otp = input(f"{YELLOW}ENTER THE CODE RECEIVED ➠ {RESET}").strip()
                
                loading_animation(2, "VERIFYING OTP")
                
                data_2fa = {
                    'format': 'json', 'email': self.identifier, 'device_id': self.device_id,
                    'access_token': "350685531728|62f8ce9f74b12f84c123cc23437a4a32",
                    'generate_session_cookies': 'true', 'twofactor_code': otp,
                    'credentials_type': 'two_factor', 'userid': error_data['uid'],
                    'machine_id': self.machine_id, 'password': self.password
                }
                
                res = self.session.post("https://b-graph.facebook.com/auth/login", data=data_2fa, headers=self._get_headers()).json()
                
                if 'access_token' in res:
                    return res
                else:
                    animated_print(f"[!] FAILED: {res.get('error', {}).get('message', 'Invalid Code')}", color=RED)
                    time.sleep(2)
            else:
                print(f"{RED}Invalid Option! Try again.{RESET}")
                time.sleep(1)

    def login(self):
        animated_print("[*] INITIALIZING SECURE LOGIN...", color=CYAN)
        loading_animation(2, "CONNECTING TO SERVER")
        
        data = {
            "format": "json", "email": self.identifier, "password": self.password,
            "generate_session_cookies": "1", "api_key": "882a8490361da98702bf97a021ddc14d",
            "device_id": self.device_id, "machine_id": self.machine_id,
            "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
        }
        
        response = self.session.post("https://b-graph.facebook.com/auth/login", data=data, headers=self._get_headers()).json()
        
        if 'access_token' in response:
            return response
        
        if 'error' in response:
            error_data = response.get('error', {}).get('error_data', {})
            if 'login_first_factor' in error_data:
                return self.handle_2fa(error_data)
        
        return response

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    clear_screen()
    show_logo()
    
    uid = input(f"{GREEN}ENTER GMAIL/PHONE NUMBER ➠ {RESET}").strip()
    pas = input(f"{GREEN}ENTER PASSWORD ➠ {RESET}").strip()
    print(GREEN + "═" * 62 + RESET)
    
    bot = FacebookLogin(uid, pas)
    result = bot.login()
    
    if result and 'access_token' in result:
        main_token = result['access_token']
        print(f"{GREEN}LOGIN SUCCESSFUL ✅{RESET}")
        print(f"{YELLOW}MAIN TOKEN: {RESET}{main_token}")
        print(GREEN + "═" * 62 + RESET)
        
        loading_animation(2, "EXPLODING GRENADE (GENERATING ALL TOKENS)")
        
        for name, app_id in FacebookAppTokens.APPS.items():
            token = bot._convert(main_token, app_id)
            if token:
                print(f"{CYAN}APP: {name}{RESET}")
                print(f"{GREEN}{token}{RESET}")
                print("-" * 30)
    else:
        print(f"{RED}LOGIN FAILED PERMANENTLY{RESET}")
        print(f"Reason: {result.get('error', {}).get('message', 'Unknown')}")

    print(f"\n{BOLD}{YELLOW}Work Finished. Thank you for using Token Grenade V7!{RESET}")
