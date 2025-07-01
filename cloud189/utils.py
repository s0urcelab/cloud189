"""
Utility functions for the Cloud189 SDK
"""

import os
import hmac
import hashlib
import base64
import random
import urllib.parse
from datetime import datetime, timedelta, timezone
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad
import binascii

class FileStream:
    """File stream handler for reading files in chunks"""
    def __init__(self, file_path):
        self.file_path = file_path
        self.file = None

    def open(self):
        """Open file for reading"""
        self.file = open(self.file_path, 'rb')

    def close(self):
        """Close file"""
        if self.file:
            self.file.close()

    def read(self, size):
        """Read specified number of bytes"""
        return self.file.read(size)

    def get_size(self):
        """Get file size"""
        return os.path.getsize(self.file_path)

    def get_name(self, custom_name=None):
        """Get file name"""
        full_name = self.file_path.split('/')[-1]
        name, ext = os.path.splitext(full_name)
        return f'{custom_name or name}{ext}'

    def __enter__(self):
        """Context manager entry"""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

def random_string():
    """Generate random string for request"""
    rand_num = random.randint(0, 99999999999999999)
    return f"0.{rand_num:017d}"

def qs(form):
    """Convert form dictionary to query string"""
    if not form:
        return ""
    return '&'.join([f"{key}={value}" for key, value in form.items()])

def get_signature(params):
    """
    Generate signature for API requests
    
    Args:
        params: Dictionary of parameters to sign
        
    Returns:
        str: Generated signature
    """
    # Sort parameters by key
    sorted_params = dict(sorted(params.items()))
    
    # Create signature string
    sign_str = '&'.join(f'{k}={v}' for k, v in sorted_params.items())
    
    # Calculate MD5
    return hashlib.md5(sign_str.encode()).hexdigest()

def rsa_encode(data: str, pub_key: str, hex_output: bool = True) -> str:
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{pub_key}\n-----END PUBLIC KEY-----"
    
    # Load the public key
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_v1_5.new(public_key)
    
    # Encrypt the data
    try:
        byte_str = data.encode('utf-8')
        encrypted_data = cipher.encrypt(byte_str)
    except Exception as e:
        # print(f"Error: {str(e)}")
        return ""
    
    # Encode to base64
    res = base64.b64encode(encrypted_data).decode('utf-8')
    
    if hex_output:
        return base64.b64decode(res).hex()
    
    return res

def rsa_encrypt(public_key: str, orig_data: str) -> str:
    """
    使用 RSA 公钥加密数据
    
    参数:
    public_key (str): PEM 格式的公钥字符串
    orig_data (str): 要加密的原始数据
    
    返回:
    str: 十六进制格式的大写加密结果
    """
    # 1. 加载公钥
    key = RSA.import_key(public_key)
    
    # 2. 创建加密器 (使用 PKCS#1 v1.5 填充)
    cipher = PKCS1_v1_5.new(key)
    
    # 3. 加密数据
    encrypted_data = cipher.encrypt(orig_data.encode('utf-8'))
    
    # 4. 转换为十六进制并大写
    return binascii.hexlify(encrypted_data).decode('utf-8').upper()

def aes_encrypt(data, key):
    """
    Encrypt data using AES
    
    Args:
        data: Data to encrypt
        key: AES key
        
    Returns:
        bytes: Encrypted data
    """
    data = data.encode('utf-8')
    key = key.encode('utf-8')
    
    # Ensure key length is valid
    if len(key) not in {16, 24, 32}:
        raise ValueError("Key must be either 16, 24, or 32 bytes long")
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Pad and encrypt
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    
    return encrypted

def hmac_sha1(data, secret):
    """
    Generate HMAC-SHA1 signature
    
    Args:
        data: Data to sign
        secret: Secret key
        
    Returns:
        str: HMAC-SHA1 signature in hex
    """
    data_bytes = data.encode('utf-8')
    secret_bytes = secret.encode('utf-8')
    
    hmac_obj = hmac.new(secret_bytes, data_bytes, hashlib.sha1)
    return hmac_obj.hexdigest()

def decodeURIComponent(s):
    """Decode URI component"""
    return urllib.parse.unquote(s)

def encode(s):
    """Encode URI component"""
    return urllib.parse.quote(s)

def get_md5_encode_str(value):
    """Get MD5 hash of string"""
    return hashlib.md5(value.encode('utf-8')).hexdigest()

def parse_cn_time(time_str):
    """
    Parse Chinese time string to datetime object
    
    Args:
        time_str: Time string in format "YYYY-MM-DD HH:MM:SS"
        
    Returns:
        datetime: Datetime object with UTC+8 timezone
    """
    local_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    cn_timezone = timezone(timedelta(hours=8))
    return local_time.replace(tzinfo=cn_timezone)

def calculate_md5_sign(params):
    """Calculate MD5 signature for sorted parameters"""
    return hashlib.md5('&'.join(sorted(params.split('&'))).encode('utf-8')).hexdigest()