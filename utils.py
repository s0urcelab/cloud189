import os
import hmac
import hashlib
import base64
import random
import urllib.parse
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class FileStream:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file = None

    def open(self):
        """打开文件以供读取"""
        self.file = open(self.file_path, 'rb')  # 以二进制模式打开文件

    def close(self):
        """关闭文件"""
        if self.file:
            self.file.close()

    def read(self, size):
        """读取指定大小的字节"""
        return self.file.read(size)

    def get_size(self):
        """获取文件大小"""
        return os.path.getsize(self.file_path)

    def get_name(self, custom_name=None):
        """获取文件名"""
        full_name = self.file_path.split('/')[-1]
        name, ext = os.path.splitext(full_name)
        return f'{custom_name or name}{ext}'

    def __enter__(self):
        """支持上下文管理器"""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出时关闭文件"""
        self.close()
        
def random_string():
    rand_num = random.randint(0, 99999999999999999)
    return f"0.{rand_num:017d}"

def qs(form):
    if not form:
        return ""
    return '&'.join([f"{key}={value}" for key, value in form.items()])

def rsa_encode(data: str, pub_key: str, hex_output: bool = True) -> str:
    public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{pub_key}\n-----END PUBLIC KEY-----"
    
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    # Encrypt the data
    try:
        byte_str = data.encode('utf-8')
        encrypted_data = public_key.encrypt(
            byte_str,
            padding.PKCS1v15()
        )
    except Exception as e:
        print(f"Error: {str(e)}")
        return ""
    
    # Encode to base64
    res = base64.b64encode(encrypted_data).decode('utf-8')
    
    if hex_output:
        return base64.b64decode(res).hex()
    
    return res

def aes_encrypt(d: str, k: str) -> bytes:
    data = d.encode('utf-8')
    key = k.encode('utf-8')
    # 确保密钥长度为16, 24或32字节
    if len(key) not in {16, 24, 32}:
        raise ValueError("Key must be either 16, 24, or 32 bytes long.")
    
    # 创建 AES 加密器
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # 进行 PKCS7 填充
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # 加密数据
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted

def hmac_sha1(data: str, secret: str) -> str:
    # 将字符串转换为字节
    data_bytes = data.encode('utf-8')
    secret_bytes = secret.encode('utf-8')
    
    # 创建 HMAC 对象
    hmac_obj = hmac.new(secret_bytes, data_bytes, hashlib.sha1)
    
    # 生成 HMAC 并转换为十六进制字符串
    return hmac_obj.hexdigest()

def decodeURIComponent(s: str) -> str:
    r = urllib.parse.unquote(s)
    return r

def encode(s: str) -> str:
    return urllib.parse.quote(s)

def get_md5_encode_str(value):
    return hashlib.md5(value.encode('utf-8')).hexdigest()

def parse_cn_time(time_str):
    # 解析时间字符串，假设格式为 "YYYY-MM-DD HH:MM:SS"
    # 添加 +08:00 时区信息
    local_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    # 设置为 UTC+8 时区
    cn_timezone = timezone(timedelta(hours=8))
    return local_time.replace(tzinfo=cn_timezone)