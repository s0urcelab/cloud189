"""
Main client for the Cloud189 SDK
"""

import time
import httpx
import uuid
import math
import hashlib
import base64
import json
import random
import logging
from urllib.parse import urlparse, parse_qs
from .constants import *
from .store import MemoryStore
from .utils import get_signature, rsa_encode, aes_encrypt, hmac_sha1, FileStream, decodeURIComponent, encode, get_md5_encode_str, parse_cn_time
from .auth import CloudAuthClient

# 禁用 httpx 的日志输出
logging.getLogger("httpx").setLevel(logging.WARNING)

# 配置 logger
logger = logging.getLogger(__name__)

class CloudClient:
    """Main client for interacting with 189 Cloud"""
    
    def __init__(self, options):
        self._validate_options(options)
        
        self.username = options.get('username')
        self.password = options.get('password')
        self.sson_cookie = options.get('ssonCookie')
        self.token_store = options.get('token', MemoryStore())
        self.slice_size = options.get('slice_size', 1024 * 1024 * 10)  # Default 10MB
        self.max_retries = options.get('max_retries', 3)  # Default 3 retries
        self.rsa = {
            "Expire": 0,
            "PkId": "",
            "PubKey": "",
        }
        self.auth_client = CloudAuthClient()
        self.token_session = {'accessToken': '', 'sessionKey': ''}
        # Create session
        self.session = httpx.Client(timeout=600.0)  # 10 minutes timeout
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Referer': f'{WEB_URL}/web/main/',
            'Accept': 'application/json;charset=UTF-8'
        })
        # Register hooks
        self.session.event_hooks['request'] = [self._before_request]
        # self.session.event_hooks['response'] = [self._after_response]

    def _get_request_params(self, request):
        """Helper method to get request parameters from GET or POST request"""
        params = {}
        if request.method == 'GET':
            params = parse_qs(urlparse(str(request.url)).query)
        else:
            # Handle JSON POST request body
            if request.content:
                try:
                    body_data = request.json
                    if body_data:
                        params.update(body_data)
                except:
                    pass
        return params

    def _get_access_token(self):
        access_token = self.token_session['accessToken']
        if not access_token:
            access_token = self._get_access_token_by_api()['accessToken']
            self.token_session['accessToken'] = access_token

        return access_token
    
    def _get_session_key(self):
        session_key = self.token_session['sessionKey']
        if not session_key:
            session_key = self._get_session_key_by_api()['sessionKey']
            self.token_session['sessionKey'] = session_key
            
        return session_key

    def _before_request(self, request, **kwargs):
        """Handle request before sending"""
        url = str(request.url)
        
        if API_URL in url:
            # Get accessToken from cache or fetch new one
            access_token = self._get_access_token()
            
            # Get request parameters
            params = self._get_request_params(request)
            
            # Add timestamp
            timestamp = str(int(time.time() * 1000))
            params['Timestamp'] = timestamp
            params['AccessToken'] = access_token
            
            # Generate signature
            signature = get_signature(params)
            
            # Add headers
            request.headers.update({
                'Sign-Type': '1',
                'Signature': signature,
                'Timestamp': timestamp,
                'Accesstoken': access_token
            })
            
        elif WEB_URL in url:
            if '/open' in url:
                # Get timestamp and app key
                timestamp = str(int(time.time() * 1000))
                app_key = '600100422'
                
                # Get request parameters
                params = self._get_request_params(request)
                
                # Add parameters
                params['Timestamp'] = timestamp
                params['AppKey'] = app_key
                
                # Generate signature
                signature = get_signature(params)
                
                # Add headers
                request.headers.update({
                    'Sign-Type': '1',
                    'Signature': signature,
                    'Timestamp': timestamp,
                    'AppKey': app_key
                })
            
            # Get sessionKey from cache or fetch new one
            session_key = self._get_session_key()
            
            url_obj = httpx.URL(url)
            # Merge original params with sessionKey
            original_params = dict(url_obj.params)
            original_params["sessionKey"] = session_key
            request.url = url_obj.copy_with(params=original_params)

        return request
    
    def _request_with_retry(self, method, url, **kwargs):
        max_retries = self.max_retries
        retry_count = 0
        
        while retry_count <= max_retries:
            response = self.session.request(method, url, **kwargs)
            
            if response.status_code >= 400:
                try:
                    data = response.json()
                    error_code = data.get('errorCode')
                    
                    if error_code == 'InvalidAccessToken':
                        logger.warning(f'InvalidAccessToken (retry {retry_count + 1})')
                        self.token_session['accessToken'] = ''
                        retry_count += 1
                        if retry_count > max_retries:
                            raise Exception(f'InvalidAccessToken retry limit exceeded ({max_retries} times)')
                        continue
                        
                    elif error_code == 'InvalidSessionKey':
                        logger.warning(f'InvalidSessionKey (retry {retry_count + 1})')
                        self.token_session['sessionKey'] = ''
                        retry_count += 1
                        if retry_count > max_retries:
                            raise Exception(f'InvalidSessionKey retry limit exceeded ({max_retries} times)')
                        continue
                except Exception as e:
                    if 'retry limit exceeded' in str(e):
                        raise e
                    pass
            
            return response
    
    def _validate_options(self, options):
        """Validate client configuration options"""
        if not options.get('token') and not (options.get('username') and options.get('password')):
            raise ValueError('Please provide username and password or token!')
    
    def _get_access_token_by_api(self):
        """Get access token using session key"""
        resp = self.session.get(f'{WEB_URL}/api/open/oauth2/getAccessTokenBySsKey.action')
        return resp.json()
    
    def _get_session_key_by_api(self):
        """Get or refresh session"""
        token_data = self.token_store.get()
        
        if token_data and token_data.get('accessToken') and token_data.get('expiresIn') > time.time() * 1000:
            try:
                return self.auth_client.login_by_access_token(token_data['accessToken'])
            except Exception as e:
                logger.error(f"Access token: {e}")
        
        if token_data and token_data.get('refreshToken'):
            try:
                refresh_session = self.auth_client.refresh_token(token_data['refreshToken'])
                self.token_store.update({
                    'accessToken': refresh_session['accessToken'],
                    'refreshToken': refresh_session['refreshToken'],
                    'expiresIn': int(time.time() * 1000) + refresh_session['expiresIn'] * 1000
                })
                return self.auth_client.login_by_access_token(refresh_session['accessToken'])
            except Exception as e:
                logger.error(f"Refreshing token: {e}")
        
        if self.sson_cookie:
            try:
                login_token = self.auth_client.login_by_sso_cookie(self.sson_cookie)
                self.token_store.update({
                    'accessToken': login_token['accessToken'],
                    'refreshToken': login_token['refreshToken'],
                    'expiresIn': int(time.time() * 1000) + 6 * 24 * 60 * 60 * 1000
                })
                return login_token
            except Exception as e:
                logger.error(f"SSO cookie: {e}")
        
        if self.username and self.password:
            try:
                login_token = self.auth_client.login_by_password(self.username, self.password)
                self.token_store.update({
                    'accessToken': login_token['accessToken'],
                    'refreshToken': login_token['refreshToken'],
                    'expiresIn': int(time.time() * 1000) + 6 * 24 * 60 * 60 * 1000
                })
                return login_token
            except Exception as e:
                logger.error(f"Password: {e}")
        
        raise Exception('Cannot get sessionKey by api')
    
    def _get_rsa_key(self):
        """Get RSA key for encryption"""
        now = int(time.time() * 1000)
        if self.rsa["Expire"] > now:
            return self.rsa["PubKey"], self.rsa["PkId"]
        
        resp = self.session.get(f"{API_URL}/security/generateRsaKey.action")
        resp_json = resp.json()
        
        if resp_json.get("res_code") != 0:
            raise Exception(f"Failed to get RSA key: {resp_json}")
        
        pub_key = resp_json.get("pubKey")
        pk_id = resp_json.get("pkId")
        self.rsa["PubKey"], self.rsa["PkId"] = pub_key, pk_id
        self.rsa["Expire"] = int(resp_json.get("expire"))
        return pub_key, pk_id
    
    def _upload_request(self, uri, form):
        """Make upload request with encryption"""
        c = str(int(time.time() * 1000))
        r = str(uuid.uuid4())
        l = str(uuid.uuid4()).replace("-", "")
        l = l[:16 + int(16 * random.random())]
        
        # Encrypt form data
        form_str = '&'.join(f"{k}={v}" for k, v in form.items())
        data = aes_encrypt(form_str, l[:16])
        h = data.hex()
        
        # Get session key and generate signature
        session_key = self._get_session_key()
        signature = hmac_sha1(f"SessionKey={session_key}&Operate=GET&RequestURI={uri}&Date={c}&params={h}", l)
        
        # Get RSA key and encrypt
        pub_key, pk_id = self._get_rsa_key()
        # b = rsa_encrypt(l, pub_key, False)
        b = rsa_encode(l, pub_key, False)

        # Set headers
        headers = {
            "accept": "application/json;charset=UTF-8",
            "SessionKey": session_key,
            "Signature": signature,
            "X-Request-Date": c,
            "X-Request-ID": r,
            "EncryptionText": b,
            "PkId": pk_id,
        }
        
        # Make request
        response = self.session.get(f"{UPLOAD_URL}{uri}?params={h}", headers=headers)
        resp_json = response.json()
        
        if resp_json.get("code") != "SUCCESS":
            raise Exception(f'Upload request failed: {resp_json.get("msg")}')
        
        return resp_json
    
    def upload(self, file_path, folder_id, rename=None):
        """Upload file to cloud storage"""
        with FileStream(file_path) as file:
            file_size = file.get_size()
            count = math.ceil(file_size / self.slice_size)
            
            # Initialize upload
            res = self._upload_request("/person/initMultiUpload", {
                "parentFolderId": folder_id,
                "fileName": encode(file.get_name(rename)),
                "fileSize": str(file_size),
                "sliceSize": str(self.slice_size),
                "lazyCheck": "1"
            })
            
            upload_file_id = res['data']['uploadFileId']
            finish = 0
            md5s = []
            md5_sum = hashlib.md5()
            
            # Upload file slices
            for i in range(1, int(count) + 1):
                byte_size = min(file_size - finish, self.slice_size)
                byte_data = file.read(byte_size)
                finish += len(byte_data)
                
                # Calculate MD5
                md5_bytes = hashlib.md5(byte_data).digest()
                md5_hex = md5_bytes.hex().upper()
                md5_base64 = base64.b64encode(md5_bytes).decode('utf-8')
                md5s.append(md5_hex)
                md5_sum.update(byte_data)
                
                # Get upload URL
                resp = self._upload_request("/person/getMultiUploadUrls", {
                    "partInfo": f"{i}-{md5_base64}",
                    "uploadFileId": upload_file_id,
                })
                
                # Upload slice
                upload_data = resp['uploadUrls'][f"partNumber_{i}"]
                request_url = upload_data['requestURL']
                request_header = decodeURIComponent(upload_data['requestHeader'])
                upload_headers = {}
                for pair in request_header.split('&'):
                    key, _, value = pair.partition('=')
                    upload_headers[key] = value
                
                response = httpx.put(request_url, headers=upload_headers, content=byte_data, timeout=600.0)  # 5 minutes timeout
                response.raise_for_status()
            
            # Calculate final MD5
            file_md5 = md5_sum.hexdigest()
            slice_md5 = file_md5 if file_size <= self.slice_size else get_md5_encode_str('\n'.join(md5s))
            
            # Commit upload
            result = self._upload_request("/person/commitMultiUploadFile", {
                "uploadFileId": upload_file_id,
                "fileMd5": file_md5,
                "sliceMd5": slice_md5,
                "lazyCheck": "1",
                "opertype": "3",
            })
            
            if result['code'] == 'SUCCESS':
                return result['file']['userFileId']
            
            raise Exception(f'Failed to upload: {result}')
    
    def delete(self, file_id, file_name, is_folder=False):
        """Delete file or folder"""
        task_infos = [{
            "fileId": file_id,
            "fileName": file_name,
            "isFolder": int(is_folder),
        }]
        
        task_infos_bytes = json.dumps(task_infos)
        
        form = {
            "type": "DELETE",
            "targetFolderId": "",
            "taskInfos": task_infos_bytes,
        }
        
        response = self._request_with_retry('POST', f"{WEB_URL}/api/open/batch/createBatchTask.action", data=form)
        resp_json = response.json()
        
        if resp_json.get("res_code") != 0:
            raise Exception(f'Failed to delete: {resp_json}')
    
    def get_all_files(self, folder_id):
        """Get all files and folders in a directory"""
        res = []
        page_num = 1
        
        while True:
            response = self._request_with_retry('GET', f"{WEB_URL}/api/open/file/listFiles.action", params={
                "pageSize": "60",
                "pageNum": str(page_num),
                "mediaType": "0",
                "folderId": str(folder_id),
                "iconOption": "5",
                "orderBy": "lastOpTime",
                "descending": "true",
            })
            resp_json = response.json()
            
            if resp_json.get('res_code') != 0:
                raise Exception(f'Failed to get files: {resp_json}')
            
            # Check if last page
            if resp_json['fileListAO']['count'] == 0:
                break
            
            # Process folders
            for folder in resp_json['fileListAO']['folderList']:
                last_op_time = parse_cn_time(folder['lastOpTime'])
                res.append({
                    'id': str(folder['id']),
                    'name': folder['name'],
                    'modified': last_op_time,
                    'is_folder': True
                })
            
            # Process files
            for file in resp_json['fileListAO']['fileList']:
                last_op_time = parse_cn_time(file['lastOpTime'])
                res.append({
                    'id': str(file['id']),
                    'name': file['name'],
                    'modified': last_op_time,
                    'size': file['size'],
                    'thumbnail': file['icon']['smallUrl']
                })
            
            page_num += 1
        
        return res
    
    def download(self, file_id):
        """Download file"""
        response = self._request_with_retry('GET', f"{WEB_URL}/api/open/file/getFileDownloadUrl.action", params={
            "fileId": file_id,
        })
        resp_json = response.json()
        
        if resp_json.get("res_code") == 0:
            return resp_json["fileDownloadUrl"]
        
        raise Exception(f'Failed to get download URL: {resp_json}')
    
    def get_play_url(self, file_id):
        """Get video play URL"""
        response = self._request_with_retry('GET', f"{WEB_URL}/api/portal/getNewVlcVideoPlayUrl.action", params={
            "fileId": file_id,
            "type": "2",
        })
        resp_json = response.json()
        
        if resp_json.get("res_code") == 0:
            return resp_json["normal"]["url"]
        
        raise Exception(f'Failed to get play URL: {resp_json}')
    
    def get_disk_space_info(self):
        """Get user storage size information"""
        response = self._request_with_retry('GET', f'{WEB_URL}/api/portal/getUserSizeInfo.action')
        resp_json = response.json()
            
        if resp_json.get("res_code") == 0:
            return resp_json
        
        raise Exception(f'Failed to get disk space info: {resp_json}')