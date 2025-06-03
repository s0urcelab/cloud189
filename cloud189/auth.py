"""
Authentication client for the Cloud189 SDK
"""

import re
import time
import httpx
import logging
from .constants import *
from .utils import rsa_encrypt

# 禁用 httpx 的日志输出
logging.getLogger("httpx").setLevel(logging.WARNING)

class CloudAuthClient:
    """Client for handling authentication with 189 Cloud"""
    
    def __init__(self):
        self.session = httpx.Client(follow_redirects=True)
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'application/json;charset=UTF-8'
        })
        # Register response hook
        self.session.event_hooks['response'] = [self._after_response]
    
    def _after_response(self, response, **kwargs):
        """Handle response after receiving"""
        try:
            data = response.json()
            if 'result' in data and 'msg' in data:
                result = data['result']
                msg = data['msg']
                
                if result == 0:  # Success
                    pass
                elif result == -117:
                    raise Exception(f'Invalid Refresh Token Error: {msg}')
                else:
                    raise Exception(f'Auth API Error: {msg}')
        except:
            pass
            
        return response
    
    def get_encrypt(self):
        """Get encryption parameters"""
        resp = self.session.post(f'{AUTH_URL}/api/logbox/config/encryptConf.do')
        return resp.json()
    
    def get_login_form(self):
        """Get login form parameters"""
        params = {
            'appId': APP_ID,
            'clientType': CLIENT_TYPE,
            'returnURL': RETURN_URL,
            'timeStamp': int(time.time() * 1000)
        }
        
        resp = self.session.get(f'{WEB_URL}/api/portal/unifyLoginForPC.action', params=params)
        text = resp.text
        
        if text:
            captcha_token = re.search(r"'captchaToken' value='(.+?)'", text).group(1)
            lt = re.search(r'lt = "(.+?)"', text).group(1)
            param_id = re.search(r'paramId = "(.+?)"', text).group(1)
            req_id = re.search(r'reqId = "(.+?)"', text).group(1)
            
            return {
                'captchaToken': captcha_token,
                'lt': lt,
                'paramId': param_id,
                'reqId': req_id
            }
        return None
    
    def _build_login_form(self, encrypt, app_conf, username, password):
        """Build login form data"""
        key_data = f"-----BEGIN PUBLIC KEY-----\n{encrypt['pubKey']}\n-----END PUBLIC KEY-----"
        username_encrypt = rsa_encrypt(key_data, username)
        password_encrypt = rsa_encrypt(key_data, password)
        
        return {
            'appKey': APP_ID,
            'accountType': ACCOUNT_TYPE,
            'validateCode': '',
            'captchaToken': app_conf['captchaToken'],
            'dynamicCheck': 'FALSE',
            'clientType': '1',
            'cb_SaveName': '3',
            'isOauth2': 'false',
            'returnUrl': RETURN_URL,
            'paramId': app_conf['paramId'],
            'userName': f"{encrypt['pre']}{username_encrypt}",
            'password': f"{encrypt['pre']}{password_encrypt}"
        }
    
    def get_session_for_pc(self, redirect_url=None, access_token=None):
        """Get session for PC client"""
        params = {
            'appId': APP_ID,
            'clientType': PC,
            'version': VERSION,
            'channelId': CID,
            'rand': int(time.time() * 1000),
        }
        
        if redirect_url:
            params['redirectURL'] = redirect_url
        if access_token:
            params['accessToken'] = access_token
            
        resp = self.session.post(f'{API_URL}/getSessionForPC.action', params=params)
        return resp.json()
    
    def login_by_password(self, username, password):
        """Login using username and password"""
        # Get encryption parameters and login form
        encrypt = self.get_encrypt()
        app_conf = self.get_login_form()
        
        # Build login form data
        data = self._build_login_form(encrypt['data'], app_conf, username, password)
        
        # Submit login
        headers = {
            'Referer': AUTH_URL,
            'lt': app_conf['lt'],
            'REQID': app_conf['reqId']
        }
        
        resp = self.session.post(
            f'{AUTH_URL}/api/logbox/oauth2/loginSubmit.do',
            data=data,
            headers=headers
        )
        login_res = resp.json()
            
        # Get session
        return self.get_session_for_pc(redirect_url=login_res['toUrl'])
    
    def login_by_access_token(self, access_token):
        """Login using access token"""
        return self.get_session_for_pc(access_token=access_token)
    
    def login_by_sso_cookie(self, cookie):
        """Login using SSO cookie"""
        params = {
            'appId': APP_ID,
            'clientType': CLIENT_TYPE,
            'returnURL': RETURN_URL,
            'timeStamp': int(time.time() * 1000)
        }
        
        # Get login page
        resp = self.session.get(f'{WEB_URL}/api/portal/unifyLoginForPC.action', params=params)
        redirect_url = resp.url
            
        # Follow redirect with cookie
        headers = {'Cookie': f'SSON={cookie}'}
        resp = self.session.get(redirect_url, headers=headers)
        return self.get_session_for_pc(redirect_url=str(resp.url))
    
    def refresh_token(self, refresh_token):
        """Refresh access token"""
        data = {
            'clientId': APP_ID,
            'refreshToken': refresh_token,
            'grantType': 'refresh_token',
            'format': 'json'
        }
        
        resp = self.session.post(f'{AUTH_URL}/api/oauth2/refreshToken.do', data=data)
        return resp.json()