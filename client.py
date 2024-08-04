import requests
import time
import random
import uuid
import math
import hashlib
import base64
import json
from cloud189.utils import rsa_encode, qs, aes_encrypt, hmac_sha1, random_string, FileStream, decodeURIComponent, encode, get_md5_encode_str, parse_cn_time
from cloud189.config import *
from cloud189.exceptions import *

class Cloud189Client:
    def __init__(self, username=None, password=None, slice_size=DEFAULT_SLICE_SIZE):
        self.username = username
        self.password = password
        self.slice_size = slice_size
        self.retry = 0
        self.session = requests.Session()
        self.rsa = {
            "Expire": 0,
            "PkId": "",
            "PubKey": "",
        }
        
    def _advreq(self, url, method, data={}, retry=0):
        headers = {
            'Accept': 'application/json;charset=UTF-8'
        }
        data['noCache'] = random_string()
        
        if method.lower() == 'get':
            response = self.session.get(url, headers=headers, params=data)
        elif method.lower() == 'post':
            response = self.session.post(url, headers=headers, data=data)
        
        if response.status_code == 200:
            response_json = response.json()
            
            if 'res_code' in response_json and response_json['res_code'] == 0:
                return response_json
            
        if retry > RETRY_MAX_COUNT:
            raise AdvReqError(f'_advreq reached retry limit')
        try:
            self._login()
            return self._advreq(url, method, data, retry + 1)
        except Cloud189Error as e:
            raise AdvReqError(f'_advreq retry: {e}')

    def _login(self):
        res = self.session.get("https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https%3A%2F%2Fcloud.189.cn%2Fmain.action")
        
        # 检查是否已登录
        redirect_url = res.url
        if redirect_url == "https://cloud.189.cn/web/main":
            return None

        # 获取 lt, reqId, appId
        lt = res.url.split("lt=")[1].split("&")[0]
        req_id = res.url.split("reqId=")[1].split("&")[0]
        app_id = res.url.split("appId=")[1].split("&")[0]

        headers = {
            "lt": lt,
            "reqid": req_id,
            "referer": redirect_url,
            "origin": "https://open.e.189.cn",
        }

        # 获取 app Conf
        app_conf_data = {
            "version": "2.0",
            "appKey": app_id,
        }
        res = self.session.post("https://open.e.189.cn/api/logbox/oauth2/appConf.do", headers=headers, data=app_conf_data)
        app_conf = res.json()

        if app_conf["result"] != "0":
            raise LoginError(f'oauth2/appConf.do: {app_conf["msg"]}')

        # 获取 encrypt conf
        encrypt_conf_data = {
            "appId": app_id,
        }
        res = self.session.post("https://open.e.189.cn/api/logbox/config/encryptConf.do", headers=headers, data=encrypt_conf_data)
        encrypt_conf = res.json()

        if encrypt_conf["result"] != 0:
            raise LoginError(f'config/encryptConf.do: {res.text}')

        login_data = {
            "version": "v2.0",
            "apToken": "",
            "appKey": app_id,
            "accountType": app_conf["data"]["accountType"],
            "userName": encrypt_conf["data"]["pre"] + rsa_encode(self.username, encrypt_conf["data"]["pubKey"]),
            "epd": encrypt_conf["data"]["pre"] + rsa_encode(self.password, encrypt_conf["data"]["pubKey"]),
            "captchaType": "",
            "validateCode": "",
            "smsValidateCode": "",
            "captchaToken": "",
            "returnUrl": app_conf["data"]["returnUrl"],
            "mailSuffix": app_conf["data"]["mailSuffix"],
            "dynamicCheck": "FALSE",
            "clientType": str(app_conf["data"]["clientType"]),
            "cb_SaveName": "3",
            "isOauth2": str(app_conf["data"]["isOauth2"]).lower(),
            "state": "",
            "paramId": app_conf["data"]["paramId"],
        }

        res = self.session.post("https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do", headers=headers, data=login_data)
        login_result = res.json()

        if login_result["result"] != 0:
            raise LoginError(f'oauth2/loginSubmit.do: {login_result["msg"]}')

        return None
    
    def _get_rsa_key(self):
        now = int(time.time() * 1000)
        if self.rsa["Expire"] > now:
            return self.rsa["PubKey"], self.rsa["PkId"]
        try:
            resp_json = self._advreq("https://cloud.189.cn/api/security/generateRsaKey.action", "GET")
            pub_key = resp_json.get("pubKey")
            pk_id = resp_json.get("pkId")
            self.rsa["PubKey"], self.rsa["PkId"] = pub_key, pk_id
            self.rsa["Expire"] = int(resp_json.get("expire"))
            return pub_key, pk_id
        except Cloud189Error as e:
            raise RsaKeyError(f'generateRsaKey.action: {e}')
        
    def _get_session_key(self):
        try:
            resp_json = self._advreq("https://cloud.189.cn/v2/getUserBriefInfo.action", "GET")
            session_key = resp_json.get("sessionKey")
            return session_key
        except Cloud189Error as e:
            raise SessionKeyError(f'getUserBriefInfo.action: {e}')
    
    def _upload_request(self, uri, form):
        c = str(int(time.time() * 1000))
        r = str(uuid.uuid4())
        l = str(uuid.uuid4()).replace("-", "")
        l = l[:16 + int(16 * random.random())]

        e = qs(form)
        data = aes_encrypt(e, l[:16])
        h = data.hex()

        session_key = self.session_key
        signature = hmac_sha1(f"SessionKey={session_key}&Operate=GET&RequestURI={uri}&Date={c}&params={h}", l)

        pub_key, pk_id = self._get_rsa_key()
        
        b = rsa_encode(l, pub_key, False)

        headers = {
            "accept": "application/json;charset=UTF-8",
            "SessionKey": session_key,
            "Signature": signature,
            "X-Request-Date": c,
            "X-Request-ID": r,
            "EncryptionText": b,
            "PkId": pk_id,
        }

        response = self.session.get(f"https://upload.cloud.189.cn{uri}?params={h}", headers=headers)

        if response.json().get("code") != "SUCCESS":
            raise UploadError(f'{uri}: {response.json().get("msg")}')

        return response.json()
    
    def upload(self, file_path, file_name, folder_id):
        session_key = self._get_session_key()
        if session_key is None:
            raise UploadError(f'failed to get session key')
        self.session_key = session_key
        
        with FileStream(file_path) as file:
            file_size = file.get_size()
            count = math.ceil(file_size / self.slice_size)

            res = self._upload_request("/person/initMultiUpload", {
                "parentFolderId": folder_id,
                "fileName": encode(file_name or file.get_name()),
                "fileSize": str(file_size),
                "sliceSize": str(self.slice_size),
                "lazyCheck": "1"
            })

            upload_file_id = res['data']['uploadFileId']
            finish = 0
            md5s = []
            md5_sum = hashlib.md5()

            for i in range(1, int(count) + 1):
                byte_size = file_size - finish
                if byte_size > self.slice_size:
                    byte_size = self.slice_size

                byte_data = file.read(byte_size)
                finish += len(byte_data)

                md5_bytes = hashlib.md5(byte_data).digest()
                md5_hex = md5_bytes.hex().upper()
                md5_base64 = base64.b64encode(md5_bytes).decode('utf-8')
                md5s.append(md5_hex)
                md5_sum.update(byte_data)

                resp = self._upload_request("/person/getMultiUploadUrls", {
                    "partInfo": f"{i}-{md5_base64}",
                    "uploadFileId": upload_file_id,
                })
                
                upload_data = resp['uploadUrls'][f"partNumber_{i}"]
                request_url = upload_data['requestURL']
                request_header = decodeURIComponent(upload_data['requestHeader'])
                upload_headers = {}
                for pair in request_header.split('&'):
                    key, _, value = pair.partition('=')  # 使用 partition 方法来分割防止多个=的异常截断
                    upload_headers[key] = value

                response = requests.put(request_url, headers=upload_headers, data=byte_data)
                response.raise_for_status()
                
                # update_progress(float(i / count))

            file_md5 = md5_sum.hexdigest()
            slice_md5 = file_md5 if file_size <= self.slice_size else get_md5_encode_str('\n'.join(md5s))

            result = self._upload_request("/person/commitMultiUploadFile", {
                "uploadFileId": upload_file_id,
                "fileMd5": file_md5,
                "sliceMd5": slice_md5,
                "lazyCheck": "1",
                "opertype": "3",
            })
            
            if result['code'] == 'SUCCESS':
                return result['file']['userFileId']
            
            raise UploadError(f'upload failed: {result}')
    
    def delete(self, file_id, file_name, is_folder=False):
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

        response = self._advreq("https://cloud.189.cn/api/open/batch/createBatchTask.action", "POST", data=form)

        if response["res_code"] != 0:
            raise DeleteError(f'createBatchTask.action: {response}')

    def get_all_files(self, folder_id):
        res = []
        page_num = 1
        
        while True:
            response = self._advreq("https://cloud.189.cn/api/open/file/listFiles.action", "GET", {
				"pageSize":   "60",
				"pageNum":    str(page_num),
				"mediaType":  "0",
				"folderId":   str(folder_id),
				"iconOption": "5",
				"orderBy":    "lastOpTime",
				"descending": "true",
			})
            
            if response['res_code'] != 0:
                raise GetFilesError(f'listFiles.action: {response}')
            
            # 已经处理到最后一页
            if response['fileListAO']['count'] == 0:
                break
            
            # 处理文件夹列表
            for folder in response['fileListAO']['folderList']:
                last_op_time = parse_cn_time(folder['lastOpTime'])
                res.append({
                    'id': str(folder['id']),
                    'name': folder['name'],
                    'modified': last_op_time,
                    'is_folder': True
                })
            
            # 处理文件列表
            for file in response['fileListAO']['fileList']:
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
    
    def get_play_url(self, file_id):
        response = self._advreq("https://cloud.189.cn/api/portal/getNewVlcVideoPlayUrl.action", "GET", {
            "fileId": file_id,
            "type": "2",
        })
        
        if response["res_code"] == 0:
            return response["normal"]["url"]
        
        raise PlayUrlError(f'getNewVlcVideoPlayUrl.action: {response}')