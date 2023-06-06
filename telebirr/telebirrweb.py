import base64
import datetime
import json
import math
import requests
import rsa
import six

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from hashlib import sha256
from urllib3.exceptions import *


class DecryptByPublicKey(object):
    """
         the modulus factor is generated first 
         the rsa public key is then generated 
         then use the rsa public key to decrypt the incoming encryption str
    """
    def __init__(self, publicKey):
        public_key =  RSA.import_key(base64.urlsafe_b64decode(publicKey))
        self._modulus = public_key.n   #  the modulus 
        self._exponent = public_key.e  #  factor 
        try:
            rsa_pubkey = rsa.PublicKey(self._modulus, self._exponent)
            self._pub_rsa_key = rsa_pubkey.save_pkcs1() #  using publickey ( modulus, factor ) calculate a public key 
        except Exception as e:
            raise TypeError(e)

    def decrypt(self, b64decoded_encrypt_text) ->str:
        """
        decrypt msg by public key
        """
        public_key = rsa.PublicKey.load_pkcs1(self._pub_rsa_key)
        encrypted = rsa.transform.bytes2int(b64decoded_encrypt_text)
        decrypted = rsa.core.decrypt_int(encrypted, public_key.e, public_key.n)

        decrypted_bytes = rsa.transform.int2bytes(decrypted)
        if len(decrypted_bytes) > 0 and list(six.iterbytes(decrypted_bytes))[0] == 1:
            try:
                raw_info = decrypted_bytes[decrypted_bytes.find(b'\x00')+1:]
            except Exception as e:
                raise TypeError(e)
        else:
            raw_info = decrypted_bytes
        return raw_info.decode("utf-8")


class TelebirrWeb:
    def __init__(self, appId, appKey, shortCode, publicKey, receiveName) -> None:
        self.appId = appId
        self.appKey = appKey
        self.shortCode = shortCode
        self.publicKey = publicKey
        self.receiveName = receiveName
        self.url = "https://app.ethiomobilemoney.et:2121/ammapi/payment/service-openup/toTradeWebPay"

    def send_request(self, subject, totalAmount, nonce, outTradeNo, notifyUrl, returnUrl=None):
        if totalAmount <= 0:
            raise TypeError("amount must be greater than 0.")

        timeoutExpress = 5
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        stringA = f"appId={self.appId}&appKey={self.appKey}&nonce={nonce}&notifyUrl={notifyUrl}&outTradeNo={outTradeNo}&receiveName={self.receiveName}&returnUrl={returnUrl}&shortCode={self.shortCode}&subject={subject}&timeoutExpress={timeoutExpress}&timestamp={timestamp}&totalAmount={totalAmount}"
        ussdjson = {
            "appId":self.appId,
            "nonce":nonce,   
            "notifyUrl":notifyUrl,
            "outTradeNo":outTradeNo,
            "receiveName":self.receiveName,
            "returnUrl":returnUrl,
            "shortCode":self.shortCode,
            "subject":subject,
            "timeoutExpress":timeoutExpress,
            "timestamp":timestamp,
            "totalAmount":totalAmount,
        }

        ussdjson = json.dumps(ussdjson).encode('utf-8')
        public_key = RSA.import_key(base64.urlsafe_b64decode(self.publicKey))
        encryptor = PKCS1_v1_5.new(public_key)

        maxEncryptSize = 245
        bufferSize = len(ussdjson)
        buffersCount = int(math.ceil(bufferSize / maxEncryptSize)) # total buffers count for encrypt
        dividedSize = int(math.ceil(bufferSize / buffersCount)) # each buffer size

        try:
            result = []
            for bufNum in range(buffersCount):
                decrypted_cipher = encryptor.encrypt(ussdjson[bufNum * dividedSize: (bufNum + 1) * dividedSize])
                result.append(decrypted_cipher)
            encrypted_decode = b"".join(result)
            encrypted_encode = base64.b64encode(encrypted_decode)
            encrypted = str(encrypted_encode, "utf-8")
        except Exception as e:
            raise TypeError(e)

        stringB = sha256(stringA.encode()).hexdigest().upper()
        data = {"appid": self.appId, "sign": stringB, "ussd": encrypted}
        headers = {
            "Content-Type": "application/json;charset=utf-8",
        }
        timeout = 5

        try:
            response = requests.post(url=self.url, json=data, headers=headers, timeout=timeout)
        except requests.exceptions.Timeout as e:
            raise e

        if not response.ok:
            raise TypeError("Telebirr Transaction Failed")

        response = response.json()
        return response
    

    def get_decrypt_data(self, data):
        try:
            data = base64.b64decode(data)
        except Exception as e:
            raise TypeError(e)

        decryptor = DecryptByPublicKey(self.publicKey)
        maxEncryptSize = 256
        bufferSize = len(data)
        buffersCount = int(math.ceil(bufferSize / maxEncryptSize)) # total buffers count for decrypt
        dividedSize = int(math.ceil(bufferSize / buffersCount)) # each buffer size
        result = []

        try:
            for bufNum in range(buffersCount):
                encrypted_text = decryptor.decrypt(data[bufNum * dividedSize: (bufNum + 1) * dividedSize])
                result.append(encrypted_text)
            message = "".join(result)
        except Exception as e:
            raise TypeError(e)
        
        response = json.loads(message)
        
        if response:
            return response
        else:
            raise TypeError("Invalid response")