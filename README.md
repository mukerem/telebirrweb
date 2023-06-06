# telebirr 

Python package for integrating telebirr web API with your project.

# telebirrweb Integration Guide

#### Step 1:

Create required values for the telebirr API. There are 12 values needed to send the request.

```python
    url = "http://196.188.120.3:11443/ammapi/payment/service-openup/toTradeWebPay/"
   appId = "a00db682c0444a9bb80ce6b1a94a1ea1"
   appKey = "87d557614c344eda8adde60657f147b5"
   receiveName = "FamilySooq"
   shortCode = "220121"
   timeoutExpress = "5"
   timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   nonce = “GFGHG521DF5GDFG12DGFGD5FG46DFG5”
   outTradeNo = “78EYRFDBVJHXDJLCKXJVCXVKCV”
   totalAmount = 100
   notifyUrl =     "https://a.familysooq.com/api/payment/telebirr/confirm/product-post/"
    returnUrl = "https://familysooq.com/detail/1/"
```


`appId`, `appKey`, and `shortCode` are given by telebirr adminstrator. The `timestamp` is the current time(request sent time) `nonce` and `outTradeNo` are unique generated numbers


#### Step 2:
Create `stringA` by concatenating those 12 values with their key name. The string must be concatinted in ascending order.

```python
stringA = f"appId={appId}&appKey={appKey}&nonce={nonce}&notifyUrl={notifyUrl}&outTradeNo={outTradeNo}&receiveName={receiveName}&returnUrl={returnUrl}&shortCode={shortCode}&subject={subject}&timeoutExpress={timeoutExpress}&timestamp={timestamp}&totalAmount={totalAmount}"
```


#### Step 3:
Create JSON object by using these 12 values with their key. The key of the JSON is not allowed to change.

```python
ussdjson = {
       "appId":appId,
       "nonce":nonce,  
       "notifyUrl":notifyUrl,
       "outTradeNo":outTradeNo,
       "receiveName":receiveName,
       "returnUrl":returnUrl,
       "shortCode":shortCode,
       "subject":subject,
       "timeoutExpress":timeoutExpress,
       "timestamp":timestamp,
       "totalAmount":totalAmount,
   }
   ussdjson = json.dumps(ussdjson).encode('utf-8')
```

#### Step 4:
Encrypt the JSON object by using the public key (Use an environment variable to store the public key). The public key is provided by telebirr administrator. The encryption method is RSA 2048. In RSA 2048 the maximum allowed text size is 245. But in our case the text length is more than 245, so we split the data(text/cipher) up to 245 bytes and encrypt each chunk. Then concatenate the encrypted data.

```python
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
publicKey = “rhdFJAvK5q2X58oyPhCqClDQxaox/3+4nr6IDuIethHNMEt2hn1yjjrfdcxswedf
p0+rte5r1RjF2MU+O8D+dtfvgyhbjnkfghbjnkmc1LOzxroznnJ+VEYAjAJpuhTD
WaQMkaD2XNzXXzy2jFk0XjdJ5SSM00m+pAqke7uxmmitoVdcX4U9vsLZIkP5YHfT
K5hJH4bLDOIOjGDEl8kB0yWUibHOY1p+cWQAE/9nyfCI1c2b0COPfcLAKDhKipW1
kzksOwKBgC51Z4JX/90XJfq5WNuaxDH2LmO69ICfks/6gQFFUfaozNPLzGTBxV6O
XqsMdg4x4DWDSep9qhOHV7hYywsDSeIwf+zzXkKN+QwjwiNcxxWAlwsJ2n/FtMKv
4jW1Ahyis5On+mWynJFJDv35Bv4uPvXYEa55Iq2ZIwXMOl+U4se8
”

public_key = RSA.import_key(base64.urlsafe_b64decode(publicKey))
encryptor = PKCS1_v1_5.new(public_key)

maxEncryptSize = 245
bufferSize = len(ussdjson)
buffersCount = int(math.ceil(bufferSize / maxEncryptSize)) # total buffers count for encrypt
dividedSize = int(math.ceil(bufferSize / buffersCount)) # each buffer size

try:
   result = []
   for bufNum in range(buffersCount):
       result.append(encryptor.encrypt(ussdjson[bufNum * dividedSize: (bufNum + 1) * dividedSize]))
   encrypted_decode = b"".join(result)
   encrypted_encode = base64.b64encode(encrypted_decode)
   encrypted = str(encrypted_encode, "utf-8")
except Exception as e:
   raise NotFound(e)
```

#### Step 5:
Create new `StringB` by hashing `StringA`. Use SHA256 to hash the given string.

```python
stringB = sha256(stringA.encode()).hexdigest().upper()
```

#### Step 6:
Send a request to the given URL. The content-type format must be application/JSON. The request data are `appId`, `encrypted`, and `stringB`. `appId` is given by telebirr adminstrator. `Encrypted` is the encrypted data and `stringB` is hashed data.

This is sample data for the request

```python
{
   "appid": "a00db682c0444a9bb80ce6b1a94a1ea1",
   "sign": "FBC7FC87F5C18A2142B8A905A885A244530D587E1243D0F2F05E2649494FC0A6",
   "ussd": "QHcp4WhzXO7QCSE8pOtEPbvJqxf4ERjd7z6pEDkukQ0/Hgfn1lq1oVLiJ2S5vHKAHurtu/dwmpRitJhJMY5y2zL6k38QFW5lJj7eWj17VwfYBvFUcVjQVl+pODwFEr5s+m9H9tiTdSDvSl+K3gXvUc4Vvray8nio/nHBE03+/asA0ZjW+RGpS+soU0qe8NBBugIArVjcEnZk33TzamXO9EIuY0riy2rgatEo1Q7B2fAJqIiPw0ArmvzX7a1/7WMcR9E5mlveMDoqHaNPsgI2AcHuxCBo38hdiVXGXUwOItn5DxEjIjkS1tGV78Rkanh01ENXJuB5bdihla7Xe+VxgWMqcricnQ/Wj2yztoAeGas+pgCvITgwpF9tpgHss470J07UjkTeFCWWJkrI0wZfEaedxonZR2barMcOP+40zoefbHBuc4uK0KYKZ0MgVEVfbvuSs/qc47q/NLIFFTw43Lpqu5zilFSEr+LnuYSvI68YiiTFNE5Ex3NBzOR7ixndvl/p+szRYy28ggmejJmfKsOP3E4UdOuCegDUPY4ml45YaPWZrPnlqxEilIIBtq+ckUhaLlfHuJBVSPgmUmnSrSu/fqPwe2PJKArtsS4EkyuxnqXfZUEuburd++mB1vLvr+c3WOsfqW5gEAh4B7EBCnvQk69Y5xiIdpYVGl2/0jQ="
}

data = {"appid": appId, "sign": stringB, "ussd": encrypted}
headers = {
   "Content-Type": "application/json;charset=utf-8",
}
timeout = 5

param = {
   "subject": subject,
   "nonce": nonce,
   "outTradeNo": outTradeNo,
   "timestamp": timestamp,
   "amount": totalAmount,
   "reason": reason
}
   response = requests.post(url=url, json=data, headers=headers, timeout=timeout)
```


### Step 7:
The response is returned by the telebirr API. If the process is successful then they return `topayURL`. Then return the response URL to the user.

#This is sample return response

```json
{
   "code":0,
   "msg":"success",
   "data":{
       "toPayUrl":"https://h5pay.trade.pay/payId=RE9879T0972S"
   }
}
```

#### Step 8:
After success payment transaction telebirr notify the success transaction using notify url that is given by our system in step 1. The return data is encrypted string. So you must decrypt the text using the same public key given by telebirr adminstrator.

*** They call your notify url API using text media as parser format. So your notify API must be accept Text /plain type request datas. ***

#This is sample notify data
   
```python   b'QXxPG958j8RTifoKcONoelrH8XSP7vZWajUw2tR07b1/sypWU/sXQAPH0fCUI6jL4I/E7apmGy7CC9hQ4UU7YeYzXduPKgsWr65qrTZDKHKaVflYmwl9IdJCSJYGl36awdRZ4LsAhQ/Jp58XKkyR7848gNlFx0o3J2ziT/IdIRq13e12FwIhZiUzoOH0wmnoIVMiDJtZq+9A5GrsOPdy1V2nTM/tgl088tA97kIoNC4sqDKqyfbs1OY+CzdNb+LhvX/HlG/f2yWTE+ZQG1g+bWT+i33k/+vbvyIHFBdHr3snaJbDzUdYL9SGFUU2JcIvGr24xYLnybVpNtaB9uOjonBKLJqNTzq5sghed1IKYnghUemVU1nUoFXC/mGA+ePX0PqyzxYPt75sfeHUkTlmzDbc5fCFZpkPEbd6v2vtMOlcGrk3hhh2crAvfK7WmOtV/WnnNRFkqpKuJJV01+jPq+Sg+xCOjjphlw5/2gLkdpUSsGvNK8AQMAlG6BWKKtyIfKRaaY0clHmmcF4XVYk1tDoSSdIJw8cAKOwr/gvtFDd/8Z7VXu4376ELZeOEmKiNE+xV5usX92ltzTBwGuMci4FCFs7XBAqQgYdwrbfOoxVEnnND1cedOMWxshxB4tfHOfuloYBtH9dfUZGMgTJ3cy4BW/KSa9mF2JK64ZDen7I='
```

Create text parser for the DRF api

```python
from rest_framework.parsers import BaseParser
class PlainTextParser(BaseParser):
   """
   Plain text parser.
   """
   media_type = 'text/plain'


   def parse(self, stream, media_type=None, parser_context=None):
       """
       Simply return a string representing the body of the request.
       """
       return stream.read()
```

#### Step 9:
Decrypt the request. 

```python
import base64
import json
import rsa
import six


from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


class DecryptByPublicKey(object):
   """
        the modulus factor is generated first
        the rsa public key is then generated
        then use the rsa public key to decrypt the incoming encryption str
   """
   def __init__(self):
       public_key =  RSA.import_key(base64.urlsafe_b64decode(publicKey))
       self._modulus = public_key.n   #  the modulus
       self._exponent = public_key.e  #  factor
       try:
           rsa_pubkey = rsa.PublicKey(self._modulus, self._exponent)
           self._pub_rsa_key = rsa_pubkey.save_pkcs1() #  using publickey ( modulus, factor ) calculate a public key
       except Exception as e:
           raise e


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
               raise e
       else:
           raw_info = decrypted_bytes
       return raw_info.decode("utf-8")


def get_decrypt_data(data):
   try:
       data = base64.b64decode(data)
   except Exception as e:
       raise NotFound(e)

   decryptor = DecryptByPublicKey()
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
       raise NotFound(e)
   response = json.loads(message)
  
   if response:
       outTradeNo = response.get('outTradeNo')
       tradeNo = response.get('tradeNo')
       return outTradeNo, tradeNo, response
   else:
       raise NotFound("Invalid response") # log to admin
 ```  
     
The decrypted data consists of `msisdn`, `totalAmount`, `tradeDate`, `transactionNo`, `outTradeNo` and `tradeNo`. 
`outTradeNo` is the requested data generated by our system and `tradeNo` is the user's telebirr account unique trade number.

# sample decrypted data

```json
{
'msisdn': '251900000032', 
'totalAmount': '10',
'outTradeNo': 'CEvSC7isJ74rrXqLVUwkraECfHARP6NL', 
'tradeDate': 1647421757000, 
'tradeNo': '202203161208521504021872763195393', 
'tradeStatus': 2, 
'transactionNo': '9CG90NCOK5'
}
```
