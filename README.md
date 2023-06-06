# telebirrweb

Python package used to integrating telebirr web API with your project.

```python
import os
from dotenv import load_dotenv
from telebirrweb import TelebirrWeb
from utils import generate_unique

load_dotenv()

telebirrAppID = os.environ.get("TelebirrAppID")
telebirrAppKey = os.environ.get("TelebirrAppKey")
telebirrShortCode = os.environ.get("TelebirrShortCode")
telebirrPublicKey = os.environ.get("TelebirrPublicKey")
receiveName = "Test"

tele = TelebirrWeb(telebirrAppID, telebirrAppKey, telebirrShortCode, telebirrPublicKey, receiveName)
subject = "Payment"
totalAmount = 10
nonce = generate_unique([], 32)
outTradeNo = generate_unique([], 32)
notifyUrl = "https://example.com/"
returnUrl = "https://example.com/"

response = tele.send_request(subject, totalAmount, nonce, outTradeNo, notifyUrl, returnUrl)
print(response)
```
