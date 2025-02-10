import hashlib
import base64
import time
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac

# https://shopify.dev/docs/api/multipass
# Author: ysh.agrwl@gmail.com

class ShopifyMultipass:
    def __init__(self, multipass_secret):
        key_material = hashlib.sha256(multipass_secret.encode('utf-8')).digest()
        self.encryption_key = key_material[:16]
        self.signature_key = key_material[16:32]

    def generate_token(self, customer_data_hash):
        customer_data_hash["created_at"] = datetime.now().isoformat()

        ciphertext = self.encrypt(json.dumps(customer_data_hash))

        return base64.urlsafe_b64encode(ciphertext + self.sign(ciphertext)).decode('utf-8')  # Decode to string


    def encrypt(self, plaintext):
        cipher = AES.new(self.encryption_key, AES.MODE_CBC)
        iv = cipher.iv  # The IV is generated automatically by PyCryptodome
        padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size) # Pad the plaintext
        ciphertext = cipher.encrypt(padded_plaintext)
        return iv + ciphertext

    def sign(self, data):
        return hmac.new(self.signature_key, data, hashlib.sha256).digest()


# Usage example

# pip install pycryptodome==3.21.0

# customer_data = {
#     "email": "nicpotts@example.com"
# }

# token = ShopifyMultipass("multipass secret from shop admin").generate_token(customer_data)
# print(token)

# redirect user to /account/login/multipass/token