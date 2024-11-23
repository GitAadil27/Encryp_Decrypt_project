from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from Crypto.Util.Padding import unpad
import os
from Crypto.Cipher import AES
import json

def decrypt_rsa(encrypted_key, private_key_path):
    # Load your private RSA key
    with open(private_key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=b"city123")

    # Decrypt the key
    decrypted_key = private_key.decrypt(
        b64decode(encrypted_key),
        padding.PKCS1v15()
    )
    return decrypted_key





private_key_file = 'HDFC_priv.key'  # Update this path to your private key file
passphrase = 'city123'  # Your passphrase as a simple string
encrypted_message = b"0XeDZOTZveSvfXaW1tCZSBNV57ZTAp4loHeFZQhYglvWb29tETUDVuLWksGsfFOCtOFGdF0bT8b1GIOd1grIHnsCfhvKTmztLt+9QAGyxBu96PQxp/YXmVOdzu5pSFtBt9RKWZAvru189BP77wVdsa28F6TPjPp5rbhf/C94tQCx0Astqjh52jS+4h2SuAjytbgs3rd8HejnLda5zaENx2Qsn6b4pdG4jdOqy+OKQfDiJf8PO8c3rwmo/8gz3VhzBP2BRIFW3Wfcu6w6N0B1hQjrGEqfJfoC4XwfuETU9TUbjtDN5feoyG4/eg8CVKq2wX9K/fXa1ORw3568J0u2mANKwbP60TizzV4H35s+0b/lSui1pImRY/ZF0FAtmwaPHOCOAyzmN+YwOCFCpV1It+w/J9Cc0PMvADyUaYy7VRyflzgKz3y18K73gtqnJ06Q5ppBBb5n8+H6YilI/AGmS+HDn4n1gVEe7Z6vI7VT/Q1GyaWRJI39fHimssNe0EOCebriT9Fzn3XQHwUbuVAmA6cL9762fRbX3FLdQmp2USlaO4oYCIZCpsvxabhFtC56UNRAjxi5/KRTQKKCnBUvrfTqHf4SpxMoxGZ+/m25F5LPhCUUbdXmGxmj0KjYV+c+jTbCLlimm3JT3yxkXDOSJ2dVeprgKeJZRISBCkz+JYh423NoH0dqO0ZUKVNrjdjSllo+DlQCK0hw3lSnPpw4mjJ83VQkoO+imi0avUoaw6W/VcT1L6eOYJqCA9bERtuvYzBQUKwNILkV2KejTAHh9gHTOuzZe77hoLI5H7c9VGisb1O+4QY9X1y9CKjuCWq9RPMIDqXFLb8F2NNuxvymt80xmIbEu2GPId06S6erzNJa7FZc0yetottOflv3gwn/QicrWgkB026Z2vQvNHOKUw6Csg0GAzirqbaumHhyTsTV98GW+XpiMLfGyiDpszrgpmtM8/H8+1Dtf+9b0GH4jxIYE44/RGLo8AX4PIUyO7gSkRtBsbr3Cb68J+lUsHMwabxc4nEw5doBey/F9dHz90NvrLgMWAvNWOfEFUdD55fsRLUZQzeN7ZOiHsKvCac9+OL1VErWXTnP/ZIZsnZVZQDluOjYoe+9fao10JMkOojOdotmjuZWAb2jD/FOot0LjMR4k9HuEAIu9hfGJFXxCxtt5mtLyHXATS9Zq4IErceMEBfkTK0eOWNBHTL6GkK6Z6XnPE9ekyATLzhi/PGC8ksBX3KJ2x4f+xZd4Zlh42+KpuKiyTdJVzWBKvBCMibiRnieR84PmhNYrT40WbACbvy/TBYcc12tK92MiIvuqR1RZ+0OMUwrIUwRg4ShD8O0CW61HqKAwCclG/XNaKicOEjlvNX/wyGGvVKdA6a9CKSmYVXZ0HwjcRcpfadLIcq//e6NfnT4zeJkb4ywKK9axcEDl5aWtutzAitqeha11vQREzCvGwFkPoqO0r6aOQtPOUYmp7MrsVq0cuQXCYMBdJzl3xkpfJ09/OyfGstIMI0YjtCdBKSR0M8xbe4Mit7U5+v1TzlE7kS2ZBCTfrtDJax9HTK+/PI2pr2Fzv7K8/JUVUOcXQCHrF90E90rbyk6LQ4b062X6kX45YjFJJgVh03qULpokd9PB8Qyjbi3V1k5+QYCKx99XeBUGlF4ktTIBHn94A0Xx2e6aOzOXp4AGkYDEMeCSDK69bEoPVqIssiexpXfDf4KJ1PXH8mK0XTH3u7YbnyGymL/bvbmyiQzNw=="
encrypted_symmetric_key = "VXsxcyiBtOMvHLcqXW7DG8pmVnyRD/Z6fkQKM9LPN3yLl2yup4S43ix2hWkeEuCg9Je37DDvmQbm6woZy4UZcFi3NcprUAn6X01ZBIKKTWXoPv4kG3UgWFcw3jbuT5RzLEjfb3y/gHhM5O90Df5IIWGp74e830MdSF3Xr6SpJYBDc9lFTOLfEeLpz1VF1roVx1Uo/LUtqjYnRwU6bTJa6MY1lYs3V14P7egM8CV7xN91MWF06wsLwUnBEmxqDOiT0yPukINy2k18Z7jOqad6H5FJn8NCWgfjMYRZKGACfnSpaQf1kHCK5DfsnoA8P2Dsgy1TuK/61+PHKCuE7zoRLQ=="
decrypted_key = decrypt_rsa(encrypted_symmetric_key, "private_key.pem")

encoded_data =  b64decode(encrypted_message)
IV = encoded_data[:16]

encrypted_message_2 = encoded_data[16:]

cipher = AES.new(decrypted_key, AES.MODE_CBC, IV)

decrypted_data = cipher.decrypt(encrypted_message_2)
# Handling padding
try:
    # Unpad if your library doesn't automatically handle padding
    from Crypto.Util.Padding import unpad
    decrypted_data = unpad(decrypted_data, AES.block_size)
except ValueError:
    print("Incorrect padding")

# Decode or further process
print(decrypted_data.decode('utf-8'))

encrypted_jwt = decrypted_data.decode('utf-8')
array_of_jwt = encrypted_jwt.split(".")
header_encoded = array_of_jwt[0]
payload_encoded = array_of_jwt[1]
signature = array_of_jwt[2]


#print('hello' , urlsafe_b64decode(encrypted_jwt))


def base64_url_decode(encoded_str):
    encoded_str += '=' * ((4- len(encoded_str) % 4)% 4)
    encoded_str = encoded_str.replace('-', '+').replace('_', '/')
    return b64decode(encoded_str)

header_json = json.loads(base64_url_decode(header_encoded))
payload_json = json.loads(base64_url_decode(payload_encoded))

print('Header: ', json.dumps(header_json, indent=4))
print('Payload: ', json.dumps(payload_json, indent=4))
