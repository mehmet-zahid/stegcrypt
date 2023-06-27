
# Encrypt data and Putting the data into an image and decrypting it back to the original data

** run hide_data.py to test code.** 

## Encrypting data

```python
from aes_enc import MyCipher
from stegano import lsb
import binascii


# Example usage
message = "This is a secret message"
print('Message:', message)
mycipher = MyCipher('secret')
encrypted = mycipher.encrypt_data(message)
encrypted_str = binascii.hexlify(encrypted).decode('utf-8')
print(encrypted)

secret = lsb.hide("c.png", encrypted_str)
secret.save("cm.png")

print('-' * 50)

# get encrypted message from image
message_to_decrypt = lsb.reveal("cm.png")
message_to_decrypt = binascii.unhexlify(message_to_decrypt.encode('utf-8'))
print(message_to_decrypt)
decrypted = mycipher.decrypt_data(message_to_decrypt)
print(decrypted)

```

