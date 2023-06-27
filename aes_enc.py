import pyaes, pbkdf2, binascii, os, secrets


class MyCipher:
    def __init__(self, password=None, key=None, iv=None) -> None:
        if key is None:
            if password is None:
                raise ValueError('Password must be specified')
            self.key = self.generate_key(password)
            self.iv = secrets.randbits(256)
            # save key and iv to file
            self.save_key(self.key)
            
        
        print('AES encryption key:', binascii.hexlify(self.key).decode('utf-8'))
        print('AES encryption iv:', self.iv)

    def generate_key(self, password: str) -> bytes:
        passwordSalt = os.urandom(16)
        key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
        return key
    
    def read_key(self, path='key') -> bytes:
        with open(path, 'rb') as f:
            key = f.read()
        return key
    
    def save_key(self, key: bytes) -> None:
        with open('key', 'wb') as f:
            f.write(key)
    
    def read_iv(self, path='iv') -> int:
        with open(path, 'rb') as f:
            iv = f.read()
        return iv
    
    def save_iv(self, iv: int):
        with open('iv', 'wb') as f:
            f.write(iv)


    def encrypt_data(self, data: str) -> bytes:
        aes = pyaes.AESModeOfOperationCTR(self.key, pyaes.Counter(self.iv))
        ciphertext = aes.encrypt(data)
        return ciphertext
    

    def decrypt_data(self, encrypted_data: bytes) -> str:
        aes = pyaes.AESModeOfOperationCTR(self.key, pyaes.Counter(self.iv))
        decrypted = aes.decrypt(encrypted_data)    
        return decrypted
    
if __name__ == '__main__':
    mycipher = MyCipher(password='secret')
    message = 'This is a secret message'
    print('Message:', message)
    encrypted = mycipher.encrypt_data(message)
    decrypted = mycipher.decrypt_data(encrypted)
        