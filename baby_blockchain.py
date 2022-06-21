from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512


class KeyPair:
    private_key: str
    public_key: str

    def genKeyPair(self):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        file_out = open("private_key.pem", "wb")
        file_out.write(self.private_key)
        file_out.close()

        self.public_key = key.publickey().export_key()
        file_out = open("public_key.pem", "wb")
        file_out.write(self.public_key)
        file_out.close()

    def printKeyPair(self):
        self.private_key = open("private_key.pem", "rb")
        self.public_key = open("public_key.pem", "rb")
        print(self.private_key.read())
        print(self.public_key.read())


class Signature:
    plaintext: str
    key: str
    hash_algorithm: str
    sign: str

    def signData(self, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
        signer = PKCS1_v1_5.new(RSA.importKey(key))
        hash_value = hash_algorithm.new(plaintext)
        return signer.sign(hash_value)

    def verifySignature(self, sign, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
        hash_value = hash_algorithm.new(plaintext)
        verifier = PKCS1_v1_5.new(RSA.importKey(key))
        return verifier.verify(hash_value, sign)

    def getSignature(self):
        private_key = open("private_key.pem", "rb")
        message = 'Signature RSA'
        signature = Signature().signData(message.encode(encoding='utf-8'), private_key.read())
        return signature

    def printVerifySignature(self):
        public_key = open("public_key.pem", "rb")
        message1 = 'Signature RSA'
        print(Signature().verifySignature(Signature().getSignature(), message1.encode('utf-8'), public_key.read()))

    def printSignature(self):
        private_key = open("private_key.pem", "rb")
        message = 'Signature RSA'
        signature = Signature().signData(message.encode(encoding='utf-8'), private_key.read())
        print(signature)
