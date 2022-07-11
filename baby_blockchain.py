from Crypto.Hash import SHA
from Crypto.Hash import RIPEMD160
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import Crypto.Hash.SHA512
import hashlib
import collections

class HASH:
    def SHA1(self, *message):
        hashing_text = ""
        h = hashlib.sha1()
        for mes in message:
            hashing_text += str(mes)

        h.update(hashing_text.encode('utf-8'))
        return h.hexdigest()


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


class Account:
    def __init__(self):
        key = RSA.generate(2048)
        self._private_key = key.export_key()
        self._public_key = key.publickey().export_key()
        self._signer = PKCS1_v1_5.new(self._private_key)
        self._wallet = list()
        self._balance = 0

    @property
    def genAccount(self):
        hash_object = hashlib.sha1(self._public_key)
        pbHash = hash_object.digest()
        account = RIPEMD160.new(pbHash)
        return account.hexdigest()

    def addKeyPairToWallet(self):
        file_out = open("private_key.pem", "wb")
        file_out.write(self._private_key)
        file_out.close()

        file_out = open("public_key.pem", "wb")
        file_out.write(self._public_key)
        file_out.close()

        self._wallet = [self._private_key, self._public_key]
        return self._wallet

    def updateBalance(self, b):
        self._balance = b

    def getBalance(self):
        return self._balance

    def printBalance(self):
        print(self._balance)

    def signature(self, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
        signer = PKCS1_v1_5.new(RSA.importKey(key))
        hash_value = hash_algorithm.new(plaintext)
        return signer.sign(hash_value)

    def verifySignature(self, sign, plaintext, key, hash_algorithm=Crypto.Hash.SHA512):
        hash_value = hash_algorithm.new(plaintext)
        verifier = PKCS1_v1_5.new(RSA.importKey(key))
        return verifier.verify(hash_value, sign)

    def signData(self):
        message = input("Write message which you want to signature:")
        signature = Account().signature(message.encode(encoding='utf-8'), self._private_key)
        return Account().verifySignature(signature, message.encode('utf-8'), self._public_key)

    def createPaymentOp(self, Account, amount, index):
        if self._balance >= amount:
            return collections.OrderedDict({
                'recipient': Account,
                'value': amount,
                'index': index})
        else:
            return "YOU DONT HAVE ENOUGH MONEY!"


class Operation:
    def __init__(self, sender=Account(), recipient=Account(), amount=0, signature=b''):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def getSignature(self):
        private_key = open("private_key.pem", "rb")
        message = self.sender.genAccount
        self.signature = Signature().signData(message.encode(encoding='utf-8'), private_key.read())
        return self.signature

    def createOperation(self):
        return self.sender, self.recipient, self.amount, Operation().getSignature()

    def signData(self, operation):
        private_key = open("private_key.pem", "rb")
        public_key = open("public_key.pem", "rb")
        self.signature = Signature().signData(str(operation).encode(encoding='utf-8'), private_key.read())
        return Signature().verifySignature(self.signature, str(operation).encode('utf-8'), public_key.read())

    def __str__(self):
        return ("Sender: %s\nRecipient: %s\nAmount: %s\nSignature: %s\n" % (
            self.sender, self.recipient, self.amount, Operation().getSignature()))


class Transaction:

    def __init__(self, transaction=[], nonce=0):
        self.transaction = transaction
        self.nonce = nonce

    def createOperation(self, transaction, nonce):
        return collections.OrderedDict({
            'transactionId': HASH().SHA1(self.transaction, self.nonce),
            'Tansactions': transaction,
            'nonce': nonce})

    def __str__(self):
        return ("TransactionID: %s\nTransaction: %s\nnonce: %s" % (
            HASH().SHA1(self.transaction, self.nonce), self.transaction, self.nonce))


class Block():
    blockID = None
    previous_hash = "0" * 64
    transactions = None
    nonce = 0

    def __init__(self, transactions, number=0):
        self.transactions = transactions
        self.number = number

    def blockID(self):
        if self.number == 0:
            return "Genesis"
        else:
            return HASH().SHA1(self.number, self.previous_hash, self.transactions, self.nonce)

    def __str__(self):
        return ("Block#: %s\nHash: %s\nPrevious Hash: %s\nTransactions:\n%s\nNonce: %s\n" % (
            self.number, self.blockID(), self.previous_hash, self.transactions, self.nonce))


class Blockchain():
    difficulty = 4

    def __init__(self, chain=[]):
        self.chain = chain

    def remove(self, block):
        self.chain.remove(block)

    def initBlockchain(self, block):
        self.chain.append(block)

    def mine(self, block):
        try:
            block.previous_hash = self.chain[-1].blockID()
        except IndexError:
            pass

        while True:
            if block.blockID()[:self.difficulty] == '0' * self.difficulty:
                self.initBlockchain(block)
                break
            else:
                block.nonce += 1

    def validateBlock(self):
        for i in range(2, len(self.chain)):
            _previous = self.chain[i].previous_hash
            _current = self.chain[i - 1].blockID()
            ftx = self.chain[i].transactions
            if _previous != _current or _current[:self.difficulty] != "0" * self.difficulty and ftx == ftx:
                return False

        return True

    def getTokenFromFaucet(self, account, amount):
        return ("Account: %s Amount: %s" % (account, amount))

    def showCoinDatabase(self, database):
        return ("Table: %s" % (database))
