import base64
import binascii
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import json
import numpy as np
import time
from time import perf_counter
import timeit

def hmac_encryptyion(message):
    m_byte = bytes(message, "utf-8")
    
    k = get_random_bytes(16)
    file_out = open ("hmackey.txt", "wb")
    file_out.write(k)
    file_out.close()
    hash_message = HMAC.new(k, digestmod=SHA256)
    hash_message.update(m_byte)
    digest = hash_message.hexdigest()
    print(digest)

    file_out = open("mactext.txt", "w")
    file_out.write('{0}{1}'.format(message, digest))
    file_out.close()

def hmac_verification(file):
    file_in = open(file, 'r')
    message = file_in.read(18)
    message_bytes = bytes(message, "utf-8")
    print(message)

    hr = file_in.read()
    hr_bytes = bytes(hr, "utf-8")
    print(hr)
    file_in.close()

    file_in = open("hmackey.txt", "rb")
    k = file_in.read()
    file_in.close()

    hash_message = HMAC.new(k, message_bytes, digestmod=SHA256)
    try:
        hash_message.hexverify(hr_bytes)
        print("The message is a match")
    except ValueError:
        print("The message or key is wrong")

def rsa_key_generation():
    #Key generation and file generation
    RSA_key = RSA.generate(2048)
    private_key = RSA_key.export_key()
    file_out = open("private.txt", "wb")
    file_out.write(private_key)
    file_out.close()
    #Publick key generation and file creation to share
    public_key = RSA_key.publickey().export_key()
    file_out = open("public_key.txt", "wb")
    file_out.write(public_key)
    file_out.close()

def rsa_signature(message):
    message_byte = bytes(message, 'utf-8')

    key = RSA.import_key(open('private.txt').read())
    hash_message = SHA256.new(message_byte)
    signature = pkcs1_15.new(key).sign(hash_message)
    print(signature)

    file_out = open("sigtext.txt", "w")
    file_out.write('{0}{1}'.format(message, signature))
    file_out.close()

def rsa_verification(file):
    
    file_in = open(file, 'r')
    message = file_in.read(18)
    message_byte = bytes(message, "utf-8")

    signature = file_in.read()
    sig_to_bytes = bytes(signature, "utf-8")
    print(signature)
    file_in.close()
    
    priv_key = RSA.import_key(open('private.txt').read())
    key = RSA.import_key(open('public_key.txt').read())
    hash_message = SHA256.new(message_byte)
    rsa_signature = pkcs1_15.new(priv_key).sign(hash_message)
    if (pkcs1_15.new(key).verify(hash_message, rsa_signature)):
        print("The signature is valid.")
    try:
        pkcs1_15.new(key).verify(hash_message, rsa_signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is invalid")

def hmac_gen():
    message = input("User-input message for HMAC Generation: ")
    message_byte = bytes(message, 'utf-8')
    key = get_random_bytes(16)

    hash_message = HMAC.new(key, digestmod = SHA256)
    hmac_repetitions = (timeit.timeit('hash_message.update(message_byte)',\
        globals = {'hash_message' : hash_message, 'message_byte' : message_byte}, number = 100))

    average_hmac = np.mean(hmac_repetitions)
    print(average_hmac)

def signature():
    #Key generation needed for hash
    rsa_key_generation()
    message = input("User-imput message for RSA Digital Signature: ")
    message_byte = bytes(message, 'utf-8')
    key = RSA.import_key(open('private.txt').read())
    hash_message = SHA256.new(message_byte)

    #Average of 100 repetitions of signature generation
    signature_generation_reps = (timeit.timeit('signature = pkcs1_15.new(key).sign(hash_message)',\
        globals = {'signature' : signature, 'pkcs1_15':pkcs1_15,'key':key,'hash_message':hash_message}, number = 100))
    average_signature_generation = np.mean(signature_generation_reps)

    #Average of 100 repitions of RSA signature verification
    rsa_signature = pkcs1_15.new(key).sign(hash_message)
    rsa_signature_ver = (timeit.timeit('pkcs1_15.new(key).verify(hash_message, rsa_signature)',\
        globals={'pkcs1_15':pkcs1_15,'key':key,'hash_message':hash_message,'rsa_signature':rsa_signature},number = 100))
    average_signature_verification = np.mean(rsa_signature_ver)

    print("Average Signature generation time: ", average_signature_generation)
    print("Average Signature verification time: ", average_signature_verification)

#AES 128 encryption using CBC mode and random key and id
#converted into bytes, padded, and encoded with utf-8
#Then passed to json object to be recieved for decryption
data = input("Enter message to be encrypted: ")
key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
print(encryption_envelope)

#Loads the json with the ciphertext and iv
#Then unpads and decrypts
#prints both the encrypted ciphertext and plaintext
entry = input("Do you want to decrypt? y/n:")
if entry == "y":
    b64 = json.loads(encryption_envelope)
    ct = base64.b64decode(b64['ciphertext'])
    print(ct)
    iv = base64.b64decode(b64['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    print("The message was: ", plaintext)
elif entry == "n":
    print("To the next encryption method")

#RSA 2048 encryption transforms message into bytes and generates a key
#uses a private key along with a publc key
info = input("Would you like to encrypt using RSA? y/n: ")
if entry == "y":
    msg = input("Please enter message to be encrypted: ")
    #Key generation and file generation
    RSA_key = RSA.generate(2048)
    private_key = RSA_key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()
    #Publick key generation and file creation to share
    public_key = RSA_key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    #Message conversion to bytes and session key generation
    b = bytes(msg, 'utf-8')
    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)
    #encryption
    file_out = open("ctext.txt", "wb")
    encryptor = PKCS1_OAEP.new(recipient_key)
    encrypted = encryptor.encrypt(b)
    file_out.write(encrypted)
    file_out.close()
    print("Ciphertext: ", encrypted)

#Start of RSA decryption. Begin by opening file and importing the private key
#decryption is ran against the private key then the encrypted message.
warning = input("Would you like to decrypt using RSA? y/n: ")
if entry == "y":
    file_in = open("ctext.txt", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    with open("ctext.txt", "rb") as f:
        bytes_read = f.read()
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(bytes_read)
    print ("Plaintext: ", decrypted)

print("Benchmark Testing of AES and RSA")
#AES encryption is based on key size and the number of rounds. In this case the key size is 16 bytes.
def AES_128_encryption(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
    encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
#AES encryption is based on key size and the number of rounds. In this case the key size is 24 bytes.
def AES_192_encryption(plaintext):
    key = get_random_bytes(24)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
    encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
#AES encryption is based on key size and the number of rounds. In this case the key size is 32 bytes.
def AES_256_encryption(plaintext):
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertexts = base64.b64encode(cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode('utf-8')
    encryption_envelope = json.dumps({'ciphertext' : ciphertexts, 'iv' : base64.b64encode(iv).decode('utf-8')})
#AES decryption by reading ciphertext and iv from encoded json file, unpads and decrypts ciphertext
def AES_decryption():
    b64 = json.loads(encryption_envelope)
    ct = base64.b64decode(b64['ciphertext'])
    iv = base64.b64decode(b64['iv'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
#Generates a key of size 1024
def RSA_1024_key():
    key = RSA.generate(1024)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
#Generates a key of size 2048
def RSA_2048_key():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
#Generates a key of size 4096
def RSA_4096_key():
    key = RSA.generate(4096)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()
#RSA encryption independent of key generation allowing it to be used
#with all levels of RSA encryption
def RSA_encryption(plaintext):
    b = bytes(plaintext, 'utf-8')
    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)
    
    file_out = open("ctext.txt", "wb")
    encryptor = PKCS1_OAEP.new(recipient_key)
    encrypted = encryptor.encrypt(b)
    file_out.write(encrypted)
    file_out.close()
#Function for decryption on all levels of RSA encrytption
def RSA_decryption():
    file_in = open("ctext.txt", "rb")
    private_key = RSA.import_key(open("private.pem").read())
    with open("ctext.txt", "rb") as f:
        bytes_read = f.read()
    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(bytes_read)
#Average for the list of times recorded for encryption and decryption
def Average(lst): 
    return sum(lst) / len(lst)

secret = input("Enter 7 character message to be encoded and tested: ")
#test for AES 128
for i in range(1, 100):
    start = perf_counter()
    AES_128_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    AES_decryption()
    d_end = perf_counter()
    execution_time = (end - start)
    d_time = []
    d_time.append(execution_time)
print("AES 128 Encryption time", Average(time))
print("AES 128 decryption time", Average(d_time))

#test for RSA 2048
for i in range(1, 100):
    RSA_2048_key()
    start = perf_counter()
    RSA_encryption(secret)
    end = perf_counter()
    execution_time = (end - start)
    time = []
    time.append(execution_time)
    d_start = perf_counter()
    RSA_decryption()
    d_end = perf_counter()
    d_execution_time = (d_end - d_start)
    d_time = []
    d_time.append(d_execution_time)
print("RSA 2048 Encryption time", Average(time))
print("RSA 2048 decryption time", Average(d_time))

message = input("Please enter message for HMAC Verification: ")
hmac_encryptyion(message)
hmac_verification("mactext.txt")
rsa_message = input("Please enter message for RSA signature: ")
rsa_key_generation()
rsa_signature(rsa_message)
rsa_verification("sigtext.txt")

hmac_gen()
signature()