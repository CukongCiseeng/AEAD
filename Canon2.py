from lib2to3.pytree import convert
from Crypto.Cipher import AES
import binascii, os
from bitstring import BitArray
import numpy as np
import sympy
from sympy import O, Matrix, Rational, mod_inverse, pprint 
import hashlib


secretKey = b'Message for AES-Message for AES-'
msg = b'Message for AES-'
ipe = b'initage for AES-'
Keybin=binascii.hexlify(secretKey)
print("Encryption key:", Keybin)



def encrypt_AES(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_ECB)
    ciphertext = aesCipher.encrypt(msg)
    return (ciphertext)

def decrypt_AES(encryptedMsg, secretKey):
    decipher = AES.new(secretKey, AES.MODE_ECB)
    plaintext = decipher.decrypt(encryptedMsg)
    return plaintext
def mod(x,modulus):
    if int(x)==2:
        p=0
    numer, denom = x.as_numer_denom()
    
    p=numer*mod_inverse(denom,modulus) % modulus
    return p
def Convert(string):
    list1=[]
    list1[:0]=string
    return list1
def canonic(Ct,k):
    k=BitArray(k).bin[:128]
    
    r=Ct^int(k,2)
    r= '{0:0128b}'.format(r)
    r=Convert(r)
    r=list(map(int, r))
    r=np.matrix(r)
    r=r.reshape(8, 16)
    """e=[]
    for _ in range(8):
        y=[]
        for j in range(16):
            y.append(r[j])
        e.append(y)
    print(e)
    
    r = Matrix(e)"""
    #r = r.rref()
    
    #r[0].applyfunc(lambda x: mod(x,5))
    r=sympy.Matrix(r).rref()
    
    r=r[0]
    print(r)
    
    r=np.delete(r, [0,1,2,3,4,5,6,7], 1)
    e=[]
    for i in range(8):
        y=[]
        for j in range(8):
            t=mod(r[i][j],2)
            y.append(t)
        e.append(y)
    
    return e
def round(IV,pt,k):
    Cs=encrypt_AES(IV,k)
    Ct=int(BitArray(Cs).bin,2)^int(BitArray(pt).bin,2)
    R=canonic(Ct,k)
    return Ct,R
print(round(ipe,msg,secretKey))
def taggen(M,A):
    m=sum(M)
hashlib.sha256(str(2 ** 128 - 1).encode('ASCII')).hexdigest()




"""encryptedMsg = encrypt_AES(msg, secretKey)
print("encryptedMsg", {
    'ciphertext': binascii.hexlify(encryptedMsg),
    'aesIV': binascii.hexlify(encryptedMsg),
    'authTag': binascii.hexlify(encryptedMsg)
})"""
"""
decryptedMsg = decrypt_AES(encryptedMsg, secretKey)
print("decryptedMsg", decryptedMsg)

tryxor=int(BitArray(Keybin).bin,2)^int(BitArray(msg).bin,2)
p=int(BitArray(Keybin).bin,2)
print("xor", tryxor)

mode input CTn-1,pt,k output CT,R"""





# np.fromstring is deprecated
# data = np.fromstring(my_data, np.float32)

