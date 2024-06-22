import re
import os
import json
import argparse
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES

def good_replace(full_str:int, start:int, end:int, replacement:str) -> str:
    return full_str[:start] + replacement + full_str[end+1:]

def es3_to_json(ori: str) -> str:
    op_str = ori
    pattern = r"\d+:{"
    match = re.search(pattern, op_str)
    while match:
        start = match.start()
        end = match.end()
        op_str = good_replace(op_str, start, end-3, f'"{op_str[start: end-2]}_fixed"')
        match = re.search(pattern, op_str)
    return op_str

def json_to_es3(ori: str) -> str:
    op_str = ori
    pattern = r'"\d+_fixed":{'
    match = re.search(pattern, op_str)
    while match:
        start = match.start()
        end = match.end()
        op_str = good_replace(op_str, start, end-3, f'{op_str[start+1: end-9]}')
        match = re.search(pattern, op_str)
    return op_str

def es3_decrypt(enc_data: bytes, key: bytes) -> bytes:
    r = enc_data[:16]
    derived_key = pbkdf2_hmac('sha1', key, r, 100, dklen=16)
    cipher = AES.new(derived_key, AES.MODE_CBC, r)
    ciphertext = enc_data[16:]
    decrypted_data = cipher.decrypt(ciphertext)
    pad_len = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_len]
    return decrypted_data

def es3_encrypt(dec_data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    derived_key = pbkdf2_hmac('sha1', key, iv, 100, dklen=16)
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    padding_len = 16 - (len(dec_data) % 16)
    padded_data = dec_data + bytes([padding_len] * padding_len)
    ciphertext = cipher.encrypt(padded_data)
    encrypted_data = iv + ciphertext
    return encrypted_data

def main():
    parser = argparse.ArgumentParser(description="EasySave3 to JSON and encryption/decryption utilities.")
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    es3_to_json_parser = subparsers.add_parser('es3_to_json', help='Convert EasySave3 format to JSON.')
    es3_to_json_parser.add_argument('input', type=str, help='Input file in EasySave3 format.')
    es3_to_json_parser.add_argument('output', type=str, help='Output file for JSON format.')

    json_to_es3_parser = subparsers.add_parser('json_to_es3', help='Convert JSON format back to EasySave3.')
    json_to_es3_parser.add_argument('input', type=str, help='Input file in JSON format.')
    json_to_es3_parser.add_argument('output', type=str, help='Output file for EasySave3 format.')

    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt data using a key.')
    decrypt_parser.add_argument('input', type=str, help='Input encrypted file.')
    decrypt_parser.add_argument('output', type=str, help='Output decrypted file.')
    decrypt_parser.add_argument('key', type=str, help='Decryption key.')

    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt data using a key.')
    encrypt_parser.add_argument('input', type=str, help='Input file to encrypt.')
    encrypt_parser.add_argument('output', type=str, help='Output encrypted file.')
    encrypt_parser.add_argument('key', type=str, help='Encryption key.')

    args = parser.parse_args()

    if args.command == 'es3_to_json':
        with open(args.input, 'r') as f:
            input_data = f.read()
        result = es3_to_json(input_data)
        with open(args.output, 'w') as f:
            f.write(result)
    elif args.command == 'json_to_es3':
        with open(args.input, 'r') as f:
            input_data = f.read()
        result = json_to_es3(input_data)
        with open(args.output, 'w') as f:
            f.write(result)
    elif args.command == 'decrypt':
        with open(args.input, 'rb') as f:
            enc_data = f.read()
        key = args.key.encode()
        result = es3_decrypt(enc_data, key)
        with open(args.output, 'wb') as f:
            f.write(result)
    elif args.command == 'encrypt':
        with open(args.input, 'rb') as f:
            dec_data = f.read()
        key = args.key.encode()
        result = es3_encrypt(dec_data, key)
        with open(args.output, 'wb') as f:
            f.write(result)

if __name__ == '__main__':
    main()