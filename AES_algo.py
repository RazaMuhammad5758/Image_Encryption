from Crypto.Cipher import DES3
from hashlib import md5
import os

def generate_tdes_key(key: str) -> bytes:
    """
    Generate a valid 24-byte Triple DES key from the given string key.
    """
    key_hash = md5(key.encode('ascii')).digest()
    if len(key_hash) < 24:
        key_hash += key_hash[:8]  # Extend to 24 bytes if needed
    return DES3.adjust_key_parity(key_hash[:24])

def encrypt_file(file_path: str, tdes_key: bytes):
    """
    Encrypt the file at the given path using Triple DES.
    """
    cipher = DES3.new(tdes_key, DES3.MODE_EAX)
    
    # Read the original file
    with open(file_path, 'rb') as input_file:
        file_bytes = input_file.read()
    
    # Encrypt the file content
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    
    # Write the encrypted content back to the file
    with open(file_path, 'wb') as output_file:
        output_file.write(nonce)  # Write nonce at the beginning
        output_file.write(tag)    # Write the tag next
        output_file.write(ciphertext)  # Write the encrypted data

    print(f"Encryption Done! File saved as: {file_path}")

def decrypt_file(file_path: str, tdes_key: bytes):
    """
    Decrypt the file at the given path using Triple DES.
    """
    # Read the encrypted file
    with open(file_path, 'rb') as input_file:
        nonce = input_file.read(16)  # Read nonce from the beginning (16 bytes)
        tag = input_file.read(16)    # Read tag right after the nonce (16 bytes)
        ciphertext = input_file.read()  # The rest is the encrypted data

    print(f"Nonce: {nonce}")
    print(f"Tag: {tag}")
    print(f"Ciphertext length: {len(ciphertext)}")

    # Decrypt the content
    cipher = DES3.new(tdes_key, DES3.MODE_EAX, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        # Write decrypted data back to the file
        with open(file_path, 'wb') as output_file:
            output_file.write(decrypted_data)
        print(f"Decryption Done! File saved as: {file_path}")
    except ValueError as e:
        print(f"Decryption failed: {e}")

def main():
    while True:
        print('Choose operation to be done:\n\t1- Encryption\n\t2- Decryption\n\t3- Exit')
        operation = input('Your Choice: ')
        
        if operation == '3':
            print("Exiting the program.")
            break
        elif operation not in ['1', '2']:
            print("Invalid choice! Please choose 1, 2, or 3.")
            continue
        
        # Get file path and key
        file_path = input('Enter file path: ')
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            continue
        
        key = input('Enter TDES key (password): ')
        tdes_key = generate_tdes_key(key)
        
        if operation == '1':
            encrypt_file(file_path, tdes_key)
        elif operation == '2':
            decrypt_file(file_path, tdes_key)

if __name__ == "__main__":
    main()
