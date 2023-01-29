from Crypto.Cipher import DES
from secrets import token_bytes

MAX_LENGTH = 8
ENCRYPT_SUFFIX = "_encrypted"	#Add 'encrypted' to the encrypted file generated from the plaintext file
DECRYPT_SUFFIX = "_decrypted"	#Add 'decrypted' to the plaintext file generated from the encrypted file


def encrypt(file_content, file_extension, key):
	"""Function to generate the encrypted file from the plaintext file given to it as input. It save the file name with '_encrypted' suffix."""
	try:
		with open(file_content + "."+ file_extension, "r") as reader, open(f"{file_content}{ENCRYPT_SUFFIX}.text", "wb") as writer:
			key = bytes(key, encoding="utf-8")
			msg = reader.read()
			cipher = DES.new(key, DES.MODE_EAX)
			nonce = cipher.nonce
			ciphertext, tag = cipher.encrypt_and_digest(msg.encode("ascii"))
			
			[ writer.write(x) for x in (nonce, tag, ciphertext) ]
			print("Encrypted successfully!!!")
	except Exception as e:
		print(f"{e}")
		
		
def decrypt(file_content, file_extension, key):
	"""Function to generate the decrypted file from the ciphertext file given to it as input. It save the file name with '_decrypted' suffix"""
	try:
		with open(f"{file_content}.{file_extension}", "rb") as reader, open(f"{file_content}{DECRYPT_SUFFIX}.{file_extension}", "wb") as writer:
			key = bytes(key, encoding="utf-8")
			nonce, tag, ciphertext = [ reader.read(x) for x in (16, 8, -1) ]
			cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
			msg = cipher.decrypt_and_verify(ciphertext, tag)
			writer.write(msg)
			print("Decrypted successfully!!!")
	except Exception as e:
		print(f"{e}")
	

def split_file(file_name):
    """Function to seperate file name from it own extension"""
    file_name = file_name.split(".")
    return file_name

	
def check_key(secret_k):
    """Function to check key length in byte"""
    if len(secret_k.encode("utf-8")) == MAX_LENGTH:
        return True
    else:
        return False


def menu():
	"""Function to display menu option"""
	print("Choose options below:")
	print("Enter 1 for encryption of file")
	print("Enter 2 for decryption of file")
	
	
if __name__ == "__main__":
	try:
		s_key = input("Enter secret key:\n")
		key_length = check_key(s_key)
		if key_length:
		    menu()
		    option = int(input("Enter option: \n"))
		    if option == 1:
			    file_name = input("Enter file name to encrypt with file extension included: \n")
			    file_n = split_file(file_name)
			    encrypt(file_n[0], file_n[1], s_key)
		    elif option == 2:
			    file_name = input("Enter file name to decrypt with file extension included: \n")
			    file_n = split_file(file_name)
			    decrypt(file_n[0], file_n[1], s_key)
		    else:
			    print("Incorrect option")
		else:
		    print("Incorrect key length!!")
	except Exception as e:
		print(f"{e}")
