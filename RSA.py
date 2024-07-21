from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

def generate_RSA_keypair():
  # Generate RSA key pair
  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
  )
  public_key = private_key.public_key()

  private_key_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
  ).decode('utf-8')

  public_key_pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  ).decode('utf-8')

  return private_key_pem, public_key_pem

def encrypt_RSA(public_key_pem, plaintext):
  # Load public key
  public_key = serialization.load_pem_public_key(
      public_key_pem.encode('utf-8'),
      backend=default_backend()
  )

  # Encrypt plaintext
  ciphertext = public_key.encrypt(
      plaintext.encode('utf-8'),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )

  return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_RSA(private_key_pem):
  # Load private key
  private_key = serialization.load_pem_private_key(
      private_key_pem.encode('utf-8'),
      password=None,
      backend=default_backend()
  )

  def decrypt_wrapper(ciphertext_base64):
    # Decode base64
    ciphertext = base64.b64decode(ciphertext_base64)

    # Decrypt ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode('utf-8')

  return decrypt_wrapper

# Main program flow
private_key_pem = None 
while True:
  choice = input("Enter 'e' to Encrypt or 'd' to Decrypt (or 'q' to quit): ")
  if choice.lower() == 'q':
    break
  elif choice.lower() == 'e':
    if not hasattr(encrypt_RSA, 'private_key_pem') or not hasattr(encrypt_RSA, 'public_key_pem'):
      private_key_pem, public_key_pem = generate_RSA_keypair()
      encrypt_RSA.private_key_pem = private_key_pem
      encrypt_RSA.public_key_pem = public_key_pem
    plaintext = input("Enter message to encrypt: ")
    encrypted_message = encrypt_RSA(encrypt_RSA.public_key_pem, plaintext)
    print("Encrypted message:", encrypted_message)
  elif choice.lower() == 'd':
    if private_key_pem is None:
      private_key_pem = input("Enter private key PEM: ")
    decrypt_function = decrypt_RSA(private_key_pem)
    ciphertext_base64 = input("Enter base64 encoded ciphertext to decrypt: ")
    decrypted_message = decrypt_function(ciphertext_base64)
    print("Decrypted message:", decrypted_message)
  else:
    print("Invalid choice. Please enter 'e', 'd', or 'q'.")
