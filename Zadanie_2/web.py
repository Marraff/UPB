from Crypto.Hash import SHA256
from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

db = SQLAlchemy(app)

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela
    - public_key: verejny kluc pouzivatela

    Poznamka: mozete si lubovolne upravit tabulku podla vlastnych potrieb
'''
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

'''
    API request na generovanie klucoveho paru pre pozuivatela <user>
    - user: meno pouzivatela, pre ktoreho sa ma vygenerovat klucovy par
    - API volanie musi vygenerovat klucovy par pre pozuivatela <user> a verejny kluc ulozit do databazy
    - API volanie musi vratit privatny kluc pouzivatela <user> (v binarnom formate)

    ukazka: curl 127.0.0.1:1337/api/gen/ubp --output ubp.key
'''
@app.route('/api/gen/<user>', methods=['GET'])
def generate_keypair(user):
    # Step 1: Generate a new RSA key pair (2048 bits)
    key = RSA.generate(2048)

    # Step 2: Extract the private and public keys
    private_key = key.export_key()  # Private key in PEM format (binary)
    public_key = key.publickey().export_key()  # Public key in PEM format (binary)

    # Step 3: Store the public key in the database for the user
    user_record = User(username=user, public_key=public_key.decode('utf-8'))  # Create new user record
    db.session.add(user_record)  # Add user to session
    db.session.commit()  # Commit to assign an ID to the user

    # Step 4: Return the private key as a binary response
    return Response(private_key, content_type='application/octet-stream')

@app.route('/show-users', methods=['GET'])
def show_users():
    users = User.query.all()  # Fetch all users from the database

    # Create a list of dictionaries representing each user
    users_list = []
    for user in users:
        user_data = {
            'id': user.id,
            'username': user.username,
            'public_key': user.public_key
        }
        users_list.append(user_data)

    # Return the list as a JSON response
    return jsonify(users_list)

'''
    API request na zasifrovanie suboru pre pouzivatela <user>
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted.bin
'''

@app.route('/api/encrypt/<user>', methods=['POST'])
def encrypt_file(user):

    user_record = User.query.filter_by(username=user).first()

    if not user_record:
        return jsonify({"error": "User not found"}), 404

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files['file']
    file_data = uploaded_file.read()  # Read the file's binary content

    # Step 1: Generate a random symmetric key (AES)
    sym_key = get_random_bytes(32)  # AES-256, 32 bytes key
    cipher_aes = AES.new(sym_key, AES.MODE_ECB)  # Using ECB mode for simplicity

    # Encrypt the file data with the symmetric key (AES)
    padding_length = 16 - (len(file_data) % 16)  # Padding for block alignment
    padded_file_data = file_data + bytes([padding_length]) * padding_length  # Add padding
    encrypted_file_data = cipher_aes.encrypt(padded_file_data)

    # Step 2: Encrypt the symmetric key using the user's RSA public key
    public_key = RSA.import_key(user_record.public_key)  # Import user's public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_sym_key = cipher_rsa.encrypt(sym_key)  # Encrypt the symmetric key

    # Step 3: Prepare the final binary format
    # Format: [encrypted_sym_key][encrypted_file_data]
    encrypted_output = encrypted_sym_key + encrypted_file_data

    # Step 4: Return the encrypted file as a binary response
    return Response(encrypted_output, content_type='application/octet-stream')

'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@ubp.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    # Step 1: Check if both the encrypted file and the private key are in the request
    if 'file' not in request.files or 'key' not in request.files:
        return jsonify({"error": "Both file and key must be provided"}), 400

    # Step 2: Read the uploaded files
    encrypted_file = request.files['file'].read()  # Read the binary encrypted file
    private_key_data = request.files['key'].read()  # Read the private key

    # Step 3: Load the RSA private key
    try:
        private_key = RSA.import_key(private_key_data)  # Import the provided private key
    except ValueError:
        return jsonify({"error": "Invalid private key"}), 400

    # Step 4: Separate the encrypted symmetric key from the file data
    encrypted_sym_key_length = private_key.size_in_bytes()  # Determine the length of the encrypted AES key
    encrypted_sym_key = encrypted_file[:encrypted_sym_key_length]  # Extract the encrypted AES key
    encrypted_file_data = encrypted_file[encrypted_sym_key_length:]  # The rest is the encrypted file data

    # Debugging: Check if the encrypted symmetric key length is correct
    if len(encrypted_sym_key) != encrypted_sym_key_length:
        return jsonify({"error": "Encrypted key size mismatch"}), 400

    # Step 5: Decrypt the symmetric AES key using the provided private RSA key
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)  # Create the RSA decryption object
        sym_key = cipher_rsa.decrypt(encrypted_sym_key)  # Decrypt the symmetric key
    except ValueError:
        return jsonify({"error": "Decryption failed. Invalid private key or corrupted data."}), 400

    # Step 6: Decrypt the file content using the decrypted AES key
    cipher_aes = AES.new(sym_key, AES.MODE_ECB)
    decrypted_padded_file_data = cipher_aes.decrypt(encrypted_file_data)  # Decrypt the AES-encrypted file data

    # Step 7: Remove padding from the decrypted file content
    padding_length = decrypted_padded_file_data[-1]  # The last byte indicates the padding length
    decrypted_file_data = decrypted_padded_file_data[:-padding_length]  # Remove padding to get the original file

    # Step 8: Return the decrypted file content as a binary response
    return Response(decrypted_file_data, content_type='application/octet-stream')

'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@ubp.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():
    # Step 1: Check if both the file and the private key are present in the request
    if 'file' not in request.files or 'key' not in request.files:
        return jsonify({"error": "Both file and private key must be provided"}), 400

    # Step 2: Read the uploaded file and private key
    file_data = request.files['file'].read()  # Read the binary content of the file to be signed
    private_key_data = request.files['key'].read()  # Read the private key

    # Step 3: Import the RSA private key
    try:
        private_key = RSA.import_key(private_key_data)  # Import the provided private key
    except ValueError:
        return jsonify({"error": "Invalid private key"}), 400

    # Step 4: Create a SHA-256 hash of the file data
    file_hash = SHA256.new(file_data)

    # Step 5: Sign the hash using the private RSA key
    try:
        signature = pkcs1_15.new(private_key).sign(file_hash)  # Generate the digital signature
    except (ValueError, TypeError):
        return jsonify({"error": "Failed to generate signature"}), 500

    # Step 6: Return the signature as a binary response
    return Response(signature, content_type='application/octet-stream')


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    # Step 1: Retrieve the user's public key from the database
    user_record = User.query.filter_by(username=user).first()

    if not user_record:
        return jsonify({"error": "User not found"}), 404

    if not user_record.public_key:
        return jsonify({"error": "Public key not found for user"}), 400

    # Step 2: Check if both the file and the signature are present in the request
    if 'file' not in request.files or 'signature' not in request.files:
        return jsonify({"error": "Both file and signature must be provided"}), 400

    # Step 3: Read the uploaded file and signature
    file_data = request.files['file'].read()  # Read the binary content of the document
    signature_data = request.files['signature'].read()  # Read the digital signature

    # Step 4: Import the user's public key
    try:
        public_key = RSA.import_key(user_record.public_key)  # Import the public key from the user record
    except ValueError:
        return jsonify({"error": "Invalid public key"}), 400

    # Step 5: Hash the file data using SHA-256
    file_hash = SHA256.new(file_data)

    # Step 6: Verify the digital signature
    try:
        pkcs1_15.new(public_key).verify(file_hash, signature_data)  # Verify the signature
        return jsonify({"verified": True})  # Signature is valid
    except (ValueError, TypeError):
        return jsonify({"verified": False})  # Signature is invalid



'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    user_record = User.query.filter_by(username=user).first()

    if not user_record:
        return jsonify({"error": "User not found"}), 404

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files['file']
    file_data = uploaded_file.read()  # Read the file's binary content

    # Step 1: Generate a random symmetric key (AES)
    sym_key = get_random_bytes(32)  # AES-256, 32 bytes key
    cipher_aes = AES.new(sym_key, AES.MODE_GCM)  # GCM mode provides both confidentiality and integrity
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)  # Encrypt file data with AES

    # Step 2: Encrypt the symmetric key using the user's RSA public key
    public_key = RSA.import_key(user_record.public_key)  # Import user's public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_sym_key = cipher_rsa.encrypt(sym_key)  # Encrypt the symmetric key

    # Step 3: Prepare the final binary format
    # Format: [encrypted_sym_key][nonce][tag][ciphertext]
    encrypted_file = encrypted_sym_key + cipher_aes.nonce + tag + ciphertext

    # Step 4: Return the encrypted file as a binary response
    return Response(encrypted_file, content_type='application/octet-stream')

    #return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@ubp.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    # Step 1: Check if both the encrypted file and the private key are present in the request
    if 'file' not in request.files or 'key' not in request.files:
        return jsonify({"error": "Both file and private key must be provided"}), 400

    # Step 2: Read the uploaded file and private key
    encrypted_file = request.files['file'].read()  # Read the binary encrypted file
    private_key_data = request.files['key'].read()  # Read the private key

    # Step 3: Load the RSA private key
    try:
        private_key = RSA.import_key(private_key_data)  # Import the provided private key
    except ValueError:
        return jsonify({"error": "Invalid private key"}), 400

    # Step 4: Separate the encrypted symmetric key, nonce, tag, and ciphertext from the file data
    encrypted_sym_key_length = private_key.size_in_bytes()  # RSA-encrypted symmetric key length
    encrypted_sym_key = encrypted_file[:encrypted_sym_key_length]  # Encrypted symmetric key
    nonce = encrypted_file[encrypted_sym_key_length:encrypted_sym_key_length + 16]  # 16-byte GCM nonce
    tag = encrypted_file[encrypted_sym_key_length + 16:encrypted_sym_key_length + 32]  # 16-byte GCM tag
    ciphertext = encrypted_file[encrypted_sym_key_length + 32:]  # The actual encrypted file data

    # Step 5: Decrypt the symmetric AES key using the private RSA key
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)  # Create RSA decryption object
        sym_key = cipher_rsa.decrypt(encrypted_sym_key)  # Decrypt the symmetric key
    except ValueError:
        return jsonify({"error": "Failed to decrypt the symmetric key"}), 400

    # Step 6: Decrypt the file content with AES-GCM using the decrypted symmetric key
    try:
        cipher_aes = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)  # Create AES-GCM cipher with the nonce
        decrypted_file_data = cipher_aes.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify integrity
    except ValueError:
        return jsonify({"error": "Integrity check failed. Decryption aborted."}), 400

    # Step 7: Return the decrypted file content
    return Response(decrypted_file_data, content_type='application/octet-stream')



if __name__ == '__main__':
    app.run(port=1337)