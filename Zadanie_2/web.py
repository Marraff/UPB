from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

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

    # Step 2: Encrypt the entire file using the user's RSA public key
    public_key = RSA.import_key(user_record.public_key)  # Import user's public key
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # RSA can only encrypt small chunks of data, so we need to split the file into chunks
    chunk_size = 214  # RSA with 2048-bit keys can encrypt 214 bytes of data with PKCS1_OAEP padding
    encrypted_file = b''

    for i in range(0, len(file_data), chunk_size):
        chunk = file_data[i:i + chunk_size]  # Get a chunk of the file
        encrypted_chunk = cipher_rsa.encrypt(chunk)  # Encrypt each chunk
        encrypted_file += encrypted_chunk  # Append encrypted chunk

    # Step 3: Return the encrypted file as a binary response
    return Response(encrypted_file, content_type='application/octet-stream')


'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@ubp.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files or 'key' not in request.files:
        return jsonify({"error": "File or private key not provided"}), 400

    encrypted_file = request.files['file'].read()  # Read the encrypted file's binary content
    private_key = RSA.import_key(request.files['key'].read())  # Import user's private key

    # Step 2: Decrypt the file using the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    chunk_size = 256  # RSA with 2048-bit keys produces 256-byte encrypted chunks

    decrypted_file = b''

    for i in range(0, len(encrypted_file), chunk_size):
        encrypted_chunk = encrypted_file[i:i + chunk_size]  # Get an encrypted chunk
        decrypted_chunk = cipher_rsa.decrypt(encrypted_chunk)  # Decrypt each chunk
        decrypted_file += decrypted_chunk  # Append decrypted chunk

    # Step 3: Return the decrypted file as a binary response
    return Response(decrypted_file, content_type='application/octet-stream')


'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@ubp.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    signature = request.files.get('signature')

    return jsonify({'verified': False})



'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    '''
        TODO: implementovat
    '''

    return Response(b'\xff', content_type='application/octet-stream')


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@ubp.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    '''
        TODO: implementovat
    '''

    file = request.files.get('file')
    key = request.files.get('key')

    return Response(b'\xff', content_type='application/octet-stream')



if __name__ == '__main__':
    app.run(port=1337)