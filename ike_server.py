# This Flask application simulates the IKEv1 Aggressive Mode protocol.
# It handles key generation, key derivation, and authentication hashing
# to demonstrate the cryptographic steps involved in establishing an IKE Security Association (SA).

from flask import Flask, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)
# Enable CORS to allow the HTML file (running in the browser) to communicate with this server
CORS(app)

# --- GLOBAL STAT
# E (SIMULATING PEER MEMORY) ---
# In a real IKE implementation, this state would be managed per connection.
# Here, we store it globally for the simulation.
STATE = {}
PSK = b"MySecurePreSharedKey123"  # Pre-Shared Key (shared secret)

# --- DH PARAMETERS (MODP Group 2 - 1024-bit prime, simplified for simulation) ---
# NOTE: Real IKE uses much larger numbers. These are kept manageable for display.
# p and g are fixed and shared.
p_hex = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)
g_int = 2
DH_PARAMETERS = dh.DHParameterNumbers(
    p=int(p_hex, 16),
    g=g_int
).parameters(default_backend())


def generate_peer_keys():
    """Generates DH private and public keys for a peer."""
    peer_private_key = DH_PARAMETERS.generate_private_key()
    peer_public_key = peer_private_key.public_key()
    return peer_private_key, peer_public_key

def derive_keys(dh_shared_secret, nonce_a, nonce_b):
    """
    Simulates the IKE HKDF process to derive SKEYID, SKEYID_a, SKEYID_e, and SKEYID_d.
    Uses PSK + Nonces + DH Shared Secret.
    """
    # IKE uses Nonce A || Nonce B as salt
    salt = nonce_a + nonce_b
    
    # IKE uses the DH Shared Secret (K) as the Input Keying Material (IKM)
    ikm = dh_shared_secret
    
    # KDF is HKDF-SHA256 (SHA-2-256 is used for Group 2)
    # Step 1: Derive SKEYID
    skeyid_kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"KeyDerivationIKEv1",
        backend=default_backend()
    )
    # The actual IKE process uses SKid from PRF(PSK, CKY_I | CKY_R)
    # For simplification, we use the DH shared secret as the primary IKM.
    skeyid = skeyid_kdf.derive(ikm)

    # Step 2: Derive SKEYID_a, SKEYID_e, SKEYID_d from SKEYID
    # SKEYID is now the PRF input (IKM) for the subsequent derivations
    
    # SKEYID_a (Authentication Key)
    skeyid_a_kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256 bits
        salt=skeyid,
        info=b"IKEv1_Auth",
        backend=default_backend()
    )
    skeyid_a = skeyid_a_kdf.derive(skeyid) # Use randomness as input keying material (simplified)

    # For the simulation display, we will only expose SKEYID_a
    return skeyid_a


def calculate_auth_hash(key, dh_public_peer, dh_public_remote, id_peer, nonce_peer):
    """
    Calculates the Authentication Hash (H_A or H_B).
    Key: Derived SKEYID_a
    Data: Nonce_peer || Public_DH_Value_Peer || Public_DH_Value_Remote || ID_Peer
    """
    # The data concatenated and hashed includes the public values and IDs/Nonces
    data_to_hash = nonce_peer + dh_public_peer.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) + dh_public_remote.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) + id_peer

    # Use HMAC-SHA256 with the derived SKEYID_a key
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data_to_hash)
    return h.finalize()


@app.route('/api/start', methods=['POST'])
def start_protocol():
    """Initializes the state for a new IKE session."""
    global STATE
    # Nonces are critical random inputs for key derivation
    nonce_a = os.urandom(16)
    nonce_b = os.urandom(16)
    
    # ID's must be bytes for hashing
    id_a = b"192.168.1.10"
    id_b = b"192.168.1.20"

    STATE = {
        'nonce_a': nonce_a,
        'nonce_b': nonce_b,
        'id_a': id_a,
        'id_b': id_b,
        'a': {'private_key': None, 'public_key': None, 'skeyid_a': None},
        'b': {'private_key': None, 'public_key': None, 'skeyid_a': None},
        'dh_shared_secret': None,
        'auth_hash_a': None,
        'auth_hash_b': None,
    }
    return jsonify({"message": "IKE State initialized with fresh nonces and IDs."})


# ...existing code...

@app.route('/api/step1_m1', methods=['POST'])
def step1_m1():
    """
    Peer A generates its keys (x, g^x) and sends M1.
    This simulates Peer A's local key generation.
    """
    a_private, a_public = generate_peer_keys()
    
    STATE['a']['private_key'] = a_private
    STATE['a']['public_key'] = a_public

    # Safely convert large integers to bytes for display
    priv_x = a_private.private_numbers().x
    priv_x_bytes = priv_x.to_bytes((priv_x.bit_length() + 7) // 8, byteorder='big')
    pub_y = a_public.public_numbers().y
    pub_y_bytes = pub_y.to_bytes((pub_y.bit_length() + 7) // 8, byteorder='big')
    
    return jsonify({
        "private_key_display": priv_x_bytes.hex()[:16] + "...",
        "public_key_display": pub_y_bytes.hex()[:16] + "...",
        "nonce_a": STATE['nonce_a'].hex(),
    })

@app.route('/api/step2_m2', methods=['POST'])
def step2_m2():
    """
    Peer B receives M1, generates its keys (y, g^y), calculates shared secret (g^xy),
    derives SKEYID, and calculates its authentication hash (H_B).
    """
    # 1. Generate B's keys
    b_private, b_public = generate_peer_keys()
    STATE['b']['private_key'] = b_private
    STATE['b']['public_key'] = b_public

     # 2. Calculate DH Shared Secret (g^xy)
    a_public = STATE['a']['public_key']
    dh_shared_secret = b_private.exchange(a_public)
    STATE['dh_shared_secret'] = dh_shared_secret

    # 3. Derive SKEYID_a
    skeyid_a = derive_keys(dh_shared_secret, STATE['nonce_a'], STATE['nonce_b'])
    STATE['b']['skeyid_a'] = skeyid_a

    # 4. Calculate Authentication Hash H_B
    auth_hash_b = calculate_auth_hash(
        key=skeyid_a,
        dh_public_peer=b_public,         # Peer B's public key (g^y)
        dh_public_remote=a_public,       # Peer A's public key (g^x)
        id_peer=STATE['id_b'],           # Peer B's ID
        nonce_peer=STATE['nonce_b']      # Peer B's Nonce
    )
    STATE['auth_hash_b'] = auth_hash_b

    # Safely convert large integers to bytes for display
    priv_y = b_private.private_numbers().x
    priv_y_bytes = priv_y.to_bytes((priv_y.bit_length() + 7) // 8, byteorder='big')
    pub_y = b_public.public_numbers().y
    pub_y_bytes = pub_y.to_bytes((pub_y.bit_length() + 7) // 8, byteorder='big')
    
    # ...existing code...
    # (rest of your function unchanged)
    return jsonify({
        "private_key_display": priv_y_bytes.hex()[:16] + "...",
        "public_key_display": pub_y_bytes.hex()[:16] + "...",
        "SKEYID_display": skeyid_a.hex()[:16] + "...",
        "auth_hash_b": auth_hash_b.hex(),
    })
# ...existing code...


@app.route('/api/step3_m3', methods=['POST'])
def step3_m3():
    """
    Peer A receives M2, calculates its shared secret, derives SKEYID,
    VERIFIES H_B, and calculates/sends its authentication hash (H_A).
    """
    # 1. Calculate DH Shared Secret (g^xy) using its private key (x) and B's public key (g^y)
    a_private = STATE['a']['private_key']
    b_public = STATE['b']['public_key']
    dh_shared_secret = a_private.exchange(b_public)
    
    # 2. Derive Keying Material (SKEYID_a)
    skeyid_a = derive_keys(dh_shared_secret, STATE['nonce_a'], STATE['nonce_b'])
    STATE['a']['skeyid_a'] = skeyid_a
    
    # 3. VERIFY H_B received in M2
    # Peer A calculates H_B locally using its derived SKEYID_a
    local_hash_b = calculate_auth_hash(
        key=skeyid_a,
        dh_public_peer=b_public,         # Peer B's public key (g^y)
        dh_public_remote=STATE['a']['public_key'], # Peer A's public key (g^x)
        id_peer=STATE['id_b'],           # Peer B's ID
        nonce_peer=STATE['nonce_b']      # Peer B's Nonce
    )
    
    verification_result = "FAILURE"
    if local_hash_b == STATE['auth_hash_b']:
        verification_result = "SUCCESS"
        
    # 4. Calculate Authentication Hash H_A (to send in M3)
    auth_hash_a = calculate_auth_hash(
        key=skeyid_a,
        dh_public_peer=STATE['a']['public_key'],  # Peer A's public key (g^x)
        dh_public_remote=b_public,                # Peer B's public key (g^y)
        id_peer=STATE['id_a'],                    # Peer A's ID
        nonce_peer=STATE['nonce_a']               # Peer A's Nonce
    )
    STATE['auth_hash_a'] = auth_hash_a

    # M3 Response
    return jsonify({
        "SKEYID_display": skeyid_a.hex()[:16] + "...",
        "verification_result": verification_result,
        "auth_hash_a": auth_hash_a.hex(),
    })


if __name__ == '__main__':
    # Running on 0.0.0.0 makes it accessible across your network if needed, but 127.0.0.1 is standard for local development.
    print("--- IKE Protocol Server Starting ---")
    print("Access the frontend HTML file and ensure it connects to http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000)
