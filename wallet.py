from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import binascii

class Wallet:
    """Creates, loads and holds private and public keys. Manages transaction signing and verification."""

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def create_keys(self):
        """Create a new pair of private and public keys."""
        private_key, public_key = self.generate_keys()
        self.private_key = private_key
        self.public_key = public_key

    def save_keys(self):
        """Saves the keys to a file (wallet.txt)."""
        if self.public_key is not None and self.private_key is not None:
            try:
                with open('wallet.txt', mode='w') as f:
                    f.write(self.public_key)
                    f.write('\n')
                    f.write(self.private_key)
                return True
            except (IOError, IndexError):
                print('Saving wallet failed...')
                return False
        return False

    def load_keys(self):
        """Loads the keys from the wallet.txt file into memory."""
        try:
            with open('wallet.txt', mode='r') as f:
                keys = f.readlines()
                public_key = keys[0].strip()
                private_key = keys[1].strip()
                self.public_key = public_key
                self.private_key = private_key
            return True
        except (IOError, IndexError):
            print('Loading wallet failed...')
            return False

    def generate_keys(self):
        """Generate a new pair of private and public key."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize private key
        private_key_hex = binascii.hexlify(
            private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        ).decode('ascii')
        
        # Serialize public key
        public_key_hex = binascii.hexlify(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode('ascii')
        
        return (private_key_hex, public_key_hex)

    def sign_transaction(self, sender, recipient, amount):
        """Sign a transaction and return the signature.

        Arguments:
            :sender: The sender of the transaction.
            :recipient: The recipient of the transaction.
            :amount: The amount of the transaction.
        """
        if self.private_key is None:
            print("No private key loaded. Cannot sign transaction.")
            return None
            
        try:
            # Deserialize private key
            private_key = serialization.load_der_private_key(
                binascii.unhexlify(self.private_key),
                password=None
            )
            
            # Create message to sign
            message = (str(sender) + str(recipient) + str(amount)).encode('utf8')
            
            # Sign the message
            signature = private_key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return binascii.hexlify(signature).decode('ascii')
        except Exception as e:
            print(f"Error signing transaction: {e}")
            return None

    @staticmethod
    def verify_transaction(transaction):
        """Verify the signature of a transaction.

        Arguments:
            :transaction: The transaction that should be verified.
        """
        try:
            # Check if transaction has required attributes
            if not hasattr(transaction, 'sender') or not hasattr(transaction, 'recipient') or not hasattr(transaction, 'amount') or not hasattr(transaction, 'signature'):
                print("Transaction missing required attributes")
                return False
            
            # Check if signature exists
            if transaction.signature is None:
                print("Transaction has no signature")
                return False
            
            # Deserialize public key
            public_key = serialization.load_der_public_key(
                binascii.unhexlify(transaction.sender)
            )
            
            # Create message that was signed
            message = (str(transaction.sender) + str(transaction.recipient) + str(transaction.amount)).encode('utf8')
            
            # Verify signature
            public_key.verify(
                binascii.unhexlify(transaction.signature),
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
            
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Error verifying transaction: {e}")
            return False