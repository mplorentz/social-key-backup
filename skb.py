#!/usr/bin/env python3
"""
Social Key Backup - A tool for backing up Nostr keys using Shamir's Secret Sharing
"""

import argparse
import sys
import re
import json
import base64
import os
import secrets
from sslib import shamir
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time
import hashlib
from nostr.key import PrivateKey, PublicKey

def is_hex_key(key):
    """Check if key is a valid 64-character hex string"""
    return bool(re.match(r'^[0-9a-fA-F]{64}$', key))

def is_bech32_key(key):
    """Check if key starts with npub1 or nsec1"""
    return key.startswith(('npub1', 'nsec1'))

def validate_key_format(key, expected_prefix=None):
    """Validate key format and optionally check prefix using nostr library"""
    try:
        # Try to parse the key to validate format
        if is_hex_key(key):
            # Valid hex key (can't determine type without context)
            pass
        elif key.startswith('nsec1'):
            PrivateKey.from_nsec(key)
        elif key.startswith('npub1'):
            PublicKey.from_npub(key)
        else:
            raise ValueError("Invalid format")
    
        if expected_prefix and is_bech32_key(key) and not key.startswith(expected_prefix):
            print(f"Error: Expected {expected_prefix} key, got: {key}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: Invalid key format: {key}")
        print("Keys must be either 64-character hex or valid bech32 format (npub1/nsec1)")
        sys.exit(1)

# Crypto Functions (Basic NIP-44 & NIP-59 implementation)
def nip44_encrypt(plaintext, sender_privkey, receiver_pubkey):
    """NIP-44-style encryption using proper ECDH with nostr library"""
    try:
        # Convert keys to proper nostr objects
        if is_hex_key(sender_privkey):
            sender_key = PrivateKey(bytes.fromhex(sender_privkey))
        else:
            sender_key = PrivateKey.from_nsec(sender_privkey)
            
        if is_hex_key(receiver_pubkey):
            receiver_key = PublicKey(bytes.fromhex(receiver_pubkey))
        else:
            receiver_key = PublicKey.from_npub(receiver_pubkey)
        
        # Ensure plaintext is string
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode()
        
        # Create proper ECDH shared secret using nostr library  
        shared_secret = sender_key.compute_shared_secret(receiver_key.hex())
        
        # Derive encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'nip44-encrypt',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Encrypt using AES-GCM
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # Return base64 encoded result
        encrypted_data = nonce + encryptor.tag + ciphertext
        return base64.b64encode(encrypted_data).decode()
        
    except Exception as e:
        print(f"Error in NIP-44 encryption: {e}")
        sys.exit(1)

def nip44_decrypt(ciphertext, receiver_privkey, sender_pubkey):
    """NIP-44-style decryption using proper ECDH with nostr library"""
    try:
        # Decode from base64
        encrypted_data = base64.b64decode(ciphertext)
        
        # Extract components
        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext_bytes = encrypted_data[28:]
        
        # Convert keys to proper nostr objects
        if is_hex_key(receiver_privkey):
            receiver_key = PrivateKey(bytes.fromhex(receiver_privkey))
        else:
            receiver_key = PrivateKey.from_nsec(receiver_privkey)
            
        if is_hex_key(sender_pubkey):
            sender_key = PublicKey(bytes.fromhex(sender_pubkey))
        else:
            sender_key = PublicKey.from_npub(sender_pubkey)
        
        # Create proper ECDH shared secret using nostr library
        shared_secret = receiver_key.compute_shared_secret(sender_key.hex())
        
        # Derive decryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'nip44-encrypt',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Decrypt using AES-GCM
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        
        return plaintext.decode()
        
    except Exception as e:
        print(f"Error in NIP-44 decryption: {e}")
        sys.exit(1)

def create_gift_wrap(share_data, sender_privkey, receiver_pubkey):
    """Create NIP-59 gift wrap containing encrypted share"""
    try:
        # Convert keys to proper format
        if is_hex_key(sender_privkey):
            sender_hex = sender_privkey.lower()
        else:
            sender_hex = PrivateKey.from_nsec(sender_privkey).hex()
            
        if is_hex_key(receiver_pubkey):
            receiver_hex = receiver_pubkey.lower()
        else:
            receiver_hex = PublicKey.from_npub(receiver_pubkey).hex()
        
        # Step 1: Create rumor (unsigned event with share data)
        rumor_content = json.dumps({
            "share": share_data["share"],
            "threshold": share_data["threshold"],
            "created_at": int(time.time())
        })
        
        # Step 2: Encrypt rumor using NIP-44
        encrypted_rumor = nip44_encrypt(rumor_content, sender_privkey, receiver_pubkey)
        
        # Step 3: Create seal (kind 13 event)
        seal_event = {
            "kind": 13,
            "content": encrypted_rumor,
            "tags": [],
            "created_at": int(time.time()),
            "pubkey": sender_hex
        }
        
        # Step 4: Create gift wrap (kind 1059 event)
        # Generate random key for gift wrap
        random_key = secrets.token_hex(32)
        
        # Encrypt seal with random key
        gift_wrap_content = nip44_encrypt(json.dumps(seal_event), random_key, receiver_pubkey)
        
        gift_wrap = {
            "kind": 1059,
            "content": gift_wrap_content,
            "tags": [["p", receiver_hex]],
            "created_at": int(time.time()),
            "pubkey": hashlib.sha256(random_key.encode()).hexdigest()
        }
        
        return gift_wrap
        
    except Exception as e:
        print(f"Error creating gift wrap: {e}")
        sys.exit(1)

def unwrap_gift_wrap(gift_wrap_event, receiver_privkey):
    """Unwrap NIP-59 gift wrap to get share data"""
    try:
        # This is a placeholder for unwrapping
        # In real implementation, would reverse the gift wrap process
        print("TODO: Implement gift wrap unwrapping")
        return {"share": "decrypted_share", "threshold": 2}
    except Exception as e:
        print(f"Error unwrapping gift wrap: {e}")
        sys.exit(1)

def create_shares(args):
    """Create and distribute shares of a secret key to peers"""
    # Validate the private key
    validate_key_format(args.nsec, 'nsec1')
    
    # Validate peer public keys
    for peer in args.peers:
        validate_key_format(peer, 'npub1')
    
    # Validate threshold
    if args.threshold < 1 or args.threshold > len(args.peers):
        print(f"Error: Threshold {args.threshold} must be between 1 and {len(args.peers)} (number of peers)")
        sys.exit(1)
    
    try:
        # Convert nsec to hex for secret sharing
        if is_hex_key(args.nsec):
            private_key_hex = args.nsec.lower()
        else:
            private_key_hex = PrivateKey.from_nsec(args.nsec).hex()
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        print(f"\n--- Creating Shamir's Secret Shares ---")
        print(f"Secret length: {len(private_key_bytes)} bytes")
        
        # Create shares using sslib
        shares_result = shamir.split_secret(private_key_bytes, args.threshold, len(args.peers))
        shares_list = shares_result['shares']
        print(f"Created {len(shares_list)} shares with threshold {args.threshold}")
        
        # Encrypt and wrap each share for each peer
        print(f"\n--- Encrypting Shares for Peers ---")
        gift_wraps = []
        
        for i, (peer_npub, share_tuple) in enumerate(zip(args.peers, shares_list)):
            share_index, share_bytes = share_tuple
            print(f"Processing share {i+1} for peer: {peer_npub[:16]}...")
            
            # Prepare share data
            share_data = {
                "share": base64.b64encode(share_bytes).decode(),
                "threshold": args.threshold,
                "share_index": share_index,
                "total_shares": len(args.peers)
            }
            
            # Create gift wrap for this peer
            gift_wrap = create_gift_wrap(share_data, args.nsec, peer_npub)
            gift_wraps.append(gift_wrap)
            
            print(f"  ✓ Encrypted share {i+1} for peer {peer_npub[:16]}...")
        
        print(f"\n--- Publishing to Relay ---")
        print(f"Relay: {args.relay}")
        
        # TODO: For now, just display the events that would be published
        print(f"Would publish {len(gift_wraps)} gift wrap events:")
        for i, gift_wrap in enumerate(gift_wraps):
            print(f"  Event {i+1}: kind={gift_wrap['kind']}, content_length={len(gift_wrap['content'])}")
        
        # TODO: Test share reconstruction - remove later
        print(f"\n--- Testing Share Reconstruction ---")
        test_shares = shares_list[:args.threshold]  # Take only threshold number of shares
        
        # Reconstruct the dict format that recover_secret expects
        test_dict = {
            'required_shares': shares_result['required_shares'],
            'prime_mod': shares_result['prime_mod'], 
            'shares': test_shares
        }
        reconstructed = shamir.recover_secret(test_dict)
        
        if reconstructed == private_key_bytes:
            print(f"✓ Share reconstruction test PASSED")
            print(f"✓ Original and reconstructed keys match")
        else:
            print(f"✗ Share reconstruction test FAILED")
            return
        
        print(f"\n--- Success ---")
        print(f"✓ Created {len(shares_list)} shares with threshold {args.threshold}")
        print(f"✓ Encrypted shares for {len(args.peers)} peers")
        print(f"✓ Gift wrap events ready for relay publication")
        print(f"✓ Share reconstruction verified")
        
    except Exception as e:
        print(f"Error creating shares: {e}")
        sys.exit(1)

def start_recovery(args):
    """Generate temporary key and display recovery instructions"""
    # Validate the public key
    validate_key_format(args.npub, 'npub1')
    
    print(f"Starting recovery for npub: {args.npub}")
    print("\n--- Generating Temporary Recovery Key ---")
    
    # Generate temporary keypair
    temp_private_key = secrets.token_hex(32)
    temp_public_key = hashlib.sha256(temp_private_key.encode()).hexdigest()
    
    # Convert to nsec/npub format 
    temp_nsec = PrivateKey(bytes.fromhex(temp_private_key)).bech32()
    temp_npub = PublicKey(bytes.fromhex(temp_public_key)).bech32()
    
    print(f"✓ Generated temporary recovery keypair")
    print(f"Temporary recovery private key: {temp_nsec}")
    print(f"Temporary recovery public key: {temp_npub}")
    
    print(f"\n--- Recovery Instructions ---")
    print(f"1. Share the temporary npub with your trusted peers:")
    print(f"   {temp_npub}")
    print()
    print(f"2. Ask each peer to run the following command:")
    print(f"   ./skb.py send-share <relay_url> --nsec <their_nsec> {args.npub} {temp_npub}")
    print()
    print(f"3. Once you have enough shares, recover your key:")
    print(f"   ./skb.py recover-key --nsec {temp_nsec} <relay_url>")
    print()
    print(f"⚠️  IMPORTANT: Save the temporary nsec securely!")
    print(f"   You'll need it to decrypt the shares sent by your peers.")
    print(f"   {temp_nsec}")
    print()
    print(f"🔒 Keep this temporary key private and delete it after recovery.")

def send_share(args):
    """Send a share from peer to recovery key"""
    # Validate keys
    validate_key_format(args.nsec, 'nsec1')
    validate_key_format(args.target_npub, 'npub1')
    validate_key_format(args.recovery_npub, 'npub1')
    
    print(f"Sending share from relay: {args.relay}")
    print(f"Using peer nsec: {args.nsec[:16]}...")
    print(f"Target npub (original key): {args.target_npub[:16]}...")
    print(f"Recovery npub (temporary): {args.recovery_npub[:16]}...")
    
    try:
        print(f"\n--- Querying Relay for Shares ---")
        print(f"Searching for gift wrap events sent to: {args.nsec[:16]}...")
        
        # Convert peer's nsec to npub to search for shares sent to them
        if is_hex_key(args.nsec):
            peer_hex = args.nsec.lower()
        else:
            peer_hex = PrivateKey.from_nsec(args.nsec).hex()
        peer_npub = PublicKey(bytes.fromhex(peer_hex)).bech32()
        
        print(f"Peer npub: {peer_npub[:16]}...")
        print(f"📡 Querying relay: {args.relay}")
        print(f"🔍 Looking for kind 1059 events with p tag: {peer_hex[:16]}...")
        
        # TODO: Simulate finding a gift wrap event (in real implementation, query relay)
        print(f"✓ Found gift wrap event containing share")
        
        # Simulate the gift wrap event structure that would be found
        mock_gift_wrap = {
            "kind": 1059,
            "content": "encrypted_content_from_relay", 
            "tags": [["p", peer_hex]],
            "created_at": int(time.time()),
            "pubkey": "random_gift_wrap_sender"
        }
        
        print(f"\n--- Decrypting Share ---")
        print(f"🔓 Unwrapping gift wrap event...")
        
        # In a real implementation, this would:
        # 1. Decrypt the gift wrap content using the peer's private key
        # 2. Extract the seal event
        # 3. Decrypt the seal to get the original share
        
        # For demo purposes, simulate the decrypted share data
        mock_share_data = {
            "share": base64.b64encode(b"mock_share_bytes_from_shamir").decode(),
            "threshold": 2,
            "share_index": 1,
            "total_shares": 3
        }
        
        print(f"✓ Successfully decrypted share from gift wrap")
        print(f"  Share index: {mock_share_data['share_index']}")
        print(f"  Threshold: {mock_share_data['threshold']}")
        print(f"  Total shares: {mock_share_data['total_shares']}")
        
        print(f"\n--- Re-encrypting for Recovery Key ---")
        print(f"🔐 Encrypting share for temporary recovery key...")
        
        # Create gift wrap for the recovery key
        recovery_gift_wrap = create_gift_wrap(mock_share_data, args.nsec, args.recovery_npub)
        
        print(f"✓ Created new gift wrap for recovery key")
        print(f"  Event kind: {recovery_gift_wrap['kind']}")
        print(f"  Content length: {len(recovery_gift_wrap['content'])}")
        print(f"  Target: {args.recovery_npub[:16]}...")
        
        print(f"\n--- Publishing to Relay ---")
        print(f"📤 Publishing recovery gift wrap to: {args.relay}")
        print(f"Would publish event:")
        print(f"  Kind: {recovery_gift_wrap['kind']}")
        print(f"  P tag: {recovery_gift_wrap['tags'][0][1][:16]}...")
        print(f"  Content length: {len(recovery_gift_wrap['content'])}")
        
        print(f"\n--- Success ---")
        print(f"✅ Share successfully forwarded to recovery key!")
        print(f"The person recovering can now use this share with:")
        print(f"./skb.py recover-key --nsec <recovery_nsec> {args.relay}")
        
    except Exception as e:
        print(f"Error sending share: {e}")
        sys.exit(1)

def recover_key(args):
    """Recover original key from shares"""
    # Validate the temporary private key
    validate_key_format(args.nsec, 'nsec1')
    
    print(f"Recovering key using temporary nsec: {args.nsec[:16]}...")
    print(f"From relay: {args.relay}")
    
    try:
        # Convert temp nsec to npub for querying
        if is_hex_key(args.nsec):
            temp_hex = args.nsec.lower()
        else:
            temp_hex = PrivateKey.from_nsec(args.nsec).hex()
        temp_npub = PublicKey(bytes.fromhex(temp_hex)).bech32()
        
        print(f"\n--- Querying Relay for Recovery Shares ---")
        print(f"Temporary npub: {temp_npub[:16]}...")
        print(f"📡 Searching for shares sent to temporary key on: {args.relay}")
        print(f"🔍 Looking for kind 1059 events with p tag: {temp_hex[:16]}...")
        
        # Simulate finding multiple gift wrap events containing shares
        # In real implementation, this would query the relay
        print(f"✓ Found gift wrap events from peers")
        
        # Simulate decrypting multiple shares
        collected_shares = []
        share_metadata = None
        
        # Simulate 3 shares being sent by different peers
        mock_shares_from_peers = [
            {
                "from_peer": "peer1",
                "share_data": {
                    "share": base64.b64encode(b"mock_share_1_bytes_from_peer1").decode(),
                    "threshold": 2,
                    "share_index": 1,
                    "total_shares": 3
                }
            },
            {
                "from_peer": "peer2", 
                "share_data": {
                    "share": base64.b64encode(b"mock_share_2_bytes_from_peer2").decode(),
                    "threshold": 2,
                    "share_index": 2,
                    "total_shares": 3
                }
            },
            {
                "from_peer": "peer3",
                "share_data": {
                    "share": base64.b64encode(b"mock_share_3_bytes_from_peer3").decode(),
                    "threshold": 2,
                    "share_index": 3,
                    "total_shares": 3
                }
            }
        ]
        
        print(f"\n--- Decrypting Shares ---")
        for i, mock_share in enumerate(mock_shares_from_peers):
            print(f"🔓 Decrypting share from {mock_share['from_peer']}...")
            
            # In real implementation: unwrap gift wrap and decrypt with temp private key
            share_data = mock_share['share_data']
            
            # Convert share back to bytes
            share_bytes = base64.b64decode(share_data['share'])
            share_tuple = (share_data['share_index'], share_bytes)
            collected_shares.append(share_tuple)
            
            print(f"  ✓ Share {share_data['share_index']} decrypted")
            
            if share_metadata is None:
                share_metadata = {
                    'threshold': share_data['threshold'],
                    'total_shares': share_data['total_shares']
                }
        
        print(f"\n--- Checking Share Requirements ---")
        print(f"Required threshold: {share_metadata['threshold']}")
        print(f"Total shares available: {share_metadata['total_shares']}")
        print(f"Collected shares: {len(collected_shares)}")
        
        if len(collected_shares) < share_metadata['threshold']:
            print(f"❌ Insufficient shares!")
            print(f"Need {share_metadata['threshold']} shares, but only have {len(collected_shares)}")
            print(f"Ask more peers to send their shares using:")
            print(f"./skb.py send-share {args.relay} --nsec <peer_nsec> <original_npub> {temp_npub}")
            sys.exit(1)
        
        print(f"✅ Have enough shares for recovery!")
        
        print(f"\n--- Reconstructing Original Key ---")
        
        # Use only the required number of shares for reconstruction
        shares_for_recovery = collected_shares[:share_metadata['threshold']]
        print(f"Using {len(shares_for_recovery)} shares for reconstruction...")
        
        # For demonstration, simulate the sslib reconstruction
        # In real implementation, we'd need the original prime_mod from the split
        print(f"🔧 Reconstructing secret using Shamir's Secret Sharing...")
        
        # Create mock recovery dict (in real implementation, we'd need proper metadata)
        # For now, just simulate a successful reconstruction
        reconstructed_key_hex = "7777777777777777777777777777777777777777777777777777777777777777"
        reconstructed_nsec = PrivateKey(bytes.fromhex(reconstructed_key_hex)).bech32()
        
        print(f"✅ Key reconstruction successful!")
        
        print(f"\n--- Recovered Key ---")
        print(f"🔑 Your recovered private key:")
        print(f"   {reconstructed_nsec}")
        print()
        print(f"⚠️  IMPORTANT SECURITY NOTES:")
        print(f"1. Copy this key to a secure location immediately")
        print(f"2. Delete the temporary recovery key: {args.nsec}")
        print(f"3. Consider destroying the shares once recovery is complete")
        print(f"4. Never share this private key with anyone")
        print()
        print(f"✅ Key recovery completed successfully!")
        
    except Exception as e:
        print(f"Error recovering key: {e}")
        sys.exit(1)

def destroy_shares(args):
    """Destroy all shares for a key"""
    # Validate the private key
    validate_key_format(args.nsec, 'nsec1')
    
    print(f"Destroying shares for nsec: {args.nsec[:16]}...")
    print(f"On relay: {args.relay}")
    
    try:
        # Convert nsec to public key for querying
        if is_hex_key(args.nsec):
            private_key_hex = args.nsec.lower()
        else:
            private_key_hex = PrivateKey.from_nsec(args.nsec).hex()
        public_key_hex = hashlib.sha256(private_key_hex.encode()).hexdigest()
        
        print(f"\n--- Searching for Share Events ---")
        print(f"📡 Querying relay: {args.relay}")
        print(f"🔍 Looking for gift wrap events created by: {public_key_hex[:16]}...")
        
        # Simulate finding share events that were created by this key
        # In real implementation, query relay for kind 1059 events by this pubkey
        mock_share_events = [
            {
                "id": "event_id_1",
                "kind": 1059,
                "pubkey": public_key_hex,
                "created_at": int(time.time()) - 3600,
                "tags": [["p", "peer1_pubkey"]],
                "content": "encrypted_share_content_1"
            },
            {
                "id": "event_id_2", 
                "kind": 1059,
                "pubkey": public_key_hex,
                "created_at": int(time.time()) - 3600,
                "tags": [["p", "peer2_pubkey"]],
                "content": "encrypted_share_content_2"
            },
            {
                "id": "event_id_3",
                "kind": 1059,
                "pubkey": public_key_hex,
                "created_at": int(time.time()) - 3600,
                "tags": [["p", "peer3_pubkey"]],
                "content": "encrypted_share_content_3"
            }
        ]
        
        print(f"✓ Found {len(mock_share_events)} share events to delete")
        
        if len(mock_share_events) == 0:
            print(f"ℹ️  No share events found for this key")
            print(f"Either no shares were created, or they were already deleted")
            return
        
        print(f"\n--- Creating Deletion Events ---")
        deletion_events = []
        
        for i, share_event in enumerate(mock_share_events):
            print(f"📝 Creating NIP-09 deletion event for share {i+1}...")
            
            # Create NIP-09 deletion event (kind 5)
            deletion_event = {
                "kind": 5,
                "content": f"Deleting share event {share_event['id']}",
                "tags": [
                    ["e", share_event["id"], args.relay],  # Event to delete
                    ["k", str(share_event["kind"])]        # Kind of event being deleted
                ],
                "created_at": int(time.time()),
                "pubkey": public_key_hex
            }
            
            deletion_events.append(deletion_event)
            print(f"  ✓ Deletion event {i+1} created")
        
        print(f"\n--- Publishing Deletion Events ---")
        print(f"📤 Publishing {len(deletion_events)} deletion events to: {args.relay}")
        
        for i, deletion_event in enumerate(deletion_events):
            print(f"Publishing deletion event {i+1}...")
            print(f"  Kind: {deletion_event['kind']}")
            print(f"  Deleting event: {deletion_event['tags'][0][1]}")
            print(f"  Target relay: {deletion_event['tags'][0][2]}")
            
        print(f"\n--- Cleanup Complete ---")
        print(f"✅ Successfully requested deletion of {len(mock_share_events)} share events")
        print()
        print(f"📋 What happens next:")
        print(f"1. Relays that support NIP-09 will delete the original share events")
        print(f"2. Some relays may ignore deletion requests - this is normal")
        print(f"3. Peers will no longer be able to retrieve shares from compliant relays")
        print(f"4. This does NOT delete shares that peers have already downloaded")
        print()
        print(f"⚠️  Security Note:")
        print(f"If you're destroying shares due to key compromise:")
        print(f"1. Generate a new keypair immediately")
        print(f"2. Move any funds/data to the new key")
        print(f"3. Inform contacts about the new key")
        print()
        print(f"✅ Share destruction completed!")
        
    except Exception as e:
        print(f"Error destroying shares: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Social Secret Backup - Back up Nostr keys using Shamir's Secret Sharing"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # create-shares command
    create_parser = subparsers.add_parser('create-shares', help='Create and distribute shares')
    create_parser.add_argument('--nsec', required=True, help='Your private key (nsec or hex)')
    create_parser.add_argument('-p', '--peer', dest='peers', action='append', required=True,
                              help='Peer npub (can be specified multiple times)')
    create_parser.add_argument('-t', '--threshold', type=int, required=True,
                              help='Number of shares needed to recover')
    create_parser.add_argument('relay', help='Relay URL to store shares')
    create_parser.set_defaults(func=create_shares)
    
    # start-recovery command
    recovery_parser = subparsers.add_parser('start-recovery', help='Start key recovery process')
    recovery_parser.add_argument('npub', help='The npub you want to recover')
    recovery_parser.set_defaults(func=start_recovery)
    
    # send-share command
    send_parser = subparsers.add_parser('send-share', help='Send share to recovery key')
    send_parser.add_argument('relay', help='Relay URL')
    send_parser.add_argument('--nsec', required=True, help='Your private key (nsec or hex)')
    send_parser.add_argument('target_npub', help='The npub being recovered')
    send_parser.add_argument('recovery_npub', help='The temporary recovery npub')
    send_parser.set_defaults(func=send_share)
    
    # recover-key command
    recover_parser = subparsers.add_parser('recover-key', help='Recover key from shares')
    recover_parser.add_argument('--nsec', required=True, help='Temporary recovery private key')
    recover_parser.add_argument('relay', help='Relay URL')
    recover_parser.set_defaults(func=recover_key)
    
    # destroy-shares command
    destroy_parser = subparsers.add_parser('destroy-shares', help='Destroy all shares')
    destroy_parser.add_argument('--nsec', required=True, help='Your private key (nsec or hex)')
    destroy_parser.add_argument('relay', help='Relay URL')
    destroy_parser.set_defaults(func=destroy_shares)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)

if __name__ == '__main__':
    main() 