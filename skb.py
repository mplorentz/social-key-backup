#!/usr/bin/env python3
"""
Social Key Backup - A tool for backing up Nostr keys using Shamir's Secret Sharing
"""

import argparse
import sys
import re
import json
import base64

def is_hex_key(key):
    """Check if key looks like a 64-character hex string"""
    return bool(re.match(r'^[0-9a-fA-F]{64}$', key))

def is_bech32_key(key):
    """Check if key looks like a bech32 key (npub/nsec)"""
    return key.startswith(('npub1', 'nsec1'))

def validate_key_format(key, expected_prefix=None):
    """Validate key format and return type"""
    if is_hex_key(key):
        return 'hex'
    elif is_bech32_key(key):
        if expected_prefix and not key.startswith(expected_prefix):
            print(f"Error: Expected {expected_prefix} key, got {key[:5]}...")
            sys.exit(1)
        return 'bech32'
    else:
        print(f"Error: Invalid key format: {key}")
        print("Keys must be either 64-character hex or bech32 format (npub1.../nsec1...)")
        sys.exit(1)

def convert_key_to_hex(key):
    """Convert key to hex format (placeholder - needs nostr library)"""
    if is_hex_key(key):
        return key.lower()
    elif is_bech32_key(key):
        # TODO: Use python-nostr to convert bech32 to hex
        print("Error: bech32 to hex conversion not yet implemented")
        sys.exit(1)
    else:
        print(f"Error: Invalid key format: {key}")
        sys.exit(1)

def convert_hex_to_npub(hex_key):
    """Convert hex public key to npub format (placeholder - needs nostr library)"""
    if not is_hex_key(hex_key):
        print(f"Error: Invalid hex key format: {hex_key}")
        sys.exit(1)
    # TODO: Use python-nostr to convert hex to npub
    print("Error: hex to npub conversion not yet implemented")
    sys.exit(1)

def convert_hex_to_nsec(hex_key):
    """Convert hex private key to nsec format (placeholder - needs nostr library)"""
    if not is_hex_key(hex_key):
        print(f"Error: Invalid hex key format: {hex_key}")
        sys.exit(1)
    # TODO: Use python-nostr to convert hex to nsec
    print("Error: hex to nsec conversion not yet implemented")
    sys.exit(1)

# Crypto Functions (NIP-44 & NIP-59)
def nip44_encrypt(plaintext, sender_privkey, receiver_pubkey):
    """Encrypt using NIP-44 (TODO: implement with python-nostr)"""
    print("Error: NIP-44 encryption not yet implemented")
    sys.exit(1)

def nip44_decrypt(ciphertext, receiver_privkey, sender_pubkey):
    """Decrypt using NIP-44 (TODO: implement with python-nostr)"""
    print("Error: NIP-44 decryption not yet implemented")
    sys.exit(1)

def create_gift_wrap(share_data, sender_privkey, receiver_pubkey):
    """Create NIP-59 gift wrap containing encrypted share"""
    # TODO: Implement gift wrap creation
    # 1. Create rumor (share data)
    # 2. Seal it (kind:13, NIP-44 encrypt, sign with sender key)
    # 3. Gift wrap it (kind:1059, NIP-44 encrypt with random key, add p tag)
    print("TODO: Implement gift wrap creation")
    return {"kind": 1059, "content": "encrypted_share", "tags": [["p", receiver_pubkey]]}

def unwrap_gift_wrap(gift_wrap, receiver_privkey):
    """Unwrap NIP-59 gift wrap to get share data"""
    # TODO: Implement gift wrap unwrapping
    # 1. Decrypt gift wrap with receiver key
    # 2. Decrypt seal with receiver key  
    # 3. Extract share data
    print("TODO: Implement gift wrap unwrapping")
    return {"share": "decrypted_share_data"}

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
    
    print(f"Creating shares for key: {args.nsec}")
    print(f"Peers: {args.peers}")
    print(f"Threshold: {args.threshold}")
    print(f"Relay: {args.relay}")
    
    # Test the encryption pipeline with placeholder data
    test_encryption_pipeline(args)

def test_encryption_pipeline(args):
    """Test the encryption pipeline with sample data"""
    print("\n--- Testing Encryption Pipeline ---")
    share_data = {"share": base64.b64encode(b"test_share").decode(), "threshold": args.threshold}
    print(f"Share data: {share_data}")
    print("TODO: Complete encryption pipeline once python-nostr is integrated")

def start_recovery(args):
    """Generate temporary key and display recovery instructions"""
    # Validate the public key
    validate_key_format(args.npub, 'npub1')
    
    print(f"Starting recovery for npub: {args.npub}")
    print("TODO: Implement start-recovery command")

def send_share(args):
    """Send a share from peer to recovery key"""
    # Validate keys
    validate_key_format(args.nsec, 'nsec1')
    validate_key_format(args.target_npub, 'npub1')
    validate_key_format(args.recovery_npub, 'npub1')
    
    print(f"Sending share from relay: {args.relay}")
    print(f"Using nsec: {args.nsec}")
    print(f"Target npub: {args.target_npub}")
    print(f"Recovery npub: {args.recovery_npub}")
    print("TODO: Implement send-share command")

def recover_key(args):
    """Recover original key from shares"""
    # Validate the temporary private key
    validate_key_format(args.nsec, 'nsec1')
    
    print(f"Recovering key using nsec: {args.nsec}")
    print(f"From relay: {args.relay}")
    print("TODO: Implement recover-key command")

def destroy_shares(args):
    """Destroy all shares for a key"""
    # Validate the private key
    validate_key_format(args.nsec, 'nsec1')
    
    print(f"Destroying shares for nsec: {args.nsec}")
    print(f"On relay: {args.relay}")
    print("TODO: Implement destroy-shares command")

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