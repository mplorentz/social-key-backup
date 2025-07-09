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
import ssl
from sslib import shamir
import time
import hashlib
from nostr.key import PrivateKey, PublicKey
from nostr.event import Event
from nostr.relay_manager import RelayManager
from nostr.filter import Filter, Filters
from nostr.message_type import ClientMessageType
import asyncio
import json

# TODO: what do about duplicate shares on relay?

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

def create_gift_wrap(share_data, sender_privkey, receiver_pubkey):
    """Create NIP-59 gift wrap containing encrypted share"""
    try:
        # Convert keys to proper format
        if is_hex_key(sender_privkey):
            sender_key = PrivateKey(bytes.fromhex(sender_privkey))
        else:
            sender_key = PrivateKey.from_nsec(sender_privkey)
            
        if is_hex_key(receiver_pubkey):
            receiver_key = PublicKey(bytes.fromhex(receiver_pubkey))
        else:
            receiver_key = PublicKey.from_npub(receiver_pubkey)
        
        # Step 1: Create rumor (unsigned event with share data)
        # I know rumor is supposed to be a nostr event, but why? I'm not
        # going to bother with that for this prototype, we'll just use raw JSON.
        rumor_content = json.dumps({
            "share": share_data["share"],
            "threshold": share_data["threshold"],
            "share_index": share_data.get("share_index", 1),
            "total_shares": share_data.get("total_shares", 2),
            "prime_mod": base64.b64encode(share_data.get("prime_mod")).decode() if isinstance(share_data.get("prime_mod"), bytes) else share_data.get("prime_mod"),  # Only encode if it's bytes
            "creator_pubkey": share_data.get("creator_pubkey"),  # Include creator pubkey for verification
            "created_at": int(time.time())
        })
        
        # Step 2: Create seal (kind 13 event with encrypted rumor)
        # Encrypt rumor using NIP-44 from sender to receiver
        encrypted_rumor = sender_key.encrypt_message(rumor_content, receiver_key.hex())
        
        # Create and sign the seal event with sender's private key
        seal_event = Event(
            kind=13,
            content=encrypted_rumor,
            tags=[],
            created_at=int(time.time()),
            public_key=sender_key.public_key.hex()
        )
        sender_key.sign_event(seal_event)
        
        # Step 3: Create gift wrap (kind 1059 event with encrypted seal)
        # Generate random key for gift wrap
        random_key = PrivateKey()
        
        # Encrypt seal using random key to receiver (convert signed event to JSON)
        seal_dict = {
            "id": seal_event.id,
            "kind": seal_event.kind,
            "content": seal_event.content,
            "tags": seal_event.tags,
            "created_at": seal_event.created_at,
            "pubkey": seal_event.public_key,
            "sig": seal_event.signature
        }
        
        gift_wrap_content = random_key.encrypt_message(json.dumps(seal_dict), receiver_key.hex())
        
        # Create and sign the gift wrap event with random private key
        gift_wrap_event = Event(
            kind=1059,
            content=gift_wrap_content,
            tags=[["p", receiver_key.hex()]],
            created_at=int(time.time()),
            public_key=random_key.public_key.hex()
        )
        random_key.sign_event(gift_wrap_event)
        
        # Convert to dict format for return
        gift_wrap = {
            "id": gift_wrap_event.id,
            "kind": gift_wrap_event.kind,
            "content": gift_wrap_event.content,
            "tags": gift_wrap_event.tags,
            "created_at": gift_wrap_event.created_at,
            "pubkey": gift_wrap_event.public_key,
            "sig": gift_wrap_event.signature
        }
        
        return gift_wrap
        
    except Exception as e:
        print(f"Error creating gift wrap: {e}")
        sys.exit(1)

def unwrap_gift_wrap(gift_wrap_event, receiver_privkey):
    """Unwrap NIP-59 gift wrap to get share data"""
    try:
        # Convert receiver private key to proper format
        if is_hex_key(receiver_privkey):
            receiver_key = PrivateKey(bytes.fromhex(receiver_privkey))
        else:
            receiver_key = PrivateKey.from_nsec(receiver_privkey)
        
        # Step 1: Extract gift wrap information and verify signature
        encrypted_content = gift_wrap_event.get('content', '')
        random_pubkey = gift_wrap_event.get('pubkey', '')  # Random key's public key
        
        # Verify gift wrap event signature
        try:
            gift_wrap_obj = Event(
                kind=gift_wrap_event['kind'],
                content=gift_wrap_event['content'],
                tags=gift_wrap_event['tags'],
                created_at=gift_wrap_event['created_at'],
                public_key=gift_wrap_event['pubkey']
            )
            gift_wrap_obj.signature = gift_wrap_event['sig']
            gift_wrap_obj.id = gift_wrap_event['id']
            
            if not gift_wrap_obj.verify():
                print(f"    Debug: Gift wrap event signature verification failed")
                return None
            
        except Exception as e:
            print(f"    Debug: Failed to verify gift wrap signature: {e}")
            return None
        
        # Step 2: Decrypt the gift wrap content
        # The content was encrypted FROM random_key TO receiver_key
        # So we decrypt FROM receiver_key TO random_key
        try:
            decrypted_seal_json = receiver_key.decrypt_message(encrypted_content, random_pubkey)
        except Exception as e:
            print(f"    Debug: Failed to decrypt gift wrap content: {e}")
            return None
        
        # Step 3: Parse the seal event
        try:
            seal_data = json.loads(decrypted_seal_json)
            
            # Verify seal event signature
            seal_event = Event(
                kind=seal_data['kind'],
                content=seal_data['content'],
                tags=seal_data['tags'],
                created_at=seal_data['created_at'],
                public_key=seal_data['pubkey']
            )
            seal_event.signature = seal_data['sig']
            seal_event.id = seal_data['id']
            
            if not seal_event.verify():
                print(f"    Debug: Seal event signature verification failed")
                return None
            
        except Exception as e:
            print(f"    Debug: Failed to parse seal event JSON: {e}")
            return None
        
        # Step 4: Decrypt the seal content to get the rumor
        seal_content = seal_event.content
        seal_sender = seal_event.public_key  # Original sender's public key
        
        # Decrypt the seal content (rumor) using receiver's key and sender's public key
        try:
            decrypted_rumor = receiver_key.decrypt_message(seal_content, seal_sender)
        except Exception as e:
            print(f"    Debug: Failed to decrypt seal content: {e}")
            return None
        
        # Step 5: Parse the rumor to get share data
        try:
            share_data = json.loads(decrypted_rumor)
        except Exception as e:
            print(f"    Debug: Failed to parse rumor JSON: {e}")
            return None
        
        return {
            "share": share_data.get("share"),
            "threshold": share_data.get("threshold"),
            "share_index": share_data.get("share_index", 1),
            "total_shares": share_data.get("total_shares", 2),
            "prime_mod": base64.b64decode(share_data.get("prime_mod")) if isinstance(share_data.get("prime_mod"), str) and share_data.get("prime_mod") else share_data.get("prime_mod"),  
            "creator_pubkey": share_data.get("creator_pubkey") 
        }
        
    except Exception as e:
        print(f"Error unwrapping gift wrap: {e}")
        # Return None to indicate failure
        return None

def create_shares(args):
    """Create and distribute shares of a secret key to peers"""
    validate_key_format(args.nsec, 'nsec1')
    for peer in args.peers:
        validate_key_format(peer, 'npub1')
    
    # Validate threshold
    if args.threshold < 2:
        print(f"Error: Threshold {args.threshold} must be higher than 1")
        sys.exit(1)
    if args.threshold > len(args.peers):
        print(f"Error: Threshold {args.threshold} must be between 2 and {len(args.peers)} (number of peers)")
        sys.exit(1)
    
    try:
        # Convert nsec to hex for secret sharing
        if is_hex_key(args.nsec):
            private_key_hex = args.nsec.lower()
        else:
            private_key_hex = PrivateKey.from_nsec(args.nsec).hex()
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        print(f"\n--- Creating Shamir's Secret Shares ---")
        
        # Create shares using sslib
        shares_result = shamir.split_secret(private_key_bytes, args.threshold, len(args.peers))
        shares_list = shares_result['shares']
        prime_mod = shares_result['prime_mod']  
        print(f"Created {len(shares_list)} shares with threshold {args.threshold}")
        print(f"Prime modulus: {prime_mod}")
        
        # Encrypt and wrap each share for each peer
        print(f"\n--- Encrypting Shares for Peers ---")
        gift_wraps = []
        
        # Get creator's public key
        if is_hex_key(args.nsec):
            creator_private_key = PrivateKey(bytes.fromhex(args.nsec))
        else:
            creator_private_key = PrivateKey.from_nsec(args.nsec)
        creator_pubkey = creator_private_key.public_key.hex()
        
        for i, (peer_npub, share_tuple) in enumerate(zip(args.peers, shares_list)):
            share_index, share_bytes = share_tuple
            print(f"Processing share {i+1} for peer: {peer_npub[:16]}...")
            
            # Prepare share data (include prime_mod for recovery)
            share_data = {
                "share": base64.b64encode(share_bytes).decode(),
                "threshold": args.threshold,
                "share_index": share_index,
                "total_shares": len(args.peers),
                "prime_mod": prime_mod,  
                "creator_pubkey": creator_pubkey  
            }
            
            # Create gift wrap for this peer
            gift_wrap = create_gift_wrap(share_data, args.nsec, peer_npub)
            gift_wraps.append(gift_wrap)
            
            print(f"  ✓ Encrypted share {i+1} for peer {peer_npub[:16]}...")
        
        print(f"\n--- Publishing to Relay ---")
        print(f"Relay: {args.relay}")
        
        # Create relay manager and publish events
        print(f"📡 Connecting to relay...")
        relay_manager = create_relay_manager(args.relay)
        
        published_count = 0
        for i, gift_wrap in enumerate(gift_wraps):
            print(f"📤 Publishing gift wrap {i+1}/{len(gift_wraps)}...")
            
            event_id = publish_event_to_relay(relay_manager, gift_wrap, args.nsec)
            if event_id:
                print(f"  ✓ Published event: {event_id[:16]}...")
                published_count += 1
            else:
                print(f"  ❌ Failed to publish event {i+1}")
        
        # Close relay connections
        relay_manager.close_connections()
        print(f"✓ Published {published_count}/{len(gift_wraps)} events to relay")
        
        # Sanity check that we can reconstruct the secret from the shares
        test_shares = shares_list[:args.threshold]  # Take only threshold number of shares
        
        # Reconstruct the dict format that recover_secret expects
        test_dict = {
            'required_shares': shares_result['required_shares'],
            'prime_mod': prime_mod,  # Use the actual prime_mod
            'shares': test_shares
        }
        reconstructed = shamir.recover_secret(test_dict)
        
        if reconstructed != private_key_bytes:
            print(f"✗ Share reconstruction test FAILED. This is a bug.")
            sys.exit(1)
            return
        
        print(f"\n--- Success ---")
        print(f"✓ Created {len(shares_list)} shares with threshold {args.threshold}")
        print(f"✓ Encrypted shares for {len(args.peers)} peers")
        print(f"✓ Published {published_count}/{len(gift_wraps)} events to relay")
        
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
    temp_key = PrivateKey()
    temp_nsec = temp_key.bech32()
    temp_npub = temp_key.public_key.bech32()
    
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
    validate_key_format(args.nsec, 'nsec1')
    validate_key_format(args.target_npub, 'npub1')
    validate_key_format(args.recovery_npub, 'npub1')
    
    try:
        print(f"--- Querying Relay for Shares ---")
        print(f"Searching for gift wrap events sent to: {args.nsec[:16]}...")
        
        # Convert peer's nsec to public key hex for searching
        if is_hex_key(args.nsec):
            peer_private_hex = args.nsec.lower()
            peer_private_key = PrivateKey(bytes.fromhex(peer_private_hex))
            peer_pubkey_hex = peer_private_key.public_key.hex()
        else:
            peer_private_key = PrivateKey.from_nsec(args.nsec)
            peer_pubkey_hex = peer_private_key.public_key.hex()
        
        peer_npub = PublicKey(bytes.fromhex(peer_pubkey_hex)).bech32()
        
        # Convert target_npub to hex for verification
        if is_hex_key(args.target_npub):
            target_pubkey_hex = args.target_npub.lower()
        else:
            target_pubkey_hex = PublicKey.from_npub(args.target_npub).hex()
        
        print(f"📡 Connecting to relay: {args.relay}")
        relay_manager = create_relay_manager(args.relay)
        
        print(f"🔍 Looking for kind 1059 events with p tag: {peer_pubkey_hex[:16]}...")
        
        # Query for gift wrap events sent to this peer (p-tags use hex format)
        events = query_events_from_relay(
            relay_manager,
            kinds=[1059],
            p_tags=[peer_pubkey_hex]
        )
        
        relay_manager.close_connections()
        
        if not events:
            print(f"❌ No share events found for this peer")
            print(f"   Make sure shares have been created and published for: {peer_npub[:16]}...")
            sys.exit(1)
        
        print(f"✓ Found {len(events)} share events")

        # Sort shares so we get the newest one first.
        events.sort(key=lambda event: event['created_at'], reverse=True)
        
        # Process each event to find the right share
        decrypted_share = None
        for i, event in enumerate(events):
            print(f"🔓 Attempting to decrypt gift wrap event {i+1}/{len(events)}...")
            
            # Try to unwrap this gift wrap
            share_data = unwrap_gift_wrap(event, args.nsec)
            
            if share_data:
                print(f"  ✓ Successfully decrypted share from event {i+1}")
                
                # Verify that this share is for the target npub being recovered
                share_creator_pubkey = share_data.get('creator_pubkey', '')
                if share_creator_pubkey.lower() != target_pubkey_hex.lower():
                    print(f"  ❌ Share verification failed: share is not for target npub")
                    print(f"    Share creator: {share_creator_pubkey[:16]}...")
                    print(f"    Target npub:   {target_pubkey_hex[:16]}...")
                    continue
                print(f"  ✓ Share verified for target npub: {target_pubkey_hex[:16]}...")
                
                decrypted_share = share_data
                break
            else:
                print(f"  ❌ Failed to decrypt event {i+1}")
        
        if not decrypted_share:
            print(f"❌ Could not decrypt any share events or verify them for target npub")
            print(f"   Make sure this peer has shares for the target npub: {args.target_npub[:16]}...")
            sys.exit(1)
        
        print(f"\n--- Re-encrypting for Recovery Key ---")
        print(f"🔐 Encrypting share for temporary recovery key...")
        
        # Create gift wrap for the recovery key
        recovery_gift_wrap = create_gift_wrap(decrypted_share, args.nsec, args.recovery_npub)
        
        print(f"✓ Created new gift wrap for recovery key")
        print(f"  Sending to: {args.recovery_npub[:16]}...")
        
        print(f"\n--- Publishing to Relay ---")
        print(f"📤 Publishing recovery gift wrap to: {args.relay}")
        
        # Connect to relay and publish the re-encrypted share
        relay_manager = create_relay_manager(args.relay)
        
        event_id = publish_event_to_relay(relay_manager, recovery_gift_wrap, args.nsec)
        
        relay_manager.close_connections()
        
        if event_id:
            print(f"✓ Published recovery event: {event_id[:16]}...")
        else:
            print(f"❌ Failed to publish recovery event")
            sys.exit(1)
        
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
        # Convert temp nsec to public key hex for querying
        if is_hex_key(args.nsec):
            temp_private_hex = args.nsec.lower()
            temp_private_key = PrivateKey(bytes.fromhex(temp_private_hex))
            temp_pubkey_hex = temp_private_key.public_key.hex()
        else:
            temp_private_key = PrivateKey.from_nsec(args.nsec)
            temp_pubkey_hex = temp_private_key.public_key.hex()
        
        temp_npub = PublicKey(bytes.fromhex(temp_pubkey_hex)).bech32()
        
        print(f"\n--- Querying Relay for Recovery Shares ---")
        print(f"Temporary npub: {temp_npub[:16]}...")
        print(f"📡 Connecting to relay: {args.relay}")
        
        relay_manager = create_relay_manager(args.relay)
        
        print(f"🔍 Looking for kind 1059 events with p tag: {temp_pubkey_hex[:16]}...")
        
        # Query for recovery shares sent to temporary key (p-tags use hex format)
        events = query_events_from_relay(
            relay_manager,
            kinds=[1059],
            p_tags=[temp_pubkey_hex],
            since=int(time.time()) - 86400  # Last 24 hours
        )
        
        relay_manager.close_connections()
        
        if not events:
            print(f"❌ No recovery shares found for temporary key")
            print(f"   Ask peers to send their shares using:")
            print(f"   ./skb.py send-share {args.relay} --nsec <peer_nsec> <original_npub> {temp_npub}")
            sys.exit(1)
        
        print(f"✓ Found {len(events)} recovery share events")
        
        # Process the events to extract share data
        collected_shares = []
        share_metadata = None
        
        print(f"\n--- Decrypting Shares ---")
        for i, event in enumerate(events):
            print(f"🔓 Decrypting share from event {i+1}/{len(events)}...")
            
            # Use the unwrap_gift_wrap function to decrypt each recovery share
            share_data = unwrap_gift_wrap(event, args.nsec)
            
            if share_data:
                print(f"  ✓ Share {i+1} decrypted successfully")
                print(f"    Share index: {share_data['share_index']}")
                print(f"    Threshold: {share_data['threshold']}")
                print(f"    Total shares: {share_data['total_shares']}")
                
                # Convert share back to bytes for sslib
                share_bytes = base64.b64decode(share_data['share'])
                share_tuple = (share_data['share_index'], share_bytes)
                collected_shares.append(share_tuple)
                
                # Store metadata from first valid share
                if share_metadata is None:
                    share_metadata = {
                        'threshold': share_data['threshold'],
                        'total_shares': share_data['total_shares'],
                        'prime_mod': share_data['prime_mod']  # Store the actual prime_mod
                    }
            else:
                print(f"  ❌ Failed to decrypt share from event {i+1}")
        
        if not collected_shares:
            print(f"❌ Could not decrypt any recovery shares")
            print(f"   Make sure peers have sent their shares using:")
            print(f"   ./skb.py send-share {args.relay} --nsec <peer_nsec> <original_npub> {temp_npub}")
            sys.exit(1)
        
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
        
        # Reconstruct the secret using sslib
        print(f"🔧 Reconstructing secret using Shamir's Secret Sharing...")
        
        # Use the actual prime_mod from the shares
        try:
            # Create the dict format that sslib expects
            recovery_dict = {
                'required_shares': share_metadata['threshold'],
                'prime_mod': share_metadata['prime_mod'],  # Use actual prime_mod from shares
                'shares': shares_for_recovery
            }
            
            reconstructed_bytes = shamir.recover_secret(recovery_dict)
            reconstructed_key_hex = reconstructed_bytes.hex()
            reconstructed_nsec = PrivateKey(reconstructed_bytes).bech32()
            
            print(f"✅ Key reconstruction successful!")
            
        except Exception as e:
            print(f"❌ Key reconstruction failed: {e}")
            print(f"This could be due to:")
            print(f"  - Corrupted shares")
            print(f"  - Wrong threshold")
            print(f"  - Mismatched prime_mod values")
            sys.exit(1)
        
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

# Relay Helper Functions
def create_relay_manager(relay_url):
    """Create and configure a relay manager"""
    relay_manager = RelayManager()
    relay_manager.add_relay(relay_url)
    # TODO: require SSL
    relay_manager.open_connections({"cert_reqs": ssl.CERT_NONE})
    # Give the connection a moment to establish
    time.sleep(2)
    return relay_manager

def publish_event_to_relay(relay_manager, event_dict, private_key):
    """Publish an event to relays using the relay manager"""
    try:
        # Check if event is already signed (has signature and id)
        if 'sig' in event_dict and 'id' in event_dict:
            # Event is already signed, use it as-is
            event = Event(
                kind=event_dict['kind'],
                content=event_dict['content'],
                tags=event_dict['tags'],
                created_at=event_dict['created_at'],
                public_key=event_dict['pubkey']
            )
            event.signature = event_dict['sig']
            event.id = event_dict['id']
        else:
            # Event needs to be signed
            # Get the private key object
            if isinstance(private_key, str):
                if private_key.startswith('nsec1'):
                    priv_key = PrivateKey.from_nsec(private_key)
                else:
                    priv_key = PrivateKey(bytes.fromhex(private_key))
            else:
                priv_key = private_key
            
            # Create proper Event object with the correct public key for signing
            event = Event(
                kind=event_dict['kind'],
                content=event_dict['content'],
                tags=event_dict['tags'],
                created_at=event_dict['created_at'],
                public_key=priv_key.public_key.hex()
            )
            
            # Sign the event using the private key
            priv_key.sign_event(event)
        
        # Publish with retry
        max_retries = 3
        for attempt in range(max_retries):
            try:
                relay_manager.publish_event(event)
                # Give a moment for the publish to complete
                time.sleep(1)
                return event.id
            except Exception as publish_error:
                if attempt == max_retries - 1:
                    raise publish_error
                # Wait before retry
                time.sleep(2)
        
        return event.id
        
    except Exception as e:
        print(f"Error publishing event: {e}")
        return None

def query_events_from_relay(relay_manager, kinds=None, authors=None, p_tags=None, since=None, limit=50):
    """Query events from relays"""
    try:
        # Create filter
        filter_obj = Filter(
            kinds=kinds,
            authors=authors,
            pubkey_refs=p_tags,
            since=since,
            limit=limit
        )
        
        filters = Filters([filter_obj])
        subscription_id = f"skb_{int(time.time())}"
        
        # Create request message
        request = [ClientMessageType.REQUEST, subscription_id]
        request.extend(filters.to_json_array())
        
        # Add subscription and publish request
        relay_manager.add_subscription(subscription_id, filters)
        
        # Publish the query request
        message = json.dumps(request)
        relay_manager.publish_message(message)
        
        # Wait for events to arrive
        time.sleep(2)
        
        # Collect events from message pool
        events = []
        while relay_manager.message_pool.has_events():
            try:
                event_msg = relay_manager.message_pool.get_event()
                if event_msg and event_msg.event:
                    # Convert to dict format for compatibility
                    event_dict = {
                        'id': event_msg.event.id,
                        'kind': event_msg.event.kind,
                        'content': event_msg.event.content,
                        'tags': event_msg.event.tags,
                        'created_at': event_msg.event.created_at,
                        'pubkey': event_msg.event.public_key,
                        'sig': event_msg.event.signature
                    }
                    events.append(event_dict)
            except Exception as e:
                print(f"Error processing event: {e}")
                continue
        
        return events
        
    except Exception as e:
        print(f"Error querying events: {e}")
        return []

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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)

if __name__ == '__main__':
    main() 