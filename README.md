# Social Secret Backup

**This is alpha software, please do not use it for real secrets yet.**

This is a tool for backing up Nostr keys to a set of peers. It uses the Shamir's Secret Key Sharing algorithm to break the key into shares so that no peer has your entire key, but if enough peers cooperate they can put their shares together to reassemble the key. This is more secure and less fragile than storing a single copy of the entire key in one location. 

## How to use

### 1. Creatings and sharing shares

Backing up a secret starts by selecting a set of peers to hold your shares. You can select any number of peers, but they need to have a Nostr key (npub).

Once you have a list of your peer's npubs, you can create the shares and send them with the command:

```shell
skb create-shares --nsec nsec123 -p npub123... -p npub456... -p npub789... -t 2 wss://nos.lol
```

Where `nsec123` is your Nostr private key, each peer's npub is passed with `-p`, the number of peers needed to reassemble the key is specificed with `-t`, and the address of the Nostr relay you want to store the shares on is specified at the end.

This will create shares and encrypt each share to each npub (using NIP-44 encryption and NIP-59 gift wrapping), publishing the shares to the given relay. 

### 2. Restoring a key from shares

In the event that you need to recover your key you will need to contact your peers and share your intent to recover. It is important for each peer to authenticate you to protect against phishing attacks. Once authenticated, you will need to share a **temporary key** with each peer along with instructions for them to send their share back to you. You can generate a temporary key (along with example instructions) using the command:

```shell
skb start-recovery npubA
```

Where `npubA` is the npub you wish to recover.

Then each peer will need to install this tool and run:
```shell
skb send-share wss://nos.lol --nsec nsec123 npubA npubB
```

Where `--nsec` is the peer's secret key, `npubA` is the profile you are trying to recover, and `npubB` is your temporary key. This command will download the peer's share from the relay, decrypt it, re-encrypt it for the temporary key, and send it back to the relay.

Once enough peers have sent their shares, you can recover your key by running:

```shell
skb recover-key --nsec nsec123 wss://nos.lol
```

Where `nsec123` is the nsec of your temporary key. This will connect to the relay, download shares sent by your peers to the temporary key, and reassemble them into your original key.

### 3. Destroying a backup

In the event that you want to destroy all shares you can run:
```
skb destroy-shares --nsec nsec123 wss://nos.lol
```

Where `nsec123` is your nsec.
