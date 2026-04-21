import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:secure_messenger/core/crypto/crypto_engine.dart';
import 'package:secure_messenger/core/crypto/key_manager.dart';

void main() {
  group('E2E Crypto Validation', () {
    test('Round-trip encryption/decryption between two users', () async {
      final x25519 = X25519();
      final ed25519 = Ed25519();

      final sundayPreKp = await x25519.newKeyPair();
      final sundayPrePub = await sundayPreKp.extractPublicKey();

      final femiPreKp = await x25519.newKeyPair();
      final femiPrePub = await femiPreKp.extractPublicKey();

      const originalText = "Hello Femi, this is a secure message!";
      
      final sharedSecret = await x25519.sharedSecretKey(
        keyPair: sundayPreKp,
        remotePublicKey: SimplePublicKey(femiPrePub.bytes, type: KeyPairType.x25519),
      );
      
      final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
      final sessionKey = await hkdf.deriveKey(
        secretKey: sharedSecret,
        nonce: const [],
        info: utf8.encode('SecureMessenger_v1_SessionKey'),
      );
      
      final aes = AesGcm.with256bits(nonceLength: 12);
      final secretBox = await aes.encrypt(
        utf8.encode(originalText),
        secretKey: sessionKey,
      );
      
      final femiSharedSecret = await x25519.sharedSecretKey(
        keyPair: femiPreKp,
        remotePublicKey: SimplePublicKey(sundayPrePub.bytes, type: KeyPairType.x25519),
      );
      
      final femiSessionKey = await hkdf.deriveKey(
        secretKey: femiSharedSecret,
        nonce: const [],
        info: utf8.encode('SecureMessenger_v1_SessionKey'),
      );
      
      final decrypted = await aes.decrypt(secretBox, secretKey: femiSessionKey);
      expect(utf8.decode(decrypted), originalText);
      print('Verified: Peer-to-peer encryption cycle works.');
    });

    test('Self-Key-Exchange (SundayPriv + SundayPub)', () async {
      final x25519 = X25519();
      final kp = await x25519.newKeyPair();
      final pub = await kp.extractPublicKey();
      
      final secret = await x25519.sharedSecretKey(
        keyPair: kp,
        remotePublicKey: pub,
      );
      
      final bytes = await secret.extractBytes();
      expect(bytes.isNotEmpty, true);
      print('Verified: Self-key-exchange works (length ${bytes.length}).');
    });
  });
}
