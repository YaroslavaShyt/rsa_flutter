import 'package:flutter/material.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'dart:typed_data';
import 'dart:convert';

import 'package:pointycastle/pointycastle.dart';

void main() => runApp(const RSAApp());

class RSAApp extends StatelessWidget {
  const RSAApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RSA Encryption App',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const RSAHomePage(),
    );
  }
}

class RSAHomePage extends StatefulWidget {
  const RSAHomePage({super.key});

  @override
  State<RSAHomePage> createState() => _RSAHomePageState();
}

class _RSAHomePageState extends State<RSAHomePage> {
  late AsymmetricKeyPair<PublicKey, PrivateKey> keyPair;
  late RSAPublicKey publicKey;
  late RSAPrivateKey privateKey;

  final TextEditingController _plaintextController = TextEditingController();
  String encryptedText = "";
  String decryptedText = "";

  AsymmetricKeyPair<PublicKey, PrivateKey> generateRSAKeyPair() {
    final keyGen = RSAKeyGenerator()
      ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 5),
        SecureRandom('Fortuna')..seed(KeyParameter(Uint8List(32))),
      ));
    return keyGen.generateKeyPair();
  }

  Uint8List rsaEncrypt(String plaintext, RSAPublicKey publicKey) {
    final encryptor = OAEPEncoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

    final input = Uint8List.fromList(utf8.encode(plaintext));
    return encryptor.process(input);
  }

  String rsaDecrypt(Uint8List ciphertext, RSAPrivateKey privateKey) {
    final decryptor = OAEPEncoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

    final decrypted = decryptor.process(ciphertext);
    return utf8.decode(decrypted);
  }

  void generateKeys() {
    setState(() {
      keyPair = generateRSAKeyPair();
      publicKey = keyPair.publicKey as RSAPublicKey;
      privateKey = keyPair.privateKey as RSAPrivateKey;
    });
  }

  void encryptText() {
    final plaintext = _plaintextController.text;
    if (plaintext.isEmpty) return;

    final encryptedBytes = rsaEncrypt(plaintext, publicKey);
    setState(() {
      encryptedText = base64Encode(encryptedBytes);
    });
  }

  void decryptText() {
    if (encryptedText.isEmpty) return;

    final encryptedBytes = base64Decode(encryptedText);
    final decrypted = rsaDecrypt(encryptedBytes, privateKey);
    setState(() {
      decryptedText = decrypted;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('RSA Encryption App')),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: _plaintextController,
            decoration: const InputDecoration(
              labelText: 'Enter Plaintext',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: generateKeys,
            child: const Text('Generate RSA Keys'),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: encryptText,
            child: const Text('Encrypt'),
          ),
          const SizedBox(height: 8),
          ElevatedButton(
            onPressed: decryptText,
            child: const Text('Decrypt'),
          ),
          const SizedBox(height: 16),
          const Text(
            'Encrypted Text (Base64):',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          SelectableText(encryptedText),
          const SizedBox(height: 16),
          const Text(
            'Decrypted Text:',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          SelectableText(decryptedText),
        ],
      ),
    );
  }
}
