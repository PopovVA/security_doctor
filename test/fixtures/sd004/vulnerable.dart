// Deliberately vulnerable fixture: weak cryptography.
import 'package:crypto/crypto.dart' as crypto;
import 'package:crypto/crypto.dart';
import 'package:pointycastle/pointycastle.dart';

void hashThings(List<int> bytes, List<int> key) {
  md5.convert(bytes);
  sha1.convert(bytes);
  crypto.md5.convert(bytes);
  Hmac(md5, key);
  // ignore: unnecessary_new
  final mac = new Hmac(sha1, key);
  print(mac);
}

void cipherThings() {
  const transformation = 'AES/ECB/PKCS5Padding';
  final cipher = ECBBlockCipher(AESEngine());
  print('$transformation $cipher');
}
