// Clean fixture: nothing here should trigger SD004.
import 'package:crypto/crypto.dart';
import 'package:pointycastle/pointycastle.dart';

void hashThings(List<int> bytes, List<int> key) {
  sha256.convert(bytes);
  sha512.convert(bytes);
  Hmac(sha256, key);

  // Identifiers that merely contain the substring are fine.
  final md5sum = lookupChecksum();
  print(md5sum);
}

String lookupChecksum() => 'not a digest call';

void cipherThings() {
  const transformation = 'AES/GCM/NoPadding';
  final cipher = GCMBlockCipher(AESEngine());
  print('$transformation $cipher');
}
