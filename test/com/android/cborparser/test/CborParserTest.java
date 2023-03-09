package com.android.cborparser.test;

import static com.android.cborparser.KMType.AGREE_KEY;
import static com.android.cborparser.KMType.ATTEST_KEY;
import static com.android.cborparser.KMType.BOTH;
import static com.android.cborparser.KMType.DECRYPT;
import static com.android.cborparser.KMType.DERIVATION_NONE;
import static com.android.cborparser.KMType.DEVICE_LOCKED;
import static com.android.cborparser.KMType.DEVICE_LOCKED_FALSE;
import static com.android.cborparser.KMType.DEVICE_LOCKED_TRUE;
import static com.android.cborparser.KMType.ECCURVE;
import static com.android.cborparser.KMType.ENCRYPT;
import static com.android.cborparser.KMType.FAILED_BOOT;
import static com.android.cborparser.KMType.HARDWARE_TYPE;
import static com.android.cborparser.KMType.ISO18033_2_KDF1_SHA1;
import static com.android.cborparser.KMType.ISO18033_2_KDF1_SHA256;
import static com.android.cborparser.KMType.ISO18033_2_KDF2_SHA1;
import static com.android.cborparser.KMType.ISO18033_2_KDF2_SHA256;
import static com.android.cborparser.KMType.KEY_DERIVATION_FUNCTION;
import static com.android.cborparser.KMType.KEY_FORMAT;
import static com.android.cborparser.KMType.PASSWORD;
import static com.android.cborparser.KMType.PKCS8;
import static com.android.cborparser.KMType.PURPOSE;
import static com.android.cborparser.KMType.P_224;
import static com.android.cborparser.KMType.P_256;
import static com.android.cborparser.KMType.P_384;
import static com.android.cborparser.KMType.P_521;
import static com.android.cborparser.KMType.RAW;
import static com.android.cborparser.KMType.RFC5869_SHA256;
import static com.android.cborparser.KMType.SELF_SIGNED_BOOT;
import static com.android.cborparser.KMType.SIGN;
import static com.android.cborparser.KMType.SOFTWARE;
import static com.android.cborparser.KMType.STRONGBOX;
import static com.android.cborparser.KMType.TRUSTED_ENVIRONMENT;
import static com.android.cborparser.KMType.UNVERIFIED_BOOT;
import static com.android.cborparser.KMType.USER_AUTH_NONE;
import static com.android.cborparser.KMType.USER_AUTH_TYPE;
import static com.android.cborparser.KMType.VERIFIED_BOOT;
import static com.android.cborparser.KMType.VERIFIED_BOOT_STATE;
import static com.android.cborparser.KMType.VERIFY;
import static com.android.cborparser.KMType.WRAP_KEY;
import static com.android.cborparser.KMType.X509;

import com.android.cborparser.KMArray;
import com.android.cborparser.KMByteBlob;
import com.android.cborparser.KMDecoder;
import com.android.cborparser.KMEncoder;
import com.android.cborparser.KMInteger;
import com.android.cborparser.KMKeyParameters;
import com.android.cborparser.KMMap;
import com.android.cborparser.KMRepository;
import com.android.cborparser.KMType;
import com.licel.jcardsim.bouncycastle.crypto.prng.RandomGenerator;
import com.licel.jcardsim.smartcardio.CardSimulator;
import javacard.framework.Util;
import javacard.security.RandomData;
import org.junit.Test;

public class CborParserTest {
  CardSimulator simulator;
  KMEncoder encoder;
  KMDecoder decoder;
  KMRepository repository;

  public CborParserTest() {
    //cryptoProvider = new KMJCardSimulator();
    simulator = new CardSimulator();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
    repository = new KMRepository(false);
    KMType.initialize();
    //decoder = new KMDecoder();
  }

  @Test
  public void testInteger() {
    byte[] num = new byte[8];
    byte[] heap = repository.getHeap();
    RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    for (short i = 7; i >= 0; i--) {
      rng.nextBytes(num, i, (short) 1);
      short ptr = KMInteger.instance(num, (short) 0, (short) 8);
      System.out.println("\nInput:\n");
      print(num, (short) 0, (short) 8);
      System.out.println("\nOutput: \n");
      print(heap, ptr, KMInteger.cast(ptr).length());
    }
  }

  @Test
  public void testDecoderInteger() {
    //byte[] num = new byte[] {0x19, 0x57, 0x49};
    //byte[] num = new byte[] {0x1A, 0x00, 0x01, (byte)0xE2, 0x40};
    //
    byte[] num = new byte[] {0x1B, 0x00, 0x00, 0x00, 0x02, (byte) 0xDF, (byte) 0xDC, 0x47, 0x15};
    short ptr = repository.alloc((short)num.length);
    Util.arrayCopyNonAtomic(num, (short) 0, repository.getHeap(), ptr, (short) num.length);

    ptr = decoder.decode(KMInteger.exp(),
        repository.getHeap(), ptr, (short) num.length);
    byte[] out = new byte[10];
    KMInteger.cast(ptr).getValue(out, (short) 0, (short) 10);
    System.out.println("\nInput:\n");
    print(num, (short) 0, (short) num.length);
    System.out.println("\nOutput: \n");
    print(out, (short) 0, (short) out.length);
  }

  @Test
  public void testArray() {
    // Expression
    short arr = KMArray.instance((short) 3);
    KMByteBlob.exp();
    KMInteger.exp();
    KMArray.instance((short) 2);
    KMByteBlob.exp();
    KMInteger.exp();
    //==========================
    byte[] cborArray = new byte[] {(byte)0x83, 0x43, 0x01, 0x02, 0x03, 0x19, 0x0a, 0x76,
        (byte)0x82, 0x43, 0x01, 0x02, 0x03, 0x19, 0x0a, 0x76};
    short ptr = repository.alloc((short)cborArray.length);
    Util.arrayCopyNonAtomic(cborArray, (short) 0, repository.getHeap(), ptr, (short) cborArray.length);
    ptr = decoder.decode(arr, repository.getHeap(), ptr, (short) cborArray.length);
    printArrayItems(ptr);

    // System.out.println("\nInput:\n");
    // print(cborArray, (short) 0, (short) cborArray.length);
    // System.out.println("\nOutput byte buffer: \n");
    // short temp = KMArray.cast(ptr).get((short) 0);
    // print(KMByteBlob.cast(temp).getBuffer(),
    //     KMByteBlob.cast(temp).getStartOff(),
    //     KMByteBlob.cast(temp).length());
    // System.out.println("\nOutput integer buffer: \n");
    // temp = KMArray.cast(ptr).get((short) 1);
    // byte[] out = new byte[10];
    // KMInteger.cast(temp).getValue(out, (short) 0, (short) 10);
    // print(out, (short) 0, (short) out.length);
  }

  public void printArrayItems(short ptr) {
    System.out.println("[");
    short length = KMArray.cast(ptr).length();
    for (short i = 0; i < length; i++) {
      short child = KMArray.cast(ptr).get((short) i);
      printItems(child);
    }
    System.out.println("]");
  }

  @Test
  public void testMap() {
    // Expression
    short map = KMMap.instance((short) 1);
    KMByteBlob.exp();//Key
    KMArray.instance((short) 3);//Value
    KMInteger.exp();
    KMByteBlob.exp();
    KMArray.instance((short) 2);
    KMInteger.exp();
    KMByteBlob.exp();
    //==========================
    byte[] mapCbor = new byte[] {(byte) 0xA1, 0x43, 0x01, 0x02, 0x03, (byte) 0x83, 0x1A, 0x00, 0x2A,
        (byte) 0xB8, (byte) 0xDD,
        0x43, 0x55, 0x55, 0x55, (byte) 0x82, 0x1A, 0x00, 0x2A, (byte) 0xB8, (byte) 0xDD,
        0x43, 0x55, 0x55, 0x55};
    short ptr = repository.alloc((short)mapCbor.length);
    Util.arrayCopyNonAtomic(mapCbor, (short) 0, repository.getHeap(), ptr, (short) mapCbor.length);
    ptr = decoder.decode(map, repository.getHeap(), ptr, (short) mapCbor.length);
    printMapItems(ptr);
  }

  @Test
  public void testEncoderMapArray() {
    byte[] number = new byte[] {0x01, 0x00, 0x03, 0x04};
    byte[] byteBlob = new byte[] {0x01, 0x00, 0x03, 0x04, 0x0A, 0x0B, 0x0C, 0x40, (byte) 0xFF};
    byte[] second = new byte[] {0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64};
    // Encoder
    short map = KMMap.instance((short) 2);
    KMInteger.instance(number, (short) 0, (short) number.length);
    KMArray.instance((short) 2);
    KMInteger.instance(number, (short) 0, (short) number.length);
    KMByteBlob.instance(byteBlob, (short) 0, (short) byteBlob.length);
    KMByteBlob.instance(second, (short) 0, (short) second.length);
    KMMap.instance((short) 0);
    short mapLen = (short) (repository.getHeapIndex() - map);

    // Expression
    short exp = KMMap.instance((short) 2);
    KMInteger.exp();
    KMArray.instance((short) 2);
    KMInteger.exp();
    KMByteBlob.exp();
    KMByteBlob.exp();
    KMMap.instance((short) 0);
    //====================
    short ptr = decoder.decode(exp, repository.getHeap(), map, mapLen);
    printMapItems(ptr);
  }

  @Test
  public void testEncoderDecEnum() {
      Object[] enums =
          new Object[] {
              new byte[] {SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX},
              new byte[] {X509, PKCS8, RAW},
              new byte[] {
                  DERIVATION_NONE,
                  RFC5869_SHA256,
                  ISO18033_2_KDF1_SHA1,
                  ISO18033_2_KDF1_SHA256,
                  ISO18033_2_KDF2_SHA1,
                  ISO18033_2_KDF2_SHA256
              },
              new byte[] {SELF_SIGNED_BOOT, VERIFIED_BOOT, UNVERIFIED_BOOT, FAILED_BOOT},
              new byte[] {DEVICE_LOCKED_TRUE, DEVICE_LOCKED_FALSE},
              new byte[] {USER_AUTH_NONE, PASSWORD, KMType.FINGERPRINT, BOTH},
              new byte[] {ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, ATTEST_KEY, AGREE_KEY},
              new byte[] {P_224, P_256, P_384, P_521},
              //new byte[] {IGNORE_INVALID_TAGS, FAIL_ON_INVALID_TAGS}
          };
    short[] types = {
        HARDWARE_TYPE,
        KEY_FORMAT,
        KEY_DERIVATION_FUNCTION,
        VERIFIED_BOOT_STATE,
        DEVICE_LOCKED,
        USER_AUTH_TYPE,
        PURPOSE,
        ECCURVE,
        //RULE
    };
    short bufStart = repository.alloc((short) 5);
    byte[] heap = repository.getHeap();
    for (short i = 0; i < types.length; i++) {
      for (short j = 0; j < ((byte[])enums[i]).length; j++) {
        Util.arrayFillNonAtomic(heap, bufStart, (short) 5, (byte) 0);
        // Encode
        short ptr = KMInteger.uint_8(((byte[])enums[i])[j]);
        short len = KMInteger.cast(ptr).length();
        // Copy encoded buf to heap
        Util.arrayCopyNonAtomic(heap, ptr, heap, bufStart, len);
        // Decoder
        short exp = KMInteger.exp(types[i]);
        ptr = decoder.decode(exp, heap, bufStart, len);
        printItems(ptr);
      }
    }
  }

  public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
          + Character.digit(s.charAt(i+1), 16));
    }
    return data;
  }

  @Test
  public void testKeyParamters() {
    String keyParmStr = "A91A10000002011A300000031908001A500000C81A000100011A700001F7011A600003F0001A600003F11B0000E677D21FD8181A200000014202031A2000000541001A200000064101";
    byte[] keyParamsBuf = hexStringToByteArray(keyParmStr);
    short ptr = repository.alloc((short)keyParamsBuf.length);
    Util.arrayCopyNonAtomic(keyParamsBuf, (short) 0, repository.getHeap(), ptr, (short) keyParamsBuf.length);
    ptr = decoder.decode(KMKeyParameters.expAny(), repository.getHeap(), ptr, (short) keyParamsBuf.length);
    printMapItems(ptr);
    // TODO makeSBEnforced, makeTeeEnforced, makeHwEnforced.
  }

  private void printItems(short child) {
    switch (KMType.getMajorType(child)) {
      case KMType.MAJOR_TYPE_INT:
        byte[] out = new byte[8];
        KMInteger.cast(child).getValue(out, (short) 0, (short) 8);
        print(out, (short) 0, (short) out.length);
        break;
      case KMType.MAJOR_TYPE_BYTE_BLOB:
        print(KMByteBlob.cast(child).getBuffer(),
            KMByteBlob.cast(child).getStartOff(),
            KMByteBlob.cast(child).length());
        break;
      case KMType.MAJOR_TYPE_ARRAY:
        printArrayItems(child);
        break;
      case KMType.MAJOR_TYPE_MAP:
        printMapItems(child);
        break;
    }
  }
  public void printMapItems(short ptr) {
    System.out.println("{");
    short length = KMMap.cast(ptr).length();
    for (short i = 0; i < length; i++) {
      short child = KMMap.cast(ptr).getKey((short) i);
      System.out.println("Key:");
      printItems(child);//Key
      child = KMMap.cast(ptr).getKeyValue((short) i);
      System.out.println("Value:");
      printItems(child);//Value
    }
    System.out.println("}");
  }

  private void print(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format(" 0x%02X", buf[i]));
    }
    System.out.println(sb.toString());
  }

}
