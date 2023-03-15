package com.android.cborparser.test;

import static com.android.cborparser.KMType.AGREE_KEY;
import static com.android.cborparser.KMType.ATTEST_KEY;
import static com.android.cborparser.KMType.BOTH;
import static com.android.cborparser.KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE;
import static com.android.cborparser.KMType.DECRYPT;
import static com.android.cborparser.KMType.ENCRYPT;
import static com.android.cborparser.KMType.HARDWARE_TYPE;
import static com.android.cborparser.KMType.KEY_FORMAT;
import static com.android.cborparser.KMType.PASSWORD;
import static com.android.cborparser.KMType.PKCS8;
import static com.android.cborparser.KMType.PURPOSE;
import static com.android.cborparser.KMType.RAW;
import static com.android.cborparser.KMType.SIGN;
import static com.android.cborparser.KMType.SOFTWARE;
import static com.android.cborparser.KMType.STRONGBOX;
import static com.android.cborparser.KMType.TRUSTED_ENVIRONMENT;
import static com.android.cborparser.KMType.USER_AUTH_NONE;
import static com.android.cborparser.KMType.USER_AUTH_TYPE;
import static com.android.cborparser.KMType.VERIFY;
import static com.android.cborparser.KMType.WRAP_KEY;
import static com.android.cborparser.KMType.X509;

import com.android.cborparser.KMArray;
import com.android.cborparser.KMByteBlob;
import com.android.cborparser.KMDecoder;
import com.android.cborparser.KMInteger;
import com.android.cborparser.KMKey;
import com.android.cborparser.KMKeyParameters;
import com.android.cborparser.KMKeymasterApplet;
import com.android.cborparser.KMMap;
import com.android.cborparser.KMRepository;
import com.android.cborparser.KMType;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.RandomData;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;

public class CborParserTest {

  public static final byte APDU_P1 = 0x60;
  public static final byte APDU_P2 = 0x00;
  CardSimulator simulator;
  //KMEncoder encoder;
  KMDecoder decoder;
  KMRepository repository;
  //KMKeyParameters keyParameters;

  public CborParserTest() {
    //cryptoProvider = new KMJCardSimulator();
    simulator = new CardSimulator();
    init();
    //encoder = new KMEncoder();
    decoder = new KMDecoder();
    repository = KMRepository.instance();
    //keyParameters = KMKeyParameters.instance(repository);
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
              // new byte[] {
              //     DERIVATION_NONE,
              //     RFC5869_SHA256,
              //     ISO18033_2_KDF1_SHA1,
              //     ISO18033_2_KDF1_SHA256,
              //     ISO18033_2_KDF2_SHA1,
              //     ISO18033_2_KDF2_SHA256
              // },
              // new byte[] {SELF_SIGNED_BOOT, VERIFIED_BOOT, UNVERIFIED_BOOT, FAILED_BOOT},
              // new byte[] {DEVICE_LOCKED_TRUE, DEVICE_LOCKED_FALSE},
              new byte[] {USER_AUTH_NONE, PASSWORD, KMType.FINGERPRINT, BOTH},
              new byte[] {ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, ATTEST_KEY, AGREE_KEY},
              //new byte[] {P_224, P_256, P_384, P_521},
              //new byte[] {IGNORE_INVALID_TAGS, FAIL_ON_INVALID_TAGS}
          };
    short[] types = {
        HARDWARE_TYPE,
        KEY_FORMAT,
        //KEY_DERIVATION_FUNCTION,
        //VERIFIED_BOOT_STATE,
        //DEVICE_LOCKED,
        USER_AUTH_TYPE,
        PURPOSE,
        //ECCURVE,
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
    System.out.println(repository.getHeapIndex());
    short ptr = repository.alloc((short)keyParamsBuf.length);
    Util.arrayCopyNonAtomic(keyParamsBuf, (short) 0, repository.getHeap(), ptr, (short) keyParamsBuf.length);
    System.out.println(KMMap.cast(ptr).length());
    ptr = decoder.decode(KMKeyParameters.expAny(), repository.getHeap(), ptr, (short) keyParamsBuf.length);
    printMapItems(ptr);
    byte[] scratchpad = new byte[512];
    // TEE Enforced
    short teeEnforced = KMKeyParameters.makeTeeEnforced(ptr, scratchpad);
    System.out.println("TEE Enforced:");
    printMapItems(teeEnforced);
    // SB enforced
    byte origin = KMType.GENERATED;
    byte[] val = new byte[] {0x00, 0x01, 0x02};
    short os_version = KMByteBlob.instance(val, (short) 0, (short) val.length);
    // TODO Update according the new function definition.
    // short sbEnforced = KMKeyParameters.makeSbEnforced(ptr, origin, os_version, os_version,
    //     os_version, os_version, scratchpad);
    // System.out.println("Strongbox Enforced:");
    // printMapItems(sbEnforced);
    // System.out.println(repository.getHeapIndex());
  }

  private void init() {
    // Create simulator
    AID appletAID = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID, KMKeymasterApplet.class);
    // Select applet
    simulator.selectApplet(appletAID);

  }

  @Test
  public void testGenerateRsaKey() {
    //8021600000004D
    //String generateKeyCmdStr = "84A91A10000002011A300000031908001A500000C81A000100011A700001F7011A600003F0001A600003F11B0000E677D21FD8181A200000014202031A2000000541001A20000006410140A0400000";
    String generateKeyCmdStr = "84B8221A10000002011A300000031908001A500000C81A000100011A70000131011A600001901B0000017918F916801A600001911B0000017918F916801A600001921B0000017918FE71981A30000195182A1A300001F91A000186A01A700001FA011A700001FD011A600002BD1B0000017918F916801A900002C64767656E657269631A900002C74B76736F635F7838365F36341A900002C854616F73705F63665F7838365F36345F70686F6E651A900002CA4F3030303030303030303030303030301A900002CB4F3030303030303030303030303030301A900002CC46476F6F676C651A900002CD57437574746C6566697368207838365F36342070686F6E651A90000259583F3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031321A900002BC583F3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031321A900002C4587E3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323330313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930311A900002C55903FE30313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323330313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323330313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323330313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313930313233343536373839303132333435363738393031323334353637383930313233303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303130313233343536373839303132333435363738393031323334353637383930313233343536373839301A800003EE440AFEBFF01A900003EF584C304A3148304606035504030C3F3031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031321A700001FC011A100001F8031A600003F0001A600003F11B0000E677D21FD8181A20000001460203020001031A2000000547000401020305061A200000064503010204051A200000CB430004021AA00001F68519BA6F19BA7019BA7019BA7019BA7059027887035901000AA1D8378EE7461BA74CF23224CDC9F1C41AFE041D594E43BB5DE35189A0B2CD28438462C16FF8C1A36029EC8946ACC0C4900EAD0BBD1A386D82C9E25A8610951776A90A0EC1CD4FA2AC1AED16EE54B69AC157917302FC282F6287276B5E374C8FDC4CD0D841C60782E35BAA94AF832720D89348A9C9D583E7DCCD88771007885850AC4777C59A17B97A80CB05FB88FD132E91A01C113F611D7B3F91DC536A57E18172EEB8CA7E35A591DA8934E55C3B49FCDFAC4FA09F2E86389D06EC84A344ACDC7B3822C5CD2844EDD67866D7F84DB0771D1B95516C09F24C6BEAC182A3D3D4AB526D9BF0A2CA50F515AD8B201FCD8B3F473A76D2A2293ABFF5FF5AF09F144C77EDA7E7F38CA95E71359ABE509EAEEDEF88427A3E673458A3BA7359DB83A91A10000002011A300000031908001A500000C81A000100011A2000000141071A100002BE001A300002C11A0001FBD01A300002C21A0003163E1A300002CE1A0134B03D1A300002CF1A0134B03DA0A0A0590100C862B082C0BC655421234947C569AFE511DBE37BD648B9FB16FBAF3A94360900C8372B820CA6F1BF5781A98A80C3066A8E7960DA627F610A228C1B6DD8AC5725BC23A08DD532155F9A197E23FDADA2362AADFDB01747466D16F9391A6DFCFFD858166FD7407CF8B96904FB495734FBAEC4A4EB65C39D15B62E06F897CA6A5DCE47848D95816F91E9001DFDECCA7F0EBA09FA0A58FC77AA3417A1A5D76A59F00E9951B9444FCA0901193B84F640D77556A7ED7BF2FF3FB582ECAD6F5A81D40219A63C699424995987E782D7AF6DE50647EA0B47A86204C05C60F6547883EC116CFA83BF98B3E94D3DF1E4DD307960F953B58AE5C7C3AB3AE684F3AA8453922971A05821301F311D301B06035504030C14416E64726F6964204B657973746F7265204B65790000";
    byte[] generateKeyCmd = hexStringToByteArray(generateKeyCmdStr);
    CommandAPDU apdu = encodeApdu(KMKeymasterApplet.INS_GENERATE_KEY_CMD, generateKeyCmd);
    ResponseAPDU response = simulator.transmitCommand(apdu);
    Assert.assertEquals(0x9000, response.getSW());
    byte[] output = response.getBytes();
    print(output, (short) 0, (short) output.length);
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

  public static CommandAPDU encodeApdu(byte ins, byte[] encodedCmd) {
    byte[] buf = new byte[2500];
    buf[0] = (byte) 0x80;
    buf[1] = ins;
    buf[2] = APDU_P1;
    buf[3] = APDU_P2;
    buf[4] = 0;
    Util.arrayCopyNonAtomic(encodedCmd, (short) 0, buf, (short) 7, (short) encodedCmd.length);
    Util.setShort(buf, (short) 5, (short) encodedCmd.length);
    byte[] apdu = new byte[7 + (short) encodedCmd.length];
    Util.arrayCopyNonAtomic(buf, (short) 0, apdu, (short) 0,
        (short) (7 + (short) encodedCmd.length));
    return new CommandAPDU(apdu);
  }

}


