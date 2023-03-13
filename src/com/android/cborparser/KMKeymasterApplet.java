package com.android.cborparser;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

public class KMKeymasterApplet extends Applet implements ExtendedLength {

  public static byte[] heap = null;
  public static short[] heapIndex = null;
  public static short[] reclaimIndex = null;
  private static final byte KEYMINT_CMD_APDU_START = 0x20;
  public static final byte INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1; // 0x21
  protected static KMRepository repository;
  protected static KMAndroidSEProvider seProvider;
  protected static KMDecoder decoder;
  // Short array used to store the temporary results.
  protected static short[] tmpVariables;
  // Short array used to hold the dictionary items.
  protected static short[] data;
  // Temporary variables array size to store intermediary results.
  public static final byte TMP_VARIABLE_ARRAY_SIZE = 5;
  // Data Dictionary items
  // Maximum Dictionary size.
  public static final byte DATA_ARRAY_SIZE = 39;
  // Below are the offsets of the data dictionary items.
  public static final byte KEY_PARAMETERS = 0;
  public static final byte KEY_CHARACTERISTICS = 1;
  public static final byte HIDDEN_PARAMETERS = 2;
  //public static final byte HW_PARAMETERS = 3;
  public static final byte SW_PARAMETERS = 4;
  public static final byte AUTH_DATA = 5;
  public static final byte AUTH_TAG = 6;
  public static final byte NONCE = 7;
  public static final byte KEY_BLOB = 8;
  public static final byte AUTH_DATA_LENGTH = 9;
  public static final byte SECRET = 10;
  public static final byte ROT = 11;
  public static final byte DERIVED_KEY = 12;
  public static final byte RSA_PUB_EXPONENT = 13;
  public static final byte APP_ID = 14;
  public static final byte APP_DATA = 15;
  public static final byte PUB_KEY = 16;
  public static final byte IMPORTED_KEY_BLOB = 17;
  public static final byte ORIGIN = 18;
  public static final byte NOT_USED = 19;
  public static final byte MASKING_KEY = 20;
  public static final byte HMAC_SHARING_PARAMS = 21;
  public static final byte OP_HANDLE = 22;
  public static final byte IV = 23;
  public static final byte INPUT_DATA = 24;
  public static final byte OUTPUT_DATA = 25;
  public static final byte HW_TOKEN = 26;
  public static final byte VERIFICATION_TOKEN = 27;
  public static final byte SIGNATURE = 28;
  public static final byte ATTEST_KEY_BLOB = 29;
  public static final byte ATTEST_KEY_PARAMS = 30;
  public static final byte ATTEST_KEY_ISSUER = 31;
  public static final byte CERTIFICATE = 32;
  public static final byte PLAIN_SECRET = 33;
  public static final byte TEE_PARAMETERS = 34;
  public static final byte SB_PARAMETERS = 35;
  public static final byte CONFIRMATION_TOKEN = 36;
  public static final byte KEY_BLOB_VERSION_DATA_OFFSET = 37;
  public static final byte CUSTOM_TAGS = 38;
  // Below are the Keyblob offsets.
  public static final byte KEY_BLOB_VERSION_OFFSET = 0;
  public static final byte KEY_BLOB_SECRET = 1;
  public static final byte KEY_BLOB_NONCE = 2;
  public static final byte KEY_BLOB_AUTH_TAG = 3;
  public static final byte KEY_BLOB_PARAMS = 4;
  public static final byte KEY_BLOB_CUSTOM_TAGS = 5;
  public static final byte KEY_BLOB_PUB_KEY = 6;
  // KEYBLOB_CURRENT_VERSION goes into KeyBlob and will affect all
  // the KeyBlobs if it is changed. please increment this
  // version number whenever you change anything related to
  // KeyBlob (structure, encryption algorithm etc).
  public static final byte KEYBLOB_CURRENT_VERSION = 3;
  // KeyBlob Verion 1 constant.
  public static final byte KEYBLOB_VERSION_1 = 1;
  // Array sizes of KeyBlob under different versions.
  // The array size of a Symmetric key's KeyBlob for Version2 and Version3
  public static final byte SYM_KEY_BLOB_SIZE_V2_V3 = 6;
  // The array size of a Asymmetric key's KeyBlob for Version2 and Version3
  public static final byte ASYM_KEY_BLOB_SIZE_V2_V3 = 7;
  // The array size of a Symmetric key's KeyBlob for Version1
  public static final byte SYM_KEY_BLOB_SIZE_V1 = 5;
  // The array size of a Asymmetric key's KeyBlob for Version1
  public static final byte ASYM_KEY_BLOB_SIZE_V1 = 6;
  // The array size of a Symmetric key's KeyBlob for Version0
  public static final byte SYM_KEY_BLOB_SIZE_V0 = 4;
  // The array size of a Asymmetric key's KeyBlob for Version0
  public static final byte ASYM_KEY_BLOB_SIZE_V0 = 5;
  // Represents the type of the Symmetric key.
  public static final byte SYM_KEY_TYPE = 0;
  // Represents the type of the Asymmetric key.
  public static final byte ASYM_KEY_TYPE = 1;
  public static final short MASTER_KEY_SIZE = 128;

  // The size of the verified boot key in ROT.
  public static final byte VERIFIED_BOOT_KEY_SIZE = 32;
  // The size of the verified boot hash in ROT.
  public static final byte VERIFIED_BOOT_HASH_SIZE = 32;
  // Below are the constants for provision reporting status
  public static final short NOT_PROVISIONED = 0x0000;
  public static final short PROVISION_STATUS_ATTESTATION_KEY = 0x0001;
  public static final short PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x0002;
  public static final short PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x0004;
  public static final short PROVISION_STATUS_ATTEST_IDS = 0x0008;
  public static final short PROVISION_STATUS_PRESHARED_SECRET = 0x0010;
  public static final short PROVISION_STATUS_PROVISIONING_LOCKED = 0x0020;
  public static final short PROVISION_STATUS_DEVICE_UNIQUE_KEYPAIR = 0x0040;
  public static final short PROVISION_STATUS_UDS_CERT_CHAIN = 0x0080;
  public static final short PROVISION_STATUS_SE_LOCKED = 0x0100;
  public static final short PROVISION_STATUS_OEM_PUBLIC_KEY = 0x0200;
  public static final short PROVISION_STATUS_SECURE_BOOT_MODE = 0x0400;
  protected  static KMKeymintDataStore kmDataStore;
  public static final byte AES_GCM_AUTH_TAG_LENGTH = 16;
  // AES GCM nonce length to be used while encrypting or decrypting the KeyBlob.
  public static final byte AES_GCM_NONCE_LENGTH = 12;
  // The maximum size of the Auth data which is used while encrypting/decrypting the KeyBlob.
  private static final short MAX_AUTH_DATA_SIZE = (short) 512;
  public KMKeymasterApplet() {
    repository = new KMRepository(false);
    seProvider = new KMAndroidSEProvider();
    decoder = new KMDecoder();
    kmDataStore = new KMKeymintDataStore(seProvider, repository);
    data = JCSystem.makeTransientShortArray(DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_DESELECT);
    tmpVariables =
        JCSystem.makeTransientShortArray(TMP_VARIABLE_ARRAY_SIZE, JCSystem.CLEAR_ON_DESELECT);
// For keyMint 3.0 and above installation, set ignore second Imei flag to false.
    kmDataStore.ignoreSecondImei = false;
    kmDataStore.createMasterKey(MASTER_KEY_SIZE);
    KMType.initialize();
    heap = repository.getHeap();
    heapIndex = repository.heapIndex;
    reclaimIndex = repository.reclaimIndex;
    KMKeyParameters.instance(repository);
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KMKeymasterApplet().register();
  }

  private static void makeKeyCharacteristics(byte[] scratchPad) {
    // short osVersion = kmDataStore.getOsVersion();
    // short osPatch = kmDataStore.getOsPatch();
    // short vendorPatch = kmDataStore.getVendorPatchLevel();
    // short bootPatch = kmDataStore.getBootPatchLevel();
    data[KEY_CHARACTERISTICS] = KMArray.instance((short) 3);
    data[SB_PARAMETERS] =
        KMKeyParameters.makeSbEnforced(kmDataStore,
            data[KEY_PARAMETERS],
            (byte) data[ORIGIN],
            scratchPad);
    data[TEE_PARAMETERS] = KMKeyParameters.makeTeeEnforced(data[KEY_PARAMETERS], scratchPad);
    data[SW_PARAMETERS] = KMKeyParameters.makeKeystoreEnforced(data[KEY_PARAMETERS], scratchPad);
    //data[HW_PARAMETERS] = KMKeyParameters.makeHwEnforced(data[SB_PARAMETERS], data[TEE_PARAMETERS]);
    // TODO Construct/Move at the end.
    // data[KEY_CHARACTERISTICS] = KMKeyCharacteristics.instance();
    // KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setStrongboxEnforced(data[SB_PARAMETERS]);
    // KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setKeystoreEnforced(data[SW_PARAMETERS]);
    // KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setTeeEnforced(data[TEE_PARAMETERS]);
  }

  private static byte getKeyType(short hardwareParams) {
    short alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hardwareParams);
    if (KMInteger.cast(alg).getShort() == KMType.RSA
        || KMInteger.cast(alg).getShort() == KMType.EC) {
      return ASYM_KEY_TYPE;
    }
    return SYM_KEY_TYPE;
  }

  private static short deriveKey(byte[] scratchPad) {
    // For KeyBlob V3: Auth Data includes HW_PARAMETERS, HIDDEN_PARAMETERS, CUSTOM_TAGS, VERSION and
    // PUB_KEY.
    short len = 0;
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 10, (byte) 0);
    byte keyType = getKeyType(data[SB_PARAMETERS]);
    // Copy the relevant parameters in the scratchPad in the order
    // 1. HW_PARAMETERS
    // 2. HIDDEN_PARAMETERS
    // 3. CUSTOM_TAGS
    // 3. VERSION ( Only Version >= 1)
    // 4. PUB_KEY ( Only for Asymmetric Keys)
    short numParams = 4;
    // // For Asymmetric Keys include the PUB_KEY.
    if (keyType == ASYM_KEY_TYPE) {
       numParams = 5;
    }
    KMOperation operation = null;
    try {
      operation =
          seProvider.initSymmetricOperation(
              KMType.SIGN,
              KMType.HMAC,
              KMType.SHA2_256,
              KMType.PADDING_NONE,
              (byte) KMType.INVALID_VALUE,
              (Object) kmDataStore.getMasterKey(),
              KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY,
              (byte[]) null,
              (short) 0,
              (short) 0,
              (short) 0,
              false);

      // prepare array header
      scratchPad[0]  = (byte) 0x80;
      scratchPad[0] |= (byte) numParams;
      operation.update(scratchPad, (short) 0, (short) 1);

      // SB + TEE
      short hwParamsSize = (short) (KMMap.cast(data[SB_PARAMETERS]).length() +
          KMMap.cast(data[TEE_PARAMETERS]).length());
      len = KMMap.instance(hwParamsSize, scratchPad, (short) 0);
      operation.update(scratchPad, (short) 0, len);
      // SB
      operation.update(repository.getHeap(),
          (short) (data[SB_PARAMETERS] + KMMap.cast(data[SB_PARAMETERS]).headerLength()),
          KMMap.cast(data[SB_PARAMETERS]).contentLength());
      // TEE
      operation.update(repository.getHeap(),
          (short) (data[TEE_PARAMETERS] + KMMap.cast(data[TEE_PARAMETERS]).headerLength()),
          KMMap.cast(data[TEE_PARAMETERS]).contentLength());
      // Hidden parameters
      // Create HIDDEN_PARAMETERS
      // Create HIDDEN_PARAMETERS and move to the end of the heap.
      short heapIndex = repository.getHeapIndex();
      len = readROT(scratchPad, KEYBLOB_CURRENT_VERSION);
      // TODO instead of create HIDDEN_PARAMETERS we can create MAP inside
      // TODO scratchPad itself.
      data[HIDDEN_PARAMETERS] =
          KMKeyParameters.makeHidden(data[KEY_PARAMETERS], scratchPad, (short) 0, len);
      len = (short) (KMMap.cast(data[HIDDEN_PARAMETERS]).contentLength() +
          KMMap.cast(data[HIDDEN_PARAMETERS]).headerLength());

      operation.update(repository.getHeap(), data[HIDDEN_PARAMETERS], len);
      // Clear the hidden parameters.
      Util.arrayFillNonAtomic(repository.getHeap(), heapIndex, len, (byte) 0);
      repository.setHeapIndex(heapIndex);
      // Custom tags
      operation.update(repository.getHeap(),
          data[CUSTOM_TAGS],
          (short) (KMMap.cast(data[CUSTOM_TAGS]).contentLength() +
              KMMap.cast(data[CUSTOM_TAGS]).headerLength()));
      // KeyBlobVersion
      operation.update(repository.getHeap(),
          data[KEY_BLOB_VERSION_DATA_OFFSET],
              KMInteger.cast(data[KEY_BLOB_VERSION_DATA_OFFSET]).length());
      if (numParams == 5) {
        operation.update(repository.getHeap(),
            data[PUB_KEY],
            (short) (KMByteBlob.cast(data[PUB_KEY]).length() +
                KMByteBlob.cast(data[PUB_KEY]).headerLength()));
      }

      // KeyDerivation:
      // 1. Do HMAC Sign, Auth data.
      // 2. HMAC Sign generates an output of 32 bytes length.
      // Consume only first 16 bytes as derived key.
      // Hmac sign.
      len = operation.sign(scratchPad, (short) 0, (short) 0, scratchPad, (short) 0);
    } finally {
      if (operation != null) {
        operation.abort();
      }
    }
    if (len < 16) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = 16;
    //data[DERIVED_KEY] = KMByteBlob.instance(scratchPad, (short) 0, len);
    return len;
  }

  private static void encryptSecret(byte[] scratchPad) {
    // make nonce
    // data[NONCE] = KMByteBlob.instance(AES_GCM_NONCE_LENGTH);
    // data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    seProvider.newRandomNumber(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length());
    // derive master key - stored in derivedKey
    short deriveKeylen = deriveKey(scratchPad);
    short len =
        seProvider.aesGCMEncrypt(
            scratchPad,
            (short) 0,
            deriveKeylen,
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            scratchPad,
            (short) deriveKeylen,
            KMByteBlob.cast(data[NONCE]).getBuffer(),
            KMByteBlob.cast(data[NONCE]).getStartOff(),
            KMByteBlob.cast(data[NONCE]).length(),
            null,
            (short) 0,
            (short) 0,
            KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
            KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
            KMByteBlob.cast(data[AUTH_TAG]).length());

    if (len > 0 && len != KMByteBlob.cast(data[SECRET]).length()) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Update the derive key.
    Util.arrayCopyNonAtomic(scratchPad, deriveKeylen,
        repository.getHeap(),
        (short) (data[SECRET] + KMByteBlob.cast(data[SECRET]).headerLength()),
        len);
    //data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
  }

  public static short readROT(byte[] scratchPad, short version) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    short len = kmDataStore.getBootKey(scratchPad, (short) 0);
    // As per IKeyMintDevice.aidl specification The root of trust
    // consists of verifyBootKey, boot state and device locked.
    if (version <= KEYBLOB_VERSION_1) {
      // To parse old keyblobs verified boot hash is included in
      // the root of trust.
      len += kmDataStore.getVerifiedBootHash(scratchPad, (short) len);
    }
    short bootState = kmDataStore.getBootState();
    len = Util.setShort(scratchPad, len, bootState);
    if (kmDataStore.isDeviceBootLocked()) {
      scratchPad[len] = (byte) 1;
    } else {
      scratchPad[len] = (byte) 0;
    }
    len++;
    return len;
    //return KMByteBlob.instance(scratchPad, (short) 0, len);
  }
  //
  // private static void makeAuthData(short version, byte[] scratchPad) {
  //   // For KeyBlob V2: Auth Data includes HW_PARAMETERS, HIDDEN_PARAMETERS, CUSTOM_TAGS, VERSION and
  //   // PUB_KEY.
  //   // For KeyBlob V1: Auth Data includes HW_PARAMETERS, HIDDEN_PARAMETERS, VERSION and PUB_KEY.
  //   // For KeyBlob V0: Auth Data includes HW_PARAMETERS, HIDDEN_PARAMETERS and PUB_KEY.
  //   // VERSION is included only for KeyBlobs having version >= 1.
  //   // PUB_KEY is included for only ASYMMETRIC KeyBlobs.
  //   short index = 0;
  //   short numParams = 0;
  //   Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 10, (byte) 0);
  //   byte keyType = getKeyType(data[SB_PARAMETERS]);
  //   // Copy the relevant parameters in the scratchPad in the order
  //   // 1. HW_PARAMETERS
  //   // 2. HIDDEN_PARAMETERS
  //   // 3. VERSION ( Only Version >= 1)
  //   // 4. PUB_KEY ( Only for Asymmetric Keys)
  //   switch (version) {
  //     case (short) 0:
  //       numParams = 2;
  //       Util.setShort(scratchPad, (short) 0, KMKeyParameters.cast(data[HW_PARAMETERS]).getVals());
  //       Util.setShort(
  //           scratchPad, (short) 2, KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals());
  //       // For Asymmetric Keys include the PUB_KEY.
  //       if (keyType == ASYM_KEY_TYPE) {
  //         numParams = 3;
  //         Util.setShort(scratchPad, (short) 4, data[PUB_KEY]);
  //       }
  //       break;
  //     case (short) 1:
  //       numParams = 3;
  //       Util.setShort(scratchPad, (short) 0, KMKeyParameters.cast(data[HW_PARAMETERS]).getVals());
  //       Util.setShort(
  //           scratchPad, (short) 2, KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals());
  //       Util.setShort(scratchPad, (short) 4, data[KEY_BLOB_VERSION_DATA_OFFSET]);
  //       // For Asymmetric Keys include the PUB_KEY.
  //       if (keyType == ASYM_KEY_TYPE) {
  //         numParams = 4;
  //         Util.setShort(scratchPad, (short) 6, data[PUB_KEY]);
  //       }
  //       break;
  //     case (short) 2:
  //       numParams = 4;
  //       Util.setShort(scratchPad, (short) 0, KMKeyParameters.cast(data[HW_PARAMETERS]).getVals());
  //       Util.setShort(
  //           scratchPad, (short) 2, KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals());
  //       Util.setShort(scratchPad, (short) 4, KMKeyParameters.cast(data[CUSTOM_TAGS]).getVals());
  //       Util.setShort(scratchPad, (short) 6, data[KEY_BLOB_VERSION_DATA_OFFSET]);
  //       // For Asymmetric Keys include the PUB_KEY.
  //       if (keyType == ASYM_KEY_TYPE) {
  //         numParams = 5;
  //         Util.setShort(scratchPad, (short) 8, data[PUB_KEY]);
  //       }
  //       break;
  //     default:
  //       KMException.throwIt(KMError.INVALID_KEY_BLOB);
  //   }
  //   // SB + TEE
  //   short hwParamsSize = (short) (KMMap.cast(data[SB_PARAMETERS]).length() +
  //       KMMap.cast(data[TEE_PARAMETERS]).length());
  //   short len = KMMap.instance(hwParamsSize, scratchPad, (short) 0);
  //   seProvider.messageDigest256(scratchPad, (short) 0, len);
  //   // SB
  //   operation.update(repository.getHeap(),
  //       (short) (data[SB_PARAMETERS] + KMMap.cast(data[SB_PARAMETERS]).headerLength()),
  //       KMMap.cast(data[SB_PARAMETERS]).contentLength());
  //   // TEE
  //   operation.update(repository.getHeap(),
  //       (short) (data[TEE_PARAMETERS] + KMMap.cast(data[TEE_PARAMETERS]).headerLength()),
  //       KMMap.cast(data[TEE_PARAMETERS]).contentLength());
  //   short prevReclaimIndex = repository.getHeapReclaimIndex();
  //   short authIndex = repository.allocReclaimableMemory(MAX_AUTH_DATA_SIZE);
  //   index = 0;
  //   short len = 0;
  //   Util.arrayFillNonAtomic(repository.getHeap(), authIndex, MAX_AUTH_DATA_SIZE, (byte) 0);
  //   while (index < numParams) {
  //     short tag = Util.getShort(scratchPad, (short) (index * 2));
  //     len = encoder.encode(tag, repository.getHeap(), (short) (authIndex + 32), prevReclaimIndex);
  //     Util.arrayCopyNonAtomic(
  //         repository.getHeap(),
  //         authIndex,
  //         repository.getHeap(),
  //         (short) (authIndex + len + 32),
  //         (short) 32);
  //     len =
  //         seProvider.messageDigest256(
  //             repository.getHeap(),
  //             (short) (authIndex + 32),
  //             (short) (len + 32),
  //             repository.getHeap(),
  //             authIndex);
  //     if (len != 32) {
  //       KMException.throwIt(KMError.UNKNOWN_ERROR);
  //     }
  //     index++;
  //   }
  //   short authDataIndex = repository.alloc(len);
  //   Util.arrayCopyNonAtomic(
  //       repository.getHeap(), authIndex, repository.getHeap(), authDataIndex, len);
  //   repository.reclaimMemory(MAX_AUTH_DATA_SIZE);
  //   data[AUTH_DATA] = authDataIndex;
  //   data[AUTH_DATA_LENGTH] = len;
  // }

  private static void createEncryptedKeyBlob(byte[] scratchPad) {
    // At this point the heap buffer contains below blocks
    /*
      KEY_PARAMETERS
      PUB_KEY
      PRIV_KEY     --> HEAP_IDX
      ..
      ..
      KEY_CHARS    --> RECLAIM_IDX
      CERT
     */

    data[KEY_BLOB] = createKeyBlobInstance(ASYM_KEY_TYPE);
    data[KEY_BLOB_VERSION_DATA_OFFSET] = KMInteger.uint_16(KEYBLOB_CURRENT_VERSION);
    /*
      Now the heap buffer contains below blocks:

      KEY_PARAMETERS
      PUB_KEY
      PRIV_KEY
      KEYBLOB_HEADER
      KEYBLOB_VERSION  --> HEAP_IDX
      ..
      ..
      KEY_CHARS        --> RECLAIM_IDX
      CERT
     */

    // Create the elements in the order to make the move easier.
    // Create CUSTOM_TAGS and move to the end of the heap.
    data[CUSTOM_TAGS] = KMKeyParameters.makeCustomTags(data[SB_PARAMETERS], scratchPad);
    short totalLength =
        (short) (KMMap.cast(data[CUSTOM_TAGS]).headerLength() +
            KMMap.cast(data[CUSTOM_TAGS]).contentLength());
    data[CUSTOM_TAGS] =
        repository.moveTowardsReclaimIndex(totalLength, scratchPad, (short) 0);

    // AUTH_TAG
    data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    totalLength =
        (short) (KMByteBlob.cast(data[AUTH_TAG]).headerLength() +
            KMByteBlob.cast(data[AUTH_TAG]).length());
    data[AUTH_TAG] =
        repository.moveTowardsReclaimIndex(totalLength, scratchPad, (short) 0);

    // NONCE
    data[NONCE] = KMByteBlob.instance(AES_GCM_NONCE_LENGTH);
    totalLength =
        (short) (KMByteBlob.cast(data[NONCE]).headerLength() +
            KMByteBlob.cast(data[NONCE]).length());
    data[NONCE] =
        repository.moveTowardsReclaimIndex(totalLength, scratchPad, (short) 0);

    /*
      KEY_PARAMETERS
      PUB_KEY
      PRIV_KEY
      KEYBLOB_HEADER
      KEYBLOB_VERSION  --> HEAP_IDX
      ..
      ..
      NONCE            --> RECLAIM_IDX
      AUTH_TAG
      CUSTOM_TAGS
      KEY_CHARS
      CERT
     */
    // encrypt the secret and cryptographically attach that to authorization data
    encryptSecret(scratchPad);
    // Move the SECRET after the VERSION
    // After the move the data[SECRET] becomes data[KEY_BLOB] and data[KEY_BLOB_VERSION_DATA_OFFSET]
    // will be followed by KEY_BLOB.
    data[KEY_BLOB] = data[SECRET];
    data[KEY_BLOB_VERSION_DATA_OFFSET] =
        (short) (data[KEY_BLOB] + KMArray.cast(data[KEY_BLOB]).headerLength());
    data[SECRET] =
        repository.move(data[SECRET], (short) (KMByteBlob.cast(data[SECRET]).headerLength() +
            KMByteBlob.cast(data[SECRET]).length()), scratchPad, (short) 0);

    // Move the nonce from the end to start
    data[NONCE] =
        repository.moveTowardsHeapIndex((short) (KMByteBlob.cast(data[NONCE]).headerLength()
            + KMByteBlob.cast(data[NONCE]).length()), scratchPad, (short) 0);
    // Move the AUTH_TAG from the end to start
    data[AUTH_TAG] =
        repository.moveTowardsHeapIndex((short) (KMByteBlob.cast(data[AUTH_TAG]).headerLength()
            + KMByteBlob.cast(data[AUTH_TAG]).length()), scratchPad, (short) 0);
     /*
      KEY_PARAMETERS
      PUB_KEY
      KEYBLOB_HEADER
      KEYBLOB_VERSION
      PRIV_KEY
      NONCE
      AUTH_TAG        --> HEAP_IDX
      ..
      ..
      CUSTOM_TAGS      --> RECLAIM_IDX
      KEY_CHARS
      CERT
     */

    // Duplicate copy of keycharacteristics
    totalLength = (short) (KMArray.cast(data[KEY_CHARACTERISTICS]).headerLength() +
    KMArray.cast(data[KEY_CHARACTERISTICS]).contentLength());
    short keyCharsDup = repository.alloc((short) totalLength);
    Util.arrayCopyNonAtomic(repository.getHeap(), data[KEY_CHARACTERISTICS], repository.getHeap(),
        keyCharsDup, totalLength);

    // Move custom tags
    data[CUSTOM_TAGS] =
        repository.moveTowardsHeapIndex((short) (KMMap.cast(data[CUSTOM_TAGS]).headerLength()
            + KMMap.cast(data[CUSTOM_TAGS]).contentLength()), scratchPad, (short) 0);
    /*
      KEY_PARAMETERS
      PUB_KEY
      KEYBLOB_HEADER
      KEYBLOB_VERSION
      PRIV_KEY
      NONCE
      AUTH_TAG
      CUSTOM_TAGS
      KEY_CHARS
      CUSTOM_TAGS        --> HEAP_IDX
      ..
      ..
      KEY_CHARS      --> RECLAIM_IDX
      CERT
     */

    if (ASYM_KEY_BLOB_SIZE_V2_V3 == getKeyType(data[SB_PARAMETERS])) {
      // Move the PUB_KEY at the end heapIndex.
      data[KEY_BLOB] = data[PUB_KEY];
      data[PUB_KEY] =
          repository.move(data[PUB_KEY], (short) (KMByteBlob.cast(data[PUB_KEY]).headerLength() +
              KMByteBlob.cast(data[PUB_KEY]).length()), scratchPad, (short) 0);
      /*
      KEY_PARAMETERS
      KEYBLOB_HEADER
      KEYBLOB_VERSION
      PRIV_KEY
      NONCE
      AUTH_TAG
      CUSTOM_TAGS
      KEY_CHARS
      CUSTOM_TAGS
      PUB_KEY       --> HEAP_IDX
      ..
      ..
      KEY_CHARS      --> RECLAIM_IDX
      CERT
     */
    }

    // Move keyBlob at the end
    short totalLen = (short) (KMArray.cast(data[KEY_BLOB]).headerLength()
        + KMArray.cast(data[KEY_BLOB]).contentLength());
    data[KEY_BLOB] = repository.moveTowardsReclaimIndex(totalLength, scratchPad, (short) 0);
    /*
      KEY_PARAMETERS   --> HEAP_IDX
      ..
      ..
      KEY_BLOB         --> RECLAIM_IDX
      KEY_CHARS
      CERT
     */
  }

  @Override
  public boolean select() {
    repository.onSelect();
    return true;
  }

  /**
   * De-selects this applet.
   */
  @Override
  public void deselect() {
    repository.onDeselect();
  }


  @Override
  public void process(APDU apdu) throws ISOException {
    try {
      byte[] apduBuffer = apdu.getBuffer();
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      switch (apduBuffer[ISO7816.OFFSET_INS]) {
        case INS_GENERATE_KEY_CMD:
          processGenerateKey(apdu);
          break;
      }
    } finally {
      repository.clean();
    }
  }

  /** Receives data, which can be extended data, as requested by the command instance. */
  public static short receiveIncoming(APDU apdu, short reqExp) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    //apduStatusFlags[APDU_INCOMING_AND_RECEIVE_STATUS_INDEX] = 1;
    // TODO add logic to handle the extended length buffer. In this case the memory can be reused
    //  from extended buffer.
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = repository.alloc(bufferLength);
    short index = bufferStartOffset;
    byte[] buffer = repository.getHeap();
    while (recvLen > 0 && ((short) (index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    short ret = decoder.decode(reqExp, buffer, bufferStartOffset, bufferLength);
    // exp memory no more required. move the input buffer at 0 offset on the heap.
    Util.arrayCopyNonAtomic(buffer, bufferStartOffset, buffer, reqExp, bufferLength);
    repository.setHeapIndex(bufferLength);
    return reqExp;
  }

  private short generateKeyCmd(APDU apdu) {
    // Array of expected arguments
    short cmd = KMArray.instance((short) 4);
    KMKeyParameters.expAny(); // key params
    KMByteBlob.exp(); // attest key blob
    KMKeyParameters.expAny(); // attest key params
    KMByteBlob.exp(); // issuer
    return receiveIncoming(apdu, cmd);
  }

  private void processGenerateKey(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
    byte[] heap = KMKeymasterApplet.heap;
    short[] heapIndex = KMKeymasterApplet.heapIndex;
    short[] reclaimIndex = KMKeymasterApplet.reclaimIndex;
    short cmd = generateKeyCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_PARAMETERS] = KMArray.cast(cmd).get((short) 0);
    data[ATTEST_KEY_BLOB] = KMArray.cast(cmd).get((short) 1);
    data[ATTEST_KEY_PARAMS] = KMArray.cast(cmd).get((short) 2);
    data[ATTEST_KEY_ISSUER] = KMArray.cast(cmd).get((short) 3);
    data[CERTIFICATE] = KMType.INVALID_VALUE; // by default the cert is empty.
    // ROLLBACK_RESISTANCE not supported.
    KMTag.assertAbsence(
        data[KEY_PARAMETERS],
        KMType.BOOL_TAG,
        KMType.ROLLBACK_RESISTANCE,
        KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);

    // Algorithm must be present
    KMTag.assertPresence(
        data[KEY_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM, KMError.INVALID_ARGUMENT);

    // Check if the tags are supported.
    if (KMKeyParameters.hasUnsupportedTags(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_TAG);
    }

    // ID_IMEI should be present if ID_SECOND_IMEI is present
    short attIdTag =
        KMKeyParameters.findTag(
            KMType.BYTES_TAG, KMType.ATTESTATION_ID_SECOND_IMEI, data[KEY_PARAMETERS]);
    if (attIdTag != KMType.INVALID_VALUE) {
      KMTag.assertPresence(
          data[KEY_PARAMETERS],
          KMType.BYTES_TAG,
          KMType.ATTESTATION_ID_IMEI,
          KMError.CANNOT_ATTEST_IDS);
    }

    short attKeyPurpose =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, data[KEY_PARAMETERS]);
    // ATTEST_KEY cannot be combined with any other purpose.
    if (attKeyPurpose != KMType.INVALID_VALUE
        && KMByteBlob.cast(attKeyPurpose).contains(KMType.ATTEST_KEY)
        && KMByteBlob.cast(attKeyPurpose).length() > 1) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
    short alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, data[KEY_PARAMETERS]);
    alg = KMInteger.cast(alg).getByte();
    // Check algorithm and dispatch to appropriate handler.
    switch (alg) {
      case KMType.RSA:
        generateRSAKey(scratchPad);
        break;
      // case KMType.AES:
      //   generateAESKey(scratchPad);
      //   break;
      // case KMType.DES:
      //   generateTDESKey(scratchPad);
      //   break;
      // case KMType.HMAC:
      //   generateHmacKey(scratchPad);
      //   break;
      // case KMType.EC:
      //   generateECKeys(scratchPad);
      //   break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
    // create key blob and associated attestation.
    data[ORIGIN] = KMType.GENERATED;
    makeKeyCharacteristics(scratchPad);
    // TODO This is a temporary code to create dummy certificate.
    short ptr = repository.allocReclaimableMemory((short) 1500);
    Util.arrayFillNonAtomic(repository.getHeap(), ptr, (short) 1500, (byte)0x01);
    // construct the certificate and place the encoded data in data[CERTIFICATE]
    // KMAttestationCert cert =
    //     generateAttestation(data[ATTEST_KEY_BLOB], data[ATTEST_KEY_PARAMS], scratchPad);
    // Move keycharacteristics at the end.
    short keyCharsLen = (short) (KMArray.cast(data[KEY_CHARACTERISTICS]).headerLength() +
        KMArray.cast(data[KEY_CHARACTERISTICS]).contentLength());
    short keyCharsOffset = data[KEY_CHARACTERISTICS];
    data[KEY_CHARACTERISTICS] = repository.moveTowardsReclaimIndex(keyCharsLen, scratchPad, (short) 0);
    data[SB_PARAMETERS] = KMArray.cast(data[KEY_CHARACTERISTICS]).get((short) 0);
    data[TEE_PARAMETERS] = KMArray.cast(data[KEY_CHARACTERISTICS]).get((short) 1);
    data[SW_PARAMETERS] = KMArray.cast(data[KEY_CHARACTERISTICS]).get((short) 2);

    createEncryptedKeyBlob(scratchPad);
    sendOutgoing(apdu, data[CERTIFICATE], data[KEY_BLOB], data[KEY_CHARACTERISTICS]);
  }

  public void sendOutgoing(
      APDU apdu, /*KMAttestationCert cert,*/ short certStart, short keyblob, short keyChars) {
    // This is the special case where the output is encoded manually without using
    // the encoder algorithm. Encoder creates a duplicate copy for each KMType Object.
    // The output of the generateKey, importKey and importWrappedKey commands are huge so
    // by manually encoding we can avoid duplicate copies.
    // The output data is directly written to the end of heap in the below order
    // output = [
    //     errorCode  : uint // ErrorCode
    //     keyBlob    : bstr // KeyBlob.
    //     keyChars
    //     certifcate
    // ]
    // certificate = [
    //     x509_cert : bstr // X509 certificate
    // ]
    // keyChars = {  // Map
    // }
    // Enable this when doing heap profiling.

    // TODO
    // Send data
    // apdu.setOutgoing();
    // apdu.setOutgoingLength(bufferLength);
    // apdu.sendBytesLong(buffer, bufferStartOffset, bufferLength);
  }

  private static void validateRSAKey(byte[] scratchPad) {
    // Read key size
    if (!KMValidations.isValidKeyParam(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    if (!KMValidations.isValidKeyParam(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
        data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  // Generate key handlers
  private static void generateRSAKey(byte[] scratchPad) {
    // Validate RSA Key
    validateRSAKey(scratchPad);
    // TODO is lengths[] required ?
    // Now generate 2048 bit RSA keypair for the given exponent
    short[] lengths = tmpVariables;
    data[PUB_KEY] = KMByteBlob.instance((short) 256);
    data[SECRET] = KMByteBlob.instance((short) 256);
    seProvider.createAsymmetricKey(
        KMType.RSA,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length(),
        lengths);

    //data[KEY_BLOB] = createKeyBlobInstance(ASYM_KEY_TYPE);
    //KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static short createKeyBlobInstance(byte keyType) {
    short arrayLen = 0;
    switch (keyType) {
      case ASYM_KEY_TYPE:
        arrayLen = ASYM_KEY_BLOB_SIZE_V2_V3;
        break;
      case SYM_KEY_TYPE:
        arrayLen = SYM_KEY_BLOB_SIZE_V2_V3;
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    return KMArray.instance(arrayLen);
  }
}
