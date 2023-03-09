package com.android.cborparser;


public class KMValidations {

  // isValidTag enumeration keys and values.
  public static boolean validateEnum(short key, byte value) {
    switch (key) {
      case KMType.HARDWARE_TYPE:
        return validateHardwareType(value);
      case KMType.KEY_FORMAT: {
        switch (value) {
          case KMType.X509:
          case KMType.RAW:
          case KMType.PKCS8:
            return true;
        }
      }
      break;
      case KMType.USER_AUTH_TYPE:
        return validateUserAuthType(value);
      case KMType.PURPOSE:
        return validatePurpose(value);
    }
    return false;
  }

  public static boolean validateHardwareType(byte value) {
    switch (value) {
      case KMType.SOFTWARE:
      case KMType.TRUSTED_ENVIRONMENT:
      case KMType.STRONGBOX:
        return true;
    }
    return false;
  }

  public static boolean validateUserAuthType(byte value) {
    switch (value) {
      case KMType.USER_AUTH_NONE:
      case KMType.PASSWORD:
      case KMType.FINGERPRINT:
      case KMType.BOTH:
      case KMType.ANY:
        return true;
      default:
        return false;
    }
  }

  public static boolean validatePurpose(byte value) {
    switch (value) {
      case KMType.ENCRYPT:
      case KMType.DECRYPT:
      case KMType.SIGN:
      case KMType.VERIFY:
      case KMType.WRAP_KEY:
      case KMType.ATTEST_KEY:
      case KMType.AGREE_KEY:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateBlockMode(byte value) {
    switch (value) {
      case KMType.ECB:
      case KMType.CBC:
      case KMType.CTR:
      case KMType.GCM:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateDigest(byte value) {
    switch (value) {
      case KMType.DIGEST_NONE:
      case KMType.MD5:
      case KMType.SHA1:
      case KMType.SHA2_224:
      case KMType.SHA2_256:
      case KMType.SHA2_384:
      case KMType.SHA2_512:
        return true;
      default:
        return false;
    }
  }

  public static boolean validatePadding(byte value) {
    switch (value) {
      case KMType.PADDING_NONE:
      case KMType.RSA_OAEP:
      case KMType.RSA_PSS:
      case KMType.RSA_PKCS1_1_5_ENCRYPT:
      case KMType.RSA_PKCS1_1_5_SIGN:
      case KMType.PKCS7:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateEnumArrayTag(short keyPtr, short valuePtr) {
    short length = KMByteBlob.cast(valuePtr).length();
    short key = KMInteger.cast(keyPtr).getShort();
    switch (key) {
      case KMType.PURPOSE:
        for (short i = 0; i < length; i++) {
          if (!validatePurpose(KMByteBlob.cast(valuePtr).get(i))) {
            return false;
          }
        }
        return true;
      case KMType.BLOCK_MODE:
        for (short i = 0; i < length; i++) {
          if (!validateBlockMode(KMByteBlob.cast(valuePtr).get(i))) {
            return false;
          }
        }
        return true;
      case KMType.DIGEST:
      case KMType.RSA_OAEP_MGF_DIGEST:
        for (short i = 0; i < length; i++) {
          if (!validateDigest(KMByteBlob.cast(valuePtr).get(i))) {
            return false;
          }
        }
        return true;
      case KMType.PADDING:
        for (short i = 0; i < length; i++) {
          if (!validatePadding(KMByteBlob.cast(valuePtr).get(i))) {
            return false;
          }
        }
        return true;

    }
    return false;
  }

  public static boolean validateEnumTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    byte value = KMInteger.cast(valuePtr).getByte();
    switch (key) {
      case KMType.ALGORITHM: {
        switch (value) {
          case KMType.RSA:
          case KMType.DES:
          case KMType.EC:
          case KMType.AES:
          case KMType.HMAC:
            return true;
        }
      }
      break;
      case KMType.ECCURVE: {
        switch (value) {
          case KMType.P_224:
          case KMType.P_256:
          case KMType.P_384:
          case KMType.P_521:
          case KMType.CURVE_25519:
            return true;
        }
      }
      break;
      case KMType.BLOB_USAGE_REQ: {
        switch (value) {
          case KMType.STANDALONE:
          case KMType.REQUIRES_FILE_SYSTEM:
            return true;
        }
      }
      break;
      case KMType.USER_AUTH_TYPE:
        return validateUserAuthType(value);
      case KMType.ORIGIN: {
        switch (value) {
          case KMType.GENERATED:
          case KMType.DERIVED:
          case KMType.IMPORTED:
          case KMType.UNKNOWN:
          case KMType.SECURELY_IMPORTED:
            return true;
        }
      }
      break;
      case KMType.HARDWARE_TYPE:
        return validateHardwareType(value);
    }
    return false;
  }

  public static boolean validateUIntTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    byte value = KMInteger.cast(valuePtr).getByte();
    switch (key) {
      case KMType.KEYSIZE:
      case KMType.MIN_MAC_LENGTH:
      case KMType.MIN_SEC_BETWEEN_OPS:
      case KMType.MAX_USES_PER_BOOT:
      case KMType.USERID:
      case KMType.AUTH_TIMEOUT:
      case KMType.OS_VERSION:
      case KMType.OS_PATCH_LEVEL:
      case KMType.VENDOR_PATCH_LEVEL:
      case KMType.BOOT_PATCH_LEVEL:
      case KMType.MAC_LENGTH:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateULongTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    byte value = KMInteger.cast(valuePtr).getByte();
    switch (key) {
      case KMType.RSA_PUBLIC_EXPONENT:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateULongArrayTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    byte value = KMInteger.cast(valuePtr).getByte();
    switch (key) {
      case KMType.USER_SECURE_ID:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateBoolTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    byte value = KMInteger.cast(valuePtr).getByte();
    switch (key) {
      case KMType.CALLER_NONCE:
      case KMType.INCLUDE_UNIQUE_ID:
      case KMType.BOOTLOADER_ONLY:
      case KMType.ROLLBACK_RESISTANCE:
      case KMType.NO_AUTH_REQUIRED:
      case KMType.ALLOW_WHILE_ON_BODY:
      case KMType.TRUSTED_USER_PRESENCE_REQUIRED:
      case KMType.TRUSTED_CONFIRMATION_REQUIRED:
      case KMType.UNLOCKED_DEVICE_REQUIRED:
      case KMType.RESET_SINCE_ID_ROTATION:
      case KMType.EARLY_BOOT_ONLY:
      case KMType.DEVICE_UNIQUE_ATTESTATION:
        if (value != 0x01) {
          return false;
        }
        return true;
    }
    return false;
  }

  public static boolean validateBignumTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    short valueLen = KMByteBlob.cast(valuePtr).length();
    switch (key) {
      case KMType.CERTIFICATE_SERIAL_NUM:
        if (valueLen > KMType.MAX_CERTIFICATE_SERIAL_SIZE) {
          return false;
        }
        break;
      default:
        return false;
    }
    return true;
  }

  public static boolean validateDateTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    byte value = KMInteger.cast(valuePtr).getByte();
    switch (key) {
      case KMType.ACTIVE_DATETIME:
      case KMType.ORIGINATION_EXPIRE_DATETIME:
      case KMType.USAGE_EXPIRE_DATETIME:
      case KMType.CREATION_DATETIME:
      case KMType.CERTIFICATE_NOT_BEFORE:
      case KMType.CERTIFICATE_NOT_AFTER:
      case KMType.USAGE_COUNT_LIMIT:
        // custom tag
      case KMType.AUTH_TIMEOUT_MILLIS:
        return true;
      default:
        return false;
    }
  }

  public static boolean validateBytesTag(short keyPtr, short valuePtr) {
    short key = KMInteger.cast(keyPtr).getShort();
    short valueLen = KMByteBlob.cast(valuePtr).length();
    switch (key) {
      case KMType.ATTESTATION_APPLICATION_ID:
        if (valueLen > KMType.MAX_ATTESTATION_APP_ID_SIZE) {
          return false;
        }
        break;
      case KMType.CERTIFICATE_SUBJECT_NAME: {
        // TODO
        // if (valueLen > KMConfigurations.MAX_SUBJECT_DER_LEN) {
        //   return false;
        // }
        // KMAsn1Parser asn1Decoder = KMAsn1Parser.instance();
        // asn1Decoder.validateDerSubject(byteBlob);
      }
      break;
      case KMType.APPLICATION_ID:
      case KMType.APPLICATION_DATA:
        if (valueLen > KMType.MAX_APP_ID_APP_DATA_SIZE) {
          return false;
        }
        break;
      case KMType.ATTESTATION_CHALLENGE:
        if (valueLen > KMType.MAX_ATTESTATION_CHALLENGE_SIZE) {
          return false;
        }
        break;
      case KMType.ATTESTATION_ID_BRAND:
      case KMType.ATTESTATION_ID_DEVICE:
      case KMType.ATTESTATION_ID_PRODUCT:
      case KMType.ATTESTATION_ID_SERIAL:
      case KMType.ATTESTATION_ID_IMEI:
      case KMType.ATTESTATION_ID_MEID:
      case KMType.ATTESTATION_ID_MANUFACTURER:
      case KMType.ATTESTATION_ID_MODEL:
        // TODO
        // if (valueLen > KMConfigurations.MAX_ATTESTATION_IDS_SIZE) {
        //   return false;
        // }
        break;
      case KMType.ROOT_OF_TRUST:
      case KMType.NONCE:
        break;
      default:
        return false;
    }
    return true;
  }

}
