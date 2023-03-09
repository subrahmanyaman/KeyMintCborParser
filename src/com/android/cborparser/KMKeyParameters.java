/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.cborparser;

import static com.android.cborparser.KMType.heap;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMKeyParameters represents KeyParameters structure from android keymaster hal specifications. It
 * corresponds to CBOR map type. struct{byte KEY_PARAM_TYPE; short length=2; short arrayPtr} where
 * arrayPtr is a pointer to array with any KMTag subtype instances.
 */
public class KMKeyParameters {

  private static final short[] customTags = {
    KMType.ULONG_TAG, KMType.AUTH_TIMEOUT_MILLIS,
  };
  private static final short[] tagArr = {
    // Unsupported tags.
    KMType.BOOL_TAG, KMType.TRUSTED_USER_PRESENCE_REQUIRED,
    KMType.UINT_TAG, KMType.MIN_SEC_BETWEEN_OPS
  };
  private static final short[] hwEnforcedTagArr = {
    // HW Enforced
    KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,
    KMType.ENUM_TAG, KMType.ALGORITHM,
    KMType.UINT_TAG, KMType.KEYSIZE,
    KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT,
    KMType.ENUM_TAG, KMType.BLOB_USAGE_REQ,
    KMType.ENUM_ARRAY_TAG, KMType.DIGEST,
    KMType.ENUM_ARRAY_TAG, KMType.PADDING,
    KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE,
    KMType.ENUM_ARRAY_TAG, KMType.RSA_OAEP_MGF_DIGEST,
    KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED,
    KMType.BOOL_TAG, KMType.CALLER_NONCE,
    KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
    KMType.ENUM_TAG, KMType.ECCURVE,
    KMType.BOOL_TAG, KMType.INCLUDE_UNIQUE_ID,
    KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE,
    KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY,
    KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY,
    KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT,
  };
  private static final short[] swEnforcedTagsArr = {
    KMType.DATE_TAG, KMType.ACTIVE_DATETIME,
    KMType.DATE_TAG, KMType.ORIGINATION_EXPIRE_DATETIME,
    KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME,
    KMType.UINT_TAG, KMType.USERID,
    KMType.DATE_TAG, KMType.CREATION_DATETIME,
    KMType.UINT_TAG, KMType.USAGE_COUNT_LIMIT,
    KMType.BOOL_TAG, KMType.ALLOW_WHILE_ON_BODY,
    KMType.UINT_TAG, KMType.MAX_BOOT_LEVEL,
  };
  private static final short[] teeEnforcedTagsArr = {
    KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID,
    KMType.UINT_TAG, KMType.AUTH_TIMEOUT,
    KMType.ENUM_TAG, KMType.USER_AUTH_TYPE,
    KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED,
    KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED,
  };
  private static final short[] invalidTagsArr = {
    KMType.BYTES_TAG, KMType.NONCE,
    KMType.BYTES_TAG, KMType.ASSOCIATED_DATA,
    KMType.BYTES_TAG, KMType.UNIQUE_ID,
    KMType.UINT_TAG, KMType.MAC_LENGTH,
  };

  private static short exp(short rule) {
    short ptr = KMMap.instance((short) 11);
    KMInteger.uint_16(KMType.RULE);
    KMInteger.exp(rule);
    KMInteger.exp(KMType.UINT_TAG); // Key
    KMInteger.exp(); // Value
    KMInteger.exp(KMType.UINT_ARRAY_TAG);
    KMArray.exp(); // Value
    KMInteger.exp(KMType.ULONG_TAG);
    KMInteger.exp(); // Value
    KMInteger.exp(KMType.DATE_TAG);
    KMInteger.exp(); // Value
    KMInteger.exp(KMType.ULONG_ARRAY_TAG);
    KMArray.exp(); // Value
    KMInteger.exp(KMType.ENUM_TAG);
    KMInteger.exp(); // Value
    KMInteger.exp(KMType.ENUM_ARRAY_TAG);
    KMByteBlob.exp(); // Value
    KMInteger.exp(KMType.BYTES_TAG);
    KMByteBlob.exp(); // Value
    KMInteger.exp(KMType.BOOL_TAG);
    KMInteger.exp(); // Value
    KMInteger.exp(KMType.BIGNUM_TAG);
    KMByteBlob.exp(); // Value
    return ptr;
  }

  public static short exp() {
    return exp(KMType.FAIL_ON_INVALID_TAGS);
  }

  public static short expAny() {
    return exp(KMType.IGNORE_INVALID_TAGS);
  }

  public static short findTag(short tagType, short tagKey, short keyParam) {
    short length = KMMap.cast(keyParam).length();
    short keyPtr;
    short valuePtr = KMTag.INVALID_VALUE;
    for (short i = 0; i < length; i++) {
      keyPtr = KMMap.cast(keyParam).getKey(i);
      if ((tagKey == KMInteger.cast(keyPtr).getShort()) &&
          (tagType == KMInteger.cast(keyPtr).getSignificantShort())) {
        valuePtr = KMMap.cast(keyParam).getKeyValue(i);
        break;
      }
    }
    return valuePtr;
  }

  public static boolean hasUnsupportedTags(short keyParamsPtr) {
    byte index = 0;
    short tagInd;
    short tagPtr;
    short tagKey;
    short tagType;
    short len = KMMap.cast(keyParamsPtr).length();
    while (index < len) {
      tagInd = 0;
      tagKey = KMMap.cast(keyParamsPtr).getKey(index);
      tagKey = KMInteger.cast(tagKey).getShort();
      tagType = KMInteger.cast(tagKey).getSignificantShort();
      while (tagInd < (short) tagArr.length) {
        if ((tagArr[tagInd] == tagType) && (tagArr[(short) (tagInd + 1)] == tagKey)) {
          return true;
        }
        tagInd += 2;
      }
      index++;
    }
    return false;
  }

  // KDF, ECIES_SINGLE_HASH_MODE missing from types.hal
  public static short makeSbEnforced(
      short keyParamsPtr,
      byte origin,
      short osVersionObjPtr,
      short osPatchObjPtr,
      short vendorPatchObjPtr,
      short bootPatchObjPtr,
      byte[] scratchPad) {
    short len = makeKeyParameters(hwEnforcedTagArr, keyParamsPtr, scratchPad);
    short mapPtr = KMMap.instance((short) (len + 5));
    copyKeyParamters(scratchPad, mapPtr, len);
    // Add Origin
    KMInteger.instance(KMType.ENUM_TAG, KMType.ORIGIN); // Key
    KMInteger.uint_8(origin); // Value
    // TODO Avoid copy and try move.
    // Add OS_VERSION
    KMInteger.instance(KMType.UINT_TAG, KMType.OS_VERSION); // Key
    KMInteger.instance(KMByteBlob.cast(osVersionObjPtr).getBuffer(),
        KMByteBlob.cast(osVersionObjPtr).getStartOff(),
        KMByteBlob.cast(osVersionObjPtr).length()); // Value
    // Add OS_PATCH_LEVEL
    KMInteger.instance(KMType.UINT_TAG, KMType.OS_PATCH_LEVEL); // Key
    KMInteger.instance(KMByteBlob.cast(osPatchObjPtr).getBuffer(),
        KMByteBlob.cast(osPatchObjPtr).getStartOff(),
        KMByteBlob.cast(osPatchObjPtr).length()); // Value
    // Add VENDOR_PATCH_LEVEL
    KMInteger.instance(KMType.UINT_TAG, KMType.VENDOR_PATCH_LEVEL); // Key
    KMInteger.instance(KMByteBlob.cast(vendorPatchObjPtr).getBuffer(),
        KMByteBlob.cast(vendorPatchObjPtr).getStartOff(),
        KMByteBlob.cast(vendorPatchObjPtr).length()); // Value
    // Add BOOT_PATCH_LEVEL
    KMInteger.instance(KMType.UINT_TAG, KMType.BOOT_PATCH_LEVEL); // Key
    KMInteger.instance(KMByteBlob.cast(bootPatchObjPtr).getBuffer(),
        KMByteBlob.cast(bootPatchObjPtr).getStartOff(),
        KMByteBlob.cast(bootPatchObjPtr).length()); // Value
    return mapPtr;
  }

  public static short makeHwEnforced(short sb, short tee) {
    return (short) 0;
    // TODO:
    // short sbLength = KMMap.cast(sb).length();
    // short teeLength = KMMap.cast(tee).length();
    // short hwEnf = KMMap.instance((short) (sbLength + teeLength));
    // // KeyParameters length won't be greater than 255.
    // if (sbLength > 255 || teeLength > 255) {
    //   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    // }
    // short sbContentStart =  (short) (sb + KMMap.cast(sb).headerLength());
    // short sbContentLength =  KMMap.cast(sb).contentLength();
    // short hwEnfContentStart = (short) (hwEnf + KMMap.cast(hwEnf).headerLength());
    // Util.arrayCopyNonAtomic(heap, sbContentStart, heap, hwEnfContentStart, sbContentLength);

    // Below is the Old Code.
    // sb = KMKeyParameters.cast(sb).getVals();
    // tee = KMKeyParameters.cast(tee).getVals();
    // len = KMArray.cast(sb).length();
    // short src = 0;
    // short dest = 0;
    // short val = 0;
    // while (src < len) {
    //   val = KMArray.cast(sb).get(src);
    //   KMArray.cast(hwEnf).add(dest, val);
    //   src++;
    //   dest++;
    // }
    // src = 0;
    // len = KMArray.cast(tee).length();
    // while (src < len) {
    //   val = KMArray.cast(tee).get(src);
    //   KMArray.cast(hwEnf).add(dest, val);
    //   src++;
    //   dest++;
    // }
    // return KMKeyParameters.instance(hwEnf);
  }

  public static short makeKeyParameters(short[] enforcedList, short keyParamsPtr, byte[] scratchPad) {
    byte index = 0;
    short tagInd;
    short arrInd = 0;
    short tagPtr;
    short tagKey;
    short tagType;
    short len = KMMap.cast(keyParamsPtr).length();
    short tagValue;
    while (index < len) {
      tagInd = 0;
      tagPtr = KMMap.cast(keyParamsPtr).getKey(index);
      tagValue = KMMap.cast(keyParamsPtr).getKeyValue(index);
      tagKey = KMInteger.cast(tagPtr).getShort();
      tagType = KMInteger.cast(tagPtr).getSignificantShort();
      if (!isValidTag(tagType, tagKey)) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      while (tagInd < (short) enforcedList.length) {
        if ((enforcedList[tagInd] == tagType)
            && (enforcedList[(short) (tagInd + 1)] == tagKey)) {
          Util.setShort(scratchPad, arrInd, tagPtr);
          arrInd += 2;
          Util.setShort(scratchPad, arrInd, tagValue);
          arrInd += 2;
          break;
        }
        tagInd += 2;
      }
      index++;
    }
    return len;
  }

  // ALL_USERS, EXPORTABLE missing from types.hal
  public static short makeKeystoreEnforced(short keyParamsPtr, byte[] scratchPad) {
    short len = makeKeyParameters(swEnforcedTagsArr, keyParamsPtr, scratchPad);
    short mapPtr = KMMap.instance(len);
    copyKeyParamters(scratchPad, mapPtr, len);
    return mapPtr;
  }

  public static short makeTeeEnforced(short keyParamsPtr, byte[] scratchPad) {
    short len = makeKeyParameters(teeEnforcedTagsArr, keyParamsPtr, scratchPad);
    short mapPtr = KMMap.instance(len);
    copyKeyParamters(scratchPad, mapPtr, len);
    return mapPtr;
  }

  public static short makeHidden(short keyParamsPtr, short rootOfTrustBlob, byte[] scratchPad) {
    short appId = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, keyParamsPtr);
    if (appId != KMTag.INVALID_VALUE) {
      if (KMByteBlob.cast(appId).length() == 0) {
        appId = KMTag.INVALID_VALUE;
      }
    }
    short appData =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, keyParamsPtr);
    if (appData != KMTag.INVALID_VALUE) {
      if (KMByteBlob.cast(appData).length() == 0) {
        appData = KMTag.INVALID_VALUE;
      }
    }
    return makeHidden(appId, appData, rootOfTrustBlob, scratchPad);
  }

  public static short makeHidden(
      short appIdBlob, short appDataBlob, short rootOfTrustBlob, byte[] scratchPad) {
    // Order in which the hidden array is created should not change.
    short index = 0;
    KMByteBlob.cast(rootOfTrustBlob);
    Util.setShort(scratchPad, index, rootOfTrustBlob);
    index += 2;
    if (appIdBlob != KMTag.INVALID_VALUE) {
      KMByteBlob.cast(appIdBlob);
      Util.setShort(scratchPad, index, appIdBlob);
      index += 2;
    }
    if (appDataBlob != KMTag.INVALID_VALUE) {
      KMByteBlob.cast(appDataBlob);
      Util.setShort(scratchPad, index, appDataBlob);
      index += 2;
    }
    short map = KMMap.instance((short) (index / 2));
    copyKeyParamters(scratchPad, map, (short) (index / 2));
    return map;
  }

  public static boolean isValidTag(short tagType, short tagKey) {
    short index = 0;
    if (tagKey == KMType.INVALID_TAG) {
      return false;
    }
    while (index < invalidTagsArr.length) {
      if ((tagType == invalidTagsArr[index]) && (tagKey == invalidTagsArr[(short) (index + 1)])) {
        return false;
      }
      index += 2;
    }
    return true;
  }

  private static short getContentLength(short ptr) {
    short majorType = KMType.getMajorType(ptr);
    switch (majorType) {
      case KMType.MAJOR_TYPE_INT:
        return KMInteger.cast(ptr).length();
      case KMType.MAJOR_TYPE_ARRAY:
        return KMArray.cast(ptr).contentLength();
      case KMType.MAJOR_TYPE_BYTE_BLOB:
        return (short) (KMByteBlob.cast(ptr).length() +
            KMByteBlob.cast(ptr).headerLength());
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return (short) 0;
  }

  public static void copyKeyParamters(byte[] ptrArr, short mapPtr, short len) {
    // KeyParameters length won't be greater than 255.
    if (len > 255) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short destPtr = (short) (mapPtr + KMMap.cast(mapPtr).headerLength());
    short index = 0;
    short ptr = 0;
    short contentLength;
    while (index < len) {
      contentLength = getContentLength(Util.getShort(ptrArr, ptr));
      Util.arrayCopyNonAtomic(heap, Util.getShort(ptrArr, ptr), heap, destPtr, contentLength);
      ptr += 2;
      destPtr += contentLength;
      contentLength = getContentLength(Util.getShort(ptrArr, ptr));
      Util.arrayCopyNonAtomic(heap, Util.getShort(ptrArr, ptr), heap, destPtr, contentLength);
      index++;
      ptr += 2;
      destPtr += contentLength;
    }
  }

  public static short makeCustomTags(short keyParams, byte[] scratchPad) {
    short index = 0;
    short tagPtr;
    short tagKey;
    short offset = 0;
    short len = (short) customTags.length;
    short map = KMMap.instance((short) (len / 2));
    short tagType;
    while (index < len) {
      tagType = customTags[(short) (index + 1)];
      switch (tagType) {
        case KMType.AUTH_TIMEOUT_MILLIS:
          short authTimeOutTag =
              KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, keyParams);
          if (authTimeOutTag != KMType.INVALID_VALUE) {
            KMInteger.instance(KMType.ULONG_TAG, KMType.AUTH_TIMEOUT_MILLIS); // Key
            tagPtr = createAuthTimeOutMillisTag(authTimeOutTag, scratchPad, offset); // Value
          }
          break;
        default:
          break;
      }
      index += 2;
    }
    // short map = KMMap.instance((short) (offset / 2));
    // copyKeyParamters(scratchPad, map, (short) (offset / 2));
    return map;
  }

  public static short createAuthTimeOutMillisTag(
      short authTime, byte[] scratchPad, short offset) {
    //short authTime = KMInteger.cast(authTimeOutTag).getValue();
    Util.arrayFillNonAtomic(scratchPad, offset, (short) 40, (byte) 0);
    Util.arrayCopyNonAtomic(
        KMInteger.cast(authTime).getBuffer(),
        KMInteger.cast(authTime).getStartOff(),
        scratchPad,
        (short) (offset + 8 - KMInteger.cast(authTime).length()),
        KMInteger.cast(authTime).length());
    // TODO KMUtils.convertToMilliSeconds()
    //KMUtils.convertToMilliseconds(scratchPad, offset, (short) (offset + 8), (short) (offset + 16));
    // return KMIntegerTag.instance(
    //     KMType.ULONG_TAG,
    //     KMType.AUTH_TIMEOUT_MILLIS,
    //     KMInteger.uint_64(scratchPad, (short) (offset + 8)));
    return  KMInteger.uint_64(scratchPad, (short) (offset + 8));
  }

  // public short getVals() {
  //   return Util.getShort(
  //       heap, (short) (KMType.instanceTable[KM_KEY_PARAMETERS_OFFSET] + TLV_HEADER_SIZE));
  // }

  // public short length() {
  //   short arrPtr = getVals();
  //   return KMArray.cast(arrPtr).length();
  // }

  // public short findTag(short tagType, short tagKey) {
  //   short length = length();
  //   for (short i = 0; i < length; i++) {
  //     get()
  //   }
    // KMArray vals = KMArray.cast(getVals());
    // short index = 0;
    // short length = vals.length();
    // short key;
    // short type;
    // short ret = KMType.INVALID_VALUE;
    // short obj;
    // while (index < length) {
    //   obj = vals.get(index);
    //   key = KMTag.getKey(obj);
    //   type = KMTag.getTagType(obj);
    //   if ((tagKey == key) && (tagType == type)) {
    //     ret = obj;
    //     break;
    //   }
    //   index++;
    // }
    // return ret;
  //}

}
