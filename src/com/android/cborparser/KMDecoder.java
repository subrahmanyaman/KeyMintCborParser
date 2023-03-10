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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This class decodes the CBOR format data into a KMType structure. It interprets the input CBOR
 * format using the input expression provided. Validation of KeyMint tags and tag types happens in
 * the process of decoding, while constructing the subtype of a KMType structure.
 */
public class KMDecoder {

  // major types
  private static final short UINT_TYPE = 0x00;
  private static final short NEG_INT_TYPE = 0x20;
  private static final short BYTES_TYPE = 0x40;
  private static final short TSTR_TYPE = 0x60;
  private static final short ARRAY_TYPE = 0x80;
  private static final short MAP_TYPE = 0xA0;
  private static final short SIMPLE_VALUE_TYPE = 0xE0;
  private static final short SEMANTIC_TAG_TYPE = 0xC0;

  // masks
  private static final short ADDITIONAL_MASK = 0x1F;
  private static final short MAJOR_TYPE_MASK = 0xE0;

  // value length
  private static final short UINT8_LENGTH = 0x18;
  private static final short UINT16_LENGTH = 0x19;
  private static final short UINT32_LENGTH = 0x1A;
  private static final short UINT64_LENGTH = 0x1B;

  private static final byte SCRATCH_BUF_SIZE = 6;
  private static final byte START_OFFSET = 0;
  private static final byte LEN_OFFSET = 2;
  private static final byte TAG_KEY_OFFSET = 4;
  private Object[] bufferRef;
  private short[] scratchBuf;

  public KMDecoder() {
    bufferRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    scratchBuf = JCSystem.makeTransientShortArray(SCRATCH_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
    bufferRef[0] = null;
    scratchBuf[START_OFFSET] = (short) 0;
    scratchBuf[LEN_OFFSET] = (short) 0;
    scratchBuf[TAG_KEY_OFFSET] = (short) 0;
  }

  public short decode(short exp, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length);
    return decode(exp);
  }

  public short decode(short exp) {
    byte type = KMType.getMajorType(exp);
    switch (type) {
      case KMType.MAJOR_TYPE_INT:
        return decodeInteger(exp);
      case KMType.MAJOR_TYPE_BYTE_BLOB:
        return decodeByteBlob();
      case KMType.MAJOR_TYPE_ARRAY:
        return decodeArray(exp);
      case KMType.MAJOR_TYPE_MAP:
        return decodeMap(exp);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0;
    }

  }

  private short decodeInteger(short exp) {
    short startOff = scratchBuf[START_OFFSET];
    short key = KMInteger.cast(exp).getShort();
    short length = KMInteger.cast(startOff).length();
    if (key != 0) {
      // unmask expression
      // TODO Currently none of the below switch types are 0. In future to handle '0' it is
      // a good idea to mast the as shown below in commented
      //key = (short) (key ^ KMInteger.INT_MASK);
      switch (key) {
        case KMType.ENUM_TAG:
        case KMType.ENUM_ARRAY_TAG:
        case KMType.UINT_TAG:
        case KMType.UINT_ARRAY_TAG:
        case KMType.ULONG_TAG:
        case KMType.ULONG_ARRAY_TAG:
        case KMType.BOOL_TAG:
        case KMType.BIGNUM_TAG:
        case KMType.DATE_TAG:
        case KMType.BYTES_TAG:
          break;
        case KMType.HARDWARE_TYPE:
        case KMType.KEY_FORMAT:
        case KMType.KEY_DERIVATION_FUNCTION:
        case KMType.VERIFIED_BOOT_STATE:
        case KMType.DEVICE_LOCKED:
        case KMType.USER_AUTH_TYPE:
        case KMType.PURPOSE:
        case KMType.ECCURVE:
          // Enum Validation
          byte value = KMInteger.cast(startOff).getByte();
          if (!KMValidations.validateEnum(key, value)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
          }
          break;
        default:
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
    }
    incrementStartOff(length);
    return startOff;
  }

  public void validateKeyParamPair(short keyPtr, short valuePtr) {
    short tagType = KMInteger.cast(keyPtr).getSignificantShort();
    switch (tagType) {
      case KMType.ENUM_TAG:
        if (!KMValidations.validateEnumTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.ENUM_ARRAY_TAG:
        if (!KMValidations.validateEnumArrayTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.UINT_TAG:
        if (!KMValidations.validateUIntTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.ULONG_TAG:
        if (!KMValidations.validateULongTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.DATE_TAG:
        if (!KMValidations.validateDateTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.UINT_ARRAY_TAG:
        break;
      case KMType.ULONG_ARRAY_TAG:
        if (!KMValidations.validateULongArrayTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.BOOL_TAG:
        if (!KMValidations.validateBoolTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.BIGNUM_TAG:
        if (!KMValidations.validateBignumTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
      case KMType.BYTES_TAG:
        if (!KMValidations.validateBytesTag(keyPtr, valuePtr)) {
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        break;
    }
  }

  public short decodeArray(short exp) {
    short startOff = scratchBuf[START_OFFSET];
    short payloadLength = KMArray.cast(startOff).length();
    incrementStartOff(KMArray.cast(startOff).headerLength());
    short index = 0;
    short type;
    short obj;
      while (index < payloadLength) {
        type = KMArray.cast(exp).get(index);
        decode(type);
        index++;
      }
    return startOff;
  }
  public short decodeMap(short exp) {
    short rulePtr = KMMap.cast(exp).getKey((short) 0);
    short rule = KMType.INVALID_VALUE;
    if (rulePtr != KMType.INVALID_VALUE && (KMType.getMajorType(rulePtr) == KMType.MAJOR_TYPE_INT)) {
      rule = KMInteger.cast(rulePtr).getShort();
    }
    if (rule == KMType.RULE) {
      return decodeKeyParam(exp);
    } else {
      short startOff = scratchBuf[START_OFFSET];
      short payloadLength = KMMap.cast(startOff).length();
      incrementStartOff(KMMap.cast(startOff).headerLength());
      short index = 0;
      short type;
      short obj;
      while (index < payloadLength) {
        type = KMMap.cast(exp).getKey(index);
        decode(type);
        type = KMMap.cast(exp).getKeyValue(index);
        decode(type);
        index++;
      }
      return startOff;
    }
  }

  private short decodeKeyParam(short exp) {
    short startOff = scratchBuf[START_OFFSET];
    short payloadLength = KMMap.cast(startOff).length();
    incrementStartOff(KMMap.cast(startOff).headerLength());
    short tagRule = KMMap.cast(exp).getKeyValue((short) 0);
    boolean ignoreInvalidTags = KMInteger.cast(tagRule).getByte() == KMType.IGNORE_INVALID_TAGS;
    short length = KMMap.cast(exp).length();
    short index = 0;
    boolean tagFound;
    short tagInd;
    short tagType;
    short tagKeyClass;
    short tagValueClass;
    short allowedType;
    // For each tag in payload ...
    while (index < payloadLength) {
      tagFound = false;
      tagInd = 1;
      tagType = KMInteger.cast(scratchBuf[START_OFFSET]).getSignificantShort();
      // Check against the allowed tags ...
      while (tagInd < length) {
        tagKeyClass = KMMap.cast(exp).getKey(tagInd);
        tagValueClass = KMMap.cast(exp).getKeyValue(tagInd);
        allowedType = KMInteger.cast(tagKeyClass).getShort();
        // If it is part of allowed tags ...
        if (tagType == allowedType) {
          // then decodeByteBlob and add that to the array.
          try {
            tagFound = true;
            validateKeyParamPair(decode(tagKeyClass), decode(tagValueClass));
            break;
          } catch (KMException e) {
            if (KMException.reason() == KMError.INVALID_TAG) {
              if (!ignoreInvalidTags) {
                KMException.throwIt(KMError.INVALID_TAG);
              }
            } else {
              KMException.throwIt(KMException.reason());
            }
            break;
          }
        }
        tagInd++;
      }
      if (!tagFound) {
        KMException.throwIt(KMError.INVALID_TAG);
      } else {
        index++;
      }
    }
    return startOff;
  }

  private short decodeByteBlob() {
    short startOff = scratchBuf[START_OFFSET];
    short length = KMByteBlob.cast(startOff).headerLength();
    length += KMByteBlob.cast(startOff).length();
    incrementStartOff(length);
    return startOff;
  }

  private short readShort() {
    byte[] buffer = (byte[]) bufferRef[0];
    short startOff = scratchBuf[START_OFFSET];
    short val = Util.makeShort(buffer[startOff], buffer[(short) (startOff + 1)]);
    incrementStartOff((short) 2);
    return val;
  }

  private byte readByte() {
    short startOff = scratchBuf[START_OFFSET];
    byte val = ((byte[]) bufferRef[0])[startOff];
    incrementStartOff((short) 1);
    return val;
  }

  private void incrementStartOff(short inc) {
    scratchBuf[START_OFFSET] += inc;
    if (scratchBuf[START_OFFSET] > scratchBuf[LEN_OFFSET]) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }
}
