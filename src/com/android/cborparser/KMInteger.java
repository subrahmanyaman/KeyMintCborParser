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
import javacard.framework.Util;

/**
 * Represents 8 bit, 16 bit, 32 bit and 64 bit unsigned integer. It corresponds to CBOR uint type.
 * struct{byte INTEGER_TYPE; short length; 4 or 8 bytes of value}
 */
public class KMInteger extends KMType {
  public static final byte UINT_8 = 1;
  public static final byte UINT_16 = 2;
  public static final byte UINT_32 = 4;
  public static final byte UINT_64 = 8;
  private static KMInteger prototype;
  public static byte INT_MAJOR_TYPE = 0x00;
  private static final byte ADD_INFO_BYTE = 24;
  private static final byte ADD_INFO_SHORT = 25;
  private static final byte ADD_INFO_INT = 26;
  private static final byte ADD_INFO_LONG = 27;

  public static final short TAG_TYPE = (short) 0x0080;
  //public static final short ANY_INT = (short) 0xFFFF;
  //public static byte[] INT_EXP = {INT_MAJOR_TYPE};
  //public static final short INT_MASK = (short) 0xFFFF;

  protected KMInteger() {}

  private static KMInteger proto(short ptr) {
    if (prototype == null) {
      prototype = new KMInteger();
    }
    KMType.instanceTable[KM_INTEGER_OFFSET] = ptr;
    return prototype;
  }

  // | TYPE(1) | LEN(2) | DATA(4 / 8) |
  public static short exp() {
    return uint_8((byte) 0);
  }

  public static short exp(short val) {
    // In future, to differentitate between val=0 is to mask it with INT_MASK.
    return uint_16(val) ;
  }

  // return an empty integer instance
  public static short instance(short length) {
    if ((length <= 0) || (length > 8)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (length > 4) {
      length = UINT_64;
    } else {
      length = UINT_32;
    }
    return KMType.instance(INTEGER_TYPE, length);
  }

  public static short instance(short tagType, short tagKey) {
    if (tagType == 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short ptr = repository.alloc((short) (UINT_32 + 1));
    heap[ptr] = ADD_INFO_INT;
    Util.setShort(heap, (short) (ptr + 1), tagType);
    Util.setShort(heap, (short) (ptr + 3), tagKey);
    return ptr;
  }

  public static short instance(byte[] num, short srcOff, short length) {
    if (length > 8) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    short startOff = srcOff;
    for(;startOff < (short) (srcOff + length); startOff++) {
      if (num[(startOff)] != 0) {
        break;
      }
    }
    short cborLength = 0;
    byte addInfo = 0;
    length = (short) (length - (startOff - srcOff));
    if (length == 1) {
      return uint_8(num[startOff]);
    } else if (length == 2) {
      return uint_16(Util.getShort(num, startOff));
    } else if (length <= 4) {
      cborLength = 5;
      addInfo = ADD_INFO_INT;
    } else if (length <= 8) {
      cborLength = 9;
      addInfo = ADD_INFO_LONG;
    }


    short ptr = repository.alloc(cborLength);
    heap[ptr] = addInfo;
    Util.arrayCopyNonAtomic(num, startOff, heap, (short) (ptr + cborLength - length), length);
    return ptr;

  }

  // public static short instance(byte[] num, short srcOff, short length) {
  //   if (length > 8) {
  //     KMException.throwIt(KMError.UNKNOWN_ERROR);
  //   }
  //   short startOff = srcOff;
  //   for(;startOff < (short) (srcOff + length); startOff++) {
  //     if (num[(startOff)] != 0) {
  //       break;
  //     }
  //   }
  //   byte majorTypeAddInfo = 0;
  //   short cborLength = 0;
  //   if ((short) (startOff - srcOff) < 4) {
  //     cborLength = 9;
  //     majorTypeAddInfo = 27;
  //   } else if ((short) (startOff - srcOff) < 6) {
  //     cborLength = 5;
  //     majorTypeAddInfo = 26;
  //   } else if ((short) (startOff - srcOff) < 7) {
  //     cborLength = 3;
  //     majorTypeAddInfo = 25;
  //   } else {
  //     if ((short) (num[startOff] & 0x00FF) > 23) {
  //       cborLength = 2;
  //       majorTypeAddInfo = 24;
  //     } else {
  //       cborLength = 1;
  //       majorTypeAddInfo = num[startOff];
  //     }
  //   }
  //
  //   short ptr = repository.alloc(cborLength);
  //   length = (short) (length - startOff - srcOff);
  //   heap[ptr] = majorTypeAddInfo;
  //   if (cborLength > 1) {
  //     Util.arrayCopyNonAtomic(num, startOff, heap, (short) (ptr + 1+ (cborLength - length - 1)), length);
  //   }
  //   return ptr;
  // }

  public static KMInteger cast(short ptr) {
    byte[] heap = repository.getHeap();
    short majorType = (short) (heap[ptr] & 0x00E0);

    if (majorType != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // if (Util.getShort(heap, (short) (ptr + 1)) == INVALID_VALUE) {
    //   ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    // }
    return proto(ptr);
  }

  // create integer and copy byte value
  public static short uint_8(byte num) {
    short length = 1;
    byte addInfo = 0;
    if ((short) (num & 0x00FF) > 23) {
      length = 2;
      addInfo = ADD_INFO_BYTE;
    }
    short ptr = repository.alloc(length);
    heap[ptr] = addInfo;
    heap[(short)(ptr + length - 1)] = num;
    return ptr;
  }

  // create integer and copy short value
  public static short uint_16(short num) {
    // Only compare the value of 'num' to 256 if it is a positive integer. This is because
    // if 'num' is negative, the condition (num < 256) will always be true.
    if (((num & 0x8000) == 0) && (num < 256)) {
      return uint_8((byte)  (num & 0x00FF));
    } else {
      short ptr = repository.alloc((short) 3);
      heap[ptr] = ADD_INFO_SHORT;
      Util.setShort(heap, (short) (ptr + 1), num);
      return ptr;
    }
  }

  // create integer and copy integer value
  public static short uint_32(byte[] num, short offset) {
    return instance(num, offset, UINT_32);
  }

  // create integer and copy integer value
  public static short uint_64(byte[] num, short offset) {
    return instance(num, offset, UINT_64);
  }

  public static short compare(short num1, short num2) {
    short num1Buf = repository.alloc((short) 8);
    short num2Buf = repository.alloc((short) 8);
    Util.arrayFillNonAtomic(repository.getHeap(), num1Buf, (short) 8, (byte) 0);
    Util.arrayFillNonAtomic(repository.getHeap(), num2Buf, (short) 8, (byte) 0);
    short len = KMInteger.cast(num1).length();
    KMInteger.cast(num1).getValue(repository.getHeap(), (short) (num1Buf + (short) (8 - len)), len);
    len = KMInteger.cast(num2).length();
    KMInteger.cast(num2).getValue(repository.getHeap(), (short) (num2Buf + (short) (8 - len)), len);
    return KMInteger.unsignedByteArrayCompare(
        repository.getHeap(), num1Buf, repository.getHeap(), num2Buf, (short) 8);
  }

  public static byte unsignedByteArrayCompare(
      byte[] a1, short offset1, byte[] a2, short offset2, short length) {
    byte count = (byte) 0;
    short val1 = (short) 0;
    short val2 = (short) 0;

    for (; count < length; count++) {
      val1 = (short) (a1[(short) (count + offset1)] & 0x00FF);
      val2 = (short) (a2[(short) (count + offset2)] & 0x00FF);

      if (val1 < val2) {
        return -1;
      }
      if (val1 > val2) {
        return 1;
      }
    }
    return 0;
  }

  // Get the length of the integer
  public short length() {
    short val = heap[getBaseOffset()];
    short addInfo = (short) (val & 0x00FF);
    if (addInfo  == 27) {
      return (short) 9;
    } else if (addInfo == 26) {
      return (short) 5;
    } else if (addInfo == 25) {
      return (short) 3;
    } else if (addInfo == 24) {
      return (short) 2;
    } else if (addInfo <= 23) {
      return (short) 1;
    } else {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return (short) 0;
  }

  // Get the buffer pointer in which blob is contained.
  public byte[] getBuffer() {
    return heap;
  }

  // Get the start of value
  public short getStartOff() {
    return getBaseOffset();
  }

  public void getValue(byte[] dest, short destOff, short length) {
    short srcLen = length(); // Gives the length of complete cbor int.
    short startOff = getStartOff();
    if (srcLen > 1) {
      startOff = (short) (getStartOff() + 1);
      srcLen = (short) (srcLen - 1);
    }
    if (length < srcLen) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (length > srcLen) {
      destOff += (short) (length - srcLen);
    }

    Util.arrayCopyNonAtomic(heap, startOff, dest, destOff, srcLen);
  }

  public void setValue(byte[] src, short srcOff) {
    Util.arrayCopyNonAtomic(src, srcOff, heap, getStartOff(), length());
  }

  public short value(byte[] dest, short destOff) {
    Util.arrayCopyNonAtomic(heap, getStartOff(), dest, destOff, length());
    return length();
  }

  public short toLittleEndian(byte[] dest, short destOff) {
    short index = (short) (length() - 1);
    while (index >= 0) {
      dest[destOff++] = heap[(short) (instanceTable[KM_INTEGER_OFFSET] + TLV_HEADER_SIZE + index)];
      index--;
    }
    return length();
  }

  private byte getAddInfo() {
    return  (byte) (heap[getStartOff()] & 0x1F);
  }

  public short getShort() {
    if (getAddInfo() <= 24) {
      // Integer is less than SHORT
      return (short) (getByte() & 0x00FF);
    }
    return Util.getShort(heap, (short) (getStartOff() + length() - UINT_16));
  }

  public short getSignificantShort() {
    if (getAddInfo() <= 25) {
      // Integer is less than UINT32
      return (short) 0;
    }
    return Util.getShort(heap, (short) (getStartOff() + length() - UINT_32));
  }

  public byte getByte() {
    byte addInfo = getAddInfo();
    if (addInfo <= 23) {
      return addInfo;
    }
    return heap[getStartOff() + length() - UINT_8];
  }

  public boolean isZero() {
    if (getShort() == 0 && getSignificantShort() == 0) {
      return true;
    }
    return false;
  }

  protected short getBaseOffset() {
    return instanceTable[KM_INTEGER_OFFSET];
  }
}
