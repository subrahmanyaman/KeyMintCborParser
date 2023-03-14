/*
 * Copyright(C) 2021 The Android Open Source Project
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
 * KMMap represents an array of a KMType key and a KMType value. Map is the sequence of pairs. Each
 * pair is one or more sub-types of KMType. The KMMap instance maps to the CBOR type map. KMMap is a
 * KMType and it further extends the value field in TLV_HEADER as MAP_HEADER struct{ short
 * subType;short length;} followed by a sequence of pairs. Each pair contains a key and a value as
 * short pointers to KMType instances.
 */
public class KMMap extends KMType {

  public static final short ANY_MAP_LENGTH = 0x1000;
  private static final byte MAP_HEADER_SIZE = 4;
  private static KMMap prototype;
  public static byte MAP_MAJOR_TYPE = (byte) 0xA0;

  private KMMap() {}

  private static KMMap proto(short ptr) {
    if (prototype == null) {
      prototype = new KMMap();
    }
    instanceTable[KM_MAP_OFFSET] = ptr;
    return prototype;
  }

  // public static short exp() {
  //   short ptr = instance(MAP_TYPE, (short) MAP_HEADER_SIZE);
  //   Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), (short) 0);
  //   Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), ANY_MAP_LENGTH);
  //   return ptr;
  // }

  public static short instance(short length) {
    return instance(length, null, (short) 0);
    // short arrayHeaderLen = 0;
    // if (length <= 23) {
    //   arrayHeaderLen = 1;
    // } else if (length >= 24 && length <= 255) {
    //   arrayHeaderLen = 2;
    // } else if (length > 255 && length <= 65535 ) {
    //   arrayHeaderLen = 3;
    // } else {
    //   KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    // }
    // short ptr = repository.alloc(arrayHeaderLen);
    // switch (arrayHeaderLen) {
    //   case 1:
    //     heap[ptr] = (byte) (MAP_MAJOR_TYPE | (byte) (length & 0x001F));
    //     break;
    //   case 2:
    //     heap[ptr] = (byte) (MAP_MAJOR_TYPE | 0x18);
    //     heap[(short) (ptr+1)] = (byte) (length & 0xFF);
    //     break;
    //   case 3:
    //     heap[ptr] = (byte) (MAP_MAJOR_TYPE | 0x19);
    //     Util.setShort(heap, (short) (ptr+1), length);
    //     break;
    //   default:
    //     KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    // }
    // return ptr;
  }

  public static short instance(short length, byte[] scratchPad, short offset) {
    short arrayHeaderLen = 0;
    if (length <= 23) {
      arrayHeaderLen = 1;
    } else if (length >= 24 && length <= 255) {
      arrayHeaderLen = 2;
    } else if (length > 255 && length <= 65535 ) {
      arrayHeaderLen = 3;
    } else {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    byte[] buf = scratchPad;
    short ret = arrayHeaderLen;
    if (scratchPad == null) {
      buf = heap;
      ret = offset = repository.alloc(arrayHeaderLen);
    }
    switch (arrayHeaderLen) {
      case 1:
        buf[offset] = (byte) (MAP_MAJOR_TYPE | (byte) (length & 0x001F));
        break;
      case 2:
        buf[offset] = (byte) (MAP_MAJOR_TYPE | 0x18);
        buf[(short) (offset+1)] = (byte) (length & 0xFF);
        break;
      case 3:
        buf[offset] = (byte) (MAP_MAJOR_TYPE | 0x19);
        Util.setShort(heap, (short) (offset+1), length);
        break;
      default:
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    return ret;
  }

  public void updateLength(short length, byte[] scratchPad, short offset) {
    short start = instanceTable[KM_MAP_OFFSET];
    short origLen = length();
    if (origLen > 23) {
      if (length > 23) {
        heap[(short) (start + 1)] = (byte) (length & 0x00FF);
        return;
      } else {
        heap[start] = (byte) (heap[start] & 0x00E0);
        heap[start] = (byte) (heap[start] | (length & 0x001F));
        repository.move((short) (start + 1), (short)  1, scratchPad, offset);
      }
    } else {
      heap[start] = (byte) (heap[start] & 0x00E0);
      heap[start] = (byte) (heap[start] | (length & 0x001F));
    }
  }

  // public static short instance(short length, byte type) {
  //   short ptr = instance(length);
  //   Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
  //   return ptr;
  // }

  public static KMMap cast(short ptr) {
    byte[] heap = repository.getHeap();
    byte majorType = (byte) (heap[ptr] & 0x00E0);

    if (majorType != MAP_MAJOR_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public void add(short index, short keyPtr, short valPtr) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short keyIndex =
        (short)
            (instanceTable[KM_MAP_OFFSET]
                + TLV_HEADER_SIZE
                + MAP_HEADER_SIZE
                + (short) (index * 4));
    Util.setShort(heap, keyIndex, keyPtr);
    Util.setShort(heap, (short) (keyIndex + 2), valPtr);
  }

  public short getKey(short index) {
    return get(KMType.instanceTable[KM_MAP_OFFSET], headerLength(), length(), index);
    // short len = length();
    // if (index >= len) {
    //   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    // }
    // short ptr = KMType.instanceTable[KM_MAP_OFFSET];
    // for (short i = 0; i <= index; i++) {
    //   byte type = KMType.getMajorType(ptr);
    //   ptr += get(ptr, PAIR_TYPE_KEY);
    //   switch (type) {
    //     case KMType.MAJOR_TYPE_INT:
    //       ptr += KMInteger.cast(ptr).length();
    //       break;
    //     case KMType.MAJOR_TYPE_BYTE_BLOB:
    //       ptr += (short) (KMByteBlob.cast(ptr).headerLength() +
    //           KMByteBlob.cast(ptr).length());
    //       break;
    //     case KMType.MAJOR_TYPE_ARRAY:
    //       ptr += KMArray.cast(ptr).headerLength();
    //       break;
    //     case KMType.MAJOR_TYPE_MAP:
    //       ptr += KMMap.cast(ptr).headerLength();
    //       break;
    //     default:
    //       ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    //       return (short) 0;
    //   }
    // }
    // return ptr;
  }

  // private static final byte PAIR_TYPE_KEY = 0x00;
  // private static final byte PAIR_TYPE_VALUE = 0x01;

  // private short get(short ptr, byte pairType) {
  //   byte type = KMType.getMajorType(ptr);
  //   switch (type) {
  //     case KMType.MAJOR_TYPE_INT:
  //       ptr += KMInteger.cast(ptr).length();
  //       break;
  //     case KMType.MAJOR_TYPE_BYTE_BLOB:
  //       ptr += (short) (KMByteBlob.cast(ptr).headerLength() +
  //           KMByteBlob.cast(ptr).length());
  //       break;
  //     case KMType.MAJOR_TYPE_ARRAY:
  //       ptr += KMArray.cast(ptr).headerLength();
  //       break;
  //     case KMType.MAJOR_TYPE_MAP:
  //       ptr += KMMap.cast(ptr).headerLength();
  //       break;
  //     default:
  //       ISOException.throwIt(ISO7816.SW_DATA_INVALID);
  //       return (short) 0;
  //   }
  //   return ptr;
  // }

  // private short contentLength(short type, short ptr) {
  //   short contentLength = 0;
  //   switch (type) {
  //     case KMType.MAJOR_TYPE_INT:
  //       contentLength += KMInteger.cast(ptr).length();
  //       break;
  //     case KMType.MAJOR_TYPE_BYTE_BLOB:
  //       contentLength += (short) (KMByteBlob.cast(ptr).headerLength() +
  //           KMByteBlob.cast(ptr).length());
  //       break;
  //     case KMType.MAJOR_TYPE_ARRAY:
  //       contentLength += KMArray.cast(ptr).contentLength();
  //       break;
  //     default:
  //       ISOException.throwIt(ISO7816.SW_DATA_INVALID);
  //       return (short) 0;
  //   }
  //   return contentLength;
  // }

  public short contentLength() {
    return contentLength(KMType.instanceTable[KM_MAP_OFFSET], headerLength(), length());
    // short contentLength = 0;
    // for (short i = 0; i < length; i++) {
    //   byte type = KMType.getMajorType(ptr);
    //   contentLength += contentLength(type, ptr); // Key
    //   ptr += (short) (ptr+contentLength);
    //   type = KMType.getMajorType(ptr);
    //   contentLength += contentLength(type, ptr); // Value
    //   ptr += (short) (ptr+contentLength);
    // }
    // return contentLength;
  }

  public short getKeyValue(short index) {
    return next(get(KMType.instanceTable[KM_MAP_OFFSET], headerLength(), length(), index));
    // short len = length();
    // if (index >= len) {
    //   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    // }
    // short ptr = KMType.instanceTable[KM_MAP_OFFSET];
    // for (short i = 0; i <= index; i++) {
    //
    // }
    // return ptr;
  }

  public void swap(short index1, short index2) {
    short len = length();
    if (index1 >= len || index2 >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Swap keys
    short indexPtr1 =
        Util.getShort(
            heap,
            (short)
                (instanceTable[KM_MAP_OFFSET]
                    + TLV_HEADER_SIZE
                    + MAP_HEADER_SIZE
                    + (short) (index1 * 4)));
    short indexPtr2 =
        Util.getShort(
            heap,
            (short)
                (instanceTable[KM_MAP_OFFSET]
                    + TLV_HEADER_SIZE
                    + MAP_HEADER_SIZE
                    + (short) (index2 * 4)));
    Util.setShort(
        heap,
        (short)
            (instanceTable[KM_MAP_OFFSET]
                + TLV_HEADER_SIZE
                + MAP_HEADER_SIZE
                + (short) (index1 * 4)),
        indexPtr2);
    Util.setShort(
        heap,
        (short)
            (instanceTable[KM_MAP_OFFSET]
                + TLV_HEADER_SIZE
                + MAP_HEADER_SIZE
                + (short) (index2 * 4)),
        indexPtr1);

    // Swap Values
    indexPtr1 =
        Util.getShort(
            heap,
            (short)
                (instanceTable[KM_MAP_OFFSET]
                    + TLV_HEADER_SIZE
                    + MAP_HEADER_SIZE
                    + (short) (index1 * 4 + 2)));
    indexPtr2 =
        Util.getShort(
            heap,
            (short)
                (instanceTable[KM_MAP_OFFSET]
                    + TLV_HEADER_SIZE
                    + MAP_HEADER_SIZE
                    + (short) (index2 * 4 + 2)));
    Util.setShort(
        heap,
        (short)
            (instanceTable[KM_MAP_OFFSET]
                + TLV_HEADER_SIZE
                + MAP_HEADER_SIZE
                + (short) (index1 * 4 + 2)),
        indexPtr2);
    Util.setShort(
        heap,
        (short)
            (instanceTable[KM_MAP_OFFSET]
                + TLV_HEADER_SIZE
                + MAP_HEADER_SIZE
                + (short) (index2 * 4 + 2)),
        indexPtr1);
  }

  public void canonicalize() {
    //KMCoseMap.canonicalize(instanceTable[KM_MAP_OFFSET], length());
  }

  public short containedType() {
    return Util.getShort(heap, (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE));
  }

  public short getStartOff() {
    return (short) (instanceTable[KM_MAP_OFFSET] + TLV_HEADER_SIZE + MAP_HEADER_SIZE);
  }

  public short length() {
    return length(KMType.instanceTable[KM_MAP_OFFSET]);
    // short start = KMType.instanceTable[KM_MAP_OFFSET];
    // //short val = heap[start];
    // byte addInfo = (byte) (heap[start] & 0x1F);
    // if (addInfo == 25) {
    //   return Util.getShort(heap, (short) (start+1));
    // } else if (addInfo == 24) {
    //   return (short) (heap[(short) (start+1)] & 0x00FF);
    // } else if (addInfo <= 23) {
    //   return addInfo;
    // } else {
    //   KMException.throwIt(KMError.UNKNOWN_ERROR);
    // }
    // return 0;
  }

  public short totalLength() {
    return (short) (headerLength() + contentLength());
  }

  public short headerLength() {
    return headerLength(KMType.instanceTable[KM_MAP_OFFSET]);
    // byte addInfo = (byte) (heap[KMType.instanceTable[KM_MAP_OFFSET]] & 0x1F);
    // if (addInfo  == 27) {
    //   return (short) 9;
    // } else if (addInfo == 26) {
    //   return (short) 5;
    // } else if (addInfo == 25) {
    //   return (short) 3;
    // } else if (addInfo == 24) {
    //   return (short) 2;
    // } else if (addInfo <= 23) {
    //   return (short) 1;
    // } else {
    //   KMException.throwIt(KMError.UNKNOWN_ERROR);
    // }
    // return 0;
  }

  public byte[] getBuffer() {
    return heap;
  }
}
