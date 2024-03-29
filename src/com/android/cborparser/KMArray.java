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
 * KMArray represents an array of KMTypes. Array is the sequence of elements of one or more sub
 * types of KMType. It also acts as a vector of one subtype of KMTypes on the lines of class KMArray
 * <subType>, where subType is subclass of KMType. Vector is the sequence of elements of one sub
 * type e.g. KMType.BYTE_BLOB_TYPE. The KMArray instance maps to the CBOR type array. KMArray is a
 * KMType and it further extends the value field in TLV_HEADER as ARRAY_HEADER struct{short subType;
 * short length;} followed by sequence of short pointers to KMType instances. The subType can be 0
 * if this is an array or subType is short KMType value e.g. KMType.BYTE_BLOB_TYPE if this is a
 * vector of that sub type.
 */
public class KMArray extends KMType {

  public static final short ANY_ARRAY_LENGTH = 0x1000;
  private static final byte ARRAY_HEADER_SIZE = 4;
  private static KMArray prototype;
  public static byte ARRAY_MAJOR_TYPE = (byte) 0x80;

  private KMArray() {}

  private static KMArray proto(short ptr) {
    if (prototype == null) {
      prototype = new KMArray();
    }
    KMType.instanceTable[KM_ARRAY_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    return KMType.exp(KMType.MAJOR_TYPE_ARRAY);
  }

  // static short exp(short type) {
    // short ptr = instance(ARRAY_TYPE, (short) ARRAY_HEADER_SIZE);
    // Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
    // Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), ANY_ARRAY_LENGTH);
    // return ptr;
 // }

  public static short instance(short length) {
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
    short ptr = repository.alloc(arrayHeaderLen);
    switch (arrayHeaderLen) {
      case 1:
        heap[ptr] = (byte) (ARRAY_MAJOR_TYPE | (byte) (length & 0x001F));
        break;
      case 2:
        heap[ptr] = (byte) (ARRAY_MAJOR_TYPE | 0x18);
        heap[(short) (ptr+1)] = (byte) (length & 0xFF);
        break;
      case 3:
        heap[ptr] = (byte) (ARRAY_MAJOR_TYPE | 0x19);
        Util.setShort(heap, (short) (ptr+1), length);
        break;
      default:
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    return ptr;
    // short ptr = KMType.instance(ARRAY_TYPE, (short) (ARRAY_HEADER_SIZE + (length * 2)));
    // Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.INVALID_VALUE);
    // Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), length);
    // return ptr;
  }

  // public static short instance(short length, byte type) {
  //   short ptr = instance(length);
  //   Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), type);
  //   return ptr;
  // }

  public static KMArray cast(short ptr) {
    byte[] heap = repository.getHeap();
    byte majorType = (byte) (heap[ptr] & 0x00E0);

    if (majorType != ARRAY_MAJOR_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public void pushBack(short objPtr) {

  }

  public void add(short index, short objPtr) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.setShort(heap, (short) (getStartOff() + (short) (index * 2)), objPtr);
  }

  public short get(short index) {
    return get(KMType.instanceTable[KM_ARRAY_OFFSET], headerLength(), length(), index);
    // short len = length();
    // if (index >= len) {
    //   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    // }
    // short ptr = (short) (KMType.instanceTable[KM_ARRAY_OFFSET] + headerLength());
    // for (short i = 0; i < index; i++) {
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
    //       ptr += (short) (KMArray.cast(ptr).headerLength() +
    //           KMArray.cast(ptr).contentLength());
    //       break;
    //     default:
    //       ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    //       return (short) 0;
    //   }
    // }
    // return ptr;
    //return Util.getShort(heap, (short) (getStartOff() + (short) (index * 2)));
  }

  public void swap(short index1, short index2) {
    short len = length();
    if (index1 >= len || index2 >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    short indexPtr1 =
        Util.getShort(
            heap,
            (short)
                (instanceTable[KM_ARRAY_OFFSET]
                    + TLV_HEADER_SIZE
                    + ARRAY_HEADER_SIZE
                    + (short) (index1 * 2)));
    short indexPtr2 =
        Util.getShort(
            heap,
            (short)
                (instanceTable[KM_ARRAY_OFFSET]
                    + TLV_HEADER_SIZE
                    + ARRAY_HEADER_SIZE
                    + (short) (index2 * 2)));
    Util.setShort(
        heap,
        (short)
            (instanceTable[KM_ARRAY_OFFSET]
                + TLV_HEADER_SIZE
                + ARRAY_HEADER_SIZE
                + (short) (index1 * 2)),
        indexPtr2);
    Util.setShort(
        heap,
        (short)
            (instanceTable[KM_ARRAY_OFFSET]
                + TLV_HEADER_SIZE
                + ARRAY_HEADER_SIZE
                + (short) (index2 * 2)),
        indexPtr1);
  }

  public short containedType() {
    return Util.getShort(heap, (short) (KMType.instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE));
  }

  public short getStartOff() {
    return (short) (KMType.instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + ARRAY_HEADER_SIZE);
  }

  public short length() {
    return length(KMType.instanceTable[KM_ARRAY_OFFSET]);
    // short start = KMType.instanceTable[KM_ARRAY_OFFSET];
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

  public short contentLength() {
    return contentLength(KMType.instanceTable[KM_ARRAY_OFFSET], headerLength(), length());
    // short length = length();
    // short ptr = (short) (KMType.instanceTable[KM_ARRAY_OFFSET] + headerLength());
    // short contentLength = 0;
    // for (short i = 0; i < length; i++) {
    //   byte type = KMType.getMajorType(ptr);
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
    // }
    // return contentLength;
  }

  public short headerLength() {
    return headerLength(KMType.instanceTable[KM_ARRAY_OFFSET]);
    // byte addInfo = (byte) (heap[KMType.instanceTable[KM_ARRAY_OFFSET]] & 0x1F);
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

  public short setLength(short len) {
    return Util.setShort(
        heap, (short) (KMType.instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + 2), len);
  }

  public byte[] getBuffer() {
    return heap;
  }

  public void deleteLastEntry() {
    short len = length();
    Util.setShort(
        heap, (short) (instanceTable[KM_ARRAY_OFFSET] + TLV_HEADER_SIZE + 2), (short) (len - 1));
  }
}
