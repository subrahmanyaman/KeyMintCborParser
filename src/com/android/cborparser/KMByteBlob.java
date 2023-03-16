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
 * KMByteBlob represents contiguous block of bytes. It corresponds to CBOR type of Byte String. It
 * extends KMType by specifying value field as zero or more sequence of bytes. struct{byte
 * BYTE_BLOB_TYPE; short length; sequence of bytes}
 */
public class KMByteBlob extends KMType {

  private static byte OFFSET_SIZE = 2;
  private static KMByteBlob prototype;
  public static byte BYTE_BLOB_MAJOR_TYPE = 0x40;
  //public static byte[] INT_EXP = {BYTE_BLOB_MAJOR_TYPE};

  protected KMByteBlob() {}

  private static KMByteBlob proto(short ptr) {
    if (prototype == null) {
      prototype = new KMByteBlob();
    }
    KMType.instanceTable[KM_BYTE_BLOB_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    return KMType.exp(BYTE_BLOB_MAJOR_TYPE);
  }

  private static void instance(byte[] buf, short offset, short length, short byteBlobHeaderLen) {
    switch (byteBlobHeaderLen) {
      case 1:
        buf[offset] = (byte) (BYTE_BLOB_MAJOR_TYPE | (byte) (length & 0x001F));
        break;
      case 2:
        buf[offset] = (byte) (BYTE_BLOB_MAJOR_TYPE | 0x18);
        buf[(short) (offset+1)] = (byte) (length & 0xFF);
        break;
      case 3:
        buf[offset] = (byte) (BYTE_BLOB_MAJOR_TYPE | 0x19);
        Util.setShort(buf, (short) (offset+1), length);
        break;
      default:
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
  }
  public static short addHeader(short length, byte[] scratchPad, short offset) {
    short byteBlobHeaderLen = byteBlobHeaderLength(length);
    instance(scratchPad, offset, length, byteBlobHeaderLen);
    return byteBlobHeaderLen;
  }

  public static short byteBlobHeaderLength(short length) {
    short byteBlobHeaderLen = 0;
    if (length <= 23) {
      byteBlobHeaderLen = 1;
    } else if (length >= 24 && length <= 255) {
      byteBlobHeaderLen = 2;
    } else if (length > 255 && length <= 65535 ) {
      byteBlobHeaderLen = 3;
    } else {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    return byteBlobHeaderLen;
  }

  // return an empty byte blob instance
  public static short instance(short length) {
    short byteBlobHeaderLen = byteBlobHeaderLength(length);
    short ptr = repository.alloc((short) (byteBlobHeaderLen + length));
    instance(repository.getHeap(), ptr, length, byteBlobHeaderLen);
    return ptr;
  }

  // byte blob from existing buf
  public static short instance(byte[] buf, short startOff, short length) {
    short ptr = instance(length);
    short start = (short) (ptr + KMByteBlob.cast(ptr).headerLength());
    Util.arrayCopyNonAtomic(buf, startOff, heap, start, length);
    return ptr;
  }

  // cast the ptr to KMByteBlob
  public static KMByteBlob cast(short ptr) {
    byte[] heap = repository.getHeap();
    short majorType = (short) (heap[ptr] & 0x00E0);

    if (majorType != MAJOR_TYPE_BYTE_BLOB) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  // Add the byte
  public void add(short index, byte val) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    heap[(short) (getStartOff() + index)] = val;
  }

  // Get the byte
  public byte get(short index) {
    short len = length();
    if (index >= len) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    return heap[(short) (getStartOff() + index)];
  }

  // Get the start of blob
  public short getStartOff() {
    //return Util.getShort(heap, (short) (getBaseOffset() + TLV_HEADER_SIZE));
    return (short) (instanceTable[KM_BYTE_BLOB_OFFSET] + headerLength());
  }

  public void setStartOff(short offset) {
    Util.setShort(heap, (short) (instanceTable[KM_BYTE_BLOB_OFFSET] + TLV_HEADER_SIZE), offset);
  }

  // Get the length of the blob
  public short length() {
    return length(instanceTable[KM_BYTE_BLOB_OFFSET]);
    //return Util.getShort(heap, (short) (getBaseOffset() + 1));
    // byte addInfo = (byte) (heap[getBaseOffset()] & 0x1F);
    // if (addInfo == 25) {
    //   return Util.getShort(heap, (short) (getBaseOffset()+1));
    // } else if (addInfo == 24) {
    //   return (short) (heap[(short) (getBaseOffset()+1)] & 0x00FF);
    // } else if (addInfo <= 23) {
    //   return addInfo;
    // } else {
    //   KMException.throwIt(KMError.UNKNOWN_ERROR);
    // }
    // return 0;
  }

  public short headerLength() {
    return headerLength(instanceTable[KM_BYTE_BLOB_OFFSET]);
    //return Util.getShort(heap, (short) (getBaseOffset() + 1));
    // byte addInfo = (byte) (heap[getBaseOffset()] & 0x1F);
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

  // Get the buffer pointer in which blob is contained.
  public byte[] getBuffer() {
    return heap;
  }

  public boolean contains(byte value) {
    short length = length();
    short ptr = (short) (instanceTable[KM_BYTE_BLOB_OFFSET] + headerLength());
    for(short i = 0; i < length; i++) {
      if (heap[(short) (ptr + i)] == value) {
        return true;
      }
    }
    return false;
  }

  // public void getValue(byte[] destBuf, short destStart, short destLength) {
  //   Util.arrayCopyNonAtomic(heap, getStartOff(), destBuf, destStart, destLength);
  // }
  //
  // public short getValues(byte[] destBuf, short destStart) {
  //   short destLength = length();
  //   Util.arrayCopyNonAtomic(heap, getStartOff(), destBuf, destStart, destLength);
  //   return destLength;
  // }
  //
  // public void setValue(byte[] srcBuf, short srcStart, short srcLength) {
  //   if (length() < srcLength) {
  //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
  //   }
  //   Util.arrayCopyNonAtomic(srcBuf, srcStart, heap, getStartOff(), srcLength);
  //   setLength(srcLength);
  // }

  public boolean isValid() {
    return (length() != 0);
  }

  // public void setLength(short len) {
  //   Util.setShort(heap, (short) (getBaseOffset() + 1), len);
  // }
}
