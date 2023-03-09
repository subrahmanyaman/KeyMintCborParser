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
 * This class encodes KMType structures to a cbor format data recursively. Encoded bytes are written
 * on the buffer provided by the caller. An exception will be thrown if the encoded data length is
 * greater than the buffer length provided.
 */
public class KMEncoder {

  // major types
  private static final byte UINT_TYPE = 0x00;
  private static final byte NEG_INT_TYPE = 0x20;
  private static final byte BYTES_TYPE = 0x40;
  private static final byte TSTR_TYPE = 0x60;
  private static final byte ARRAY_TYPE = (byte) 0x80;
  private static final byte MAP_TYPE = (byte) 0xA0;
  private static final byte SIMPLE_VALUE_TYPE = (byte) 0xE0;
  private static final byte SEMANTIC_TAG_TYPE = (byte) 0xC0;

  // masks
  private static final byte ADDITIONAL_MASK = 0x1F;

  // value length
  private static final byte UINT8_LENGTH = (byte) 0x18;
  private static final byte UINT16_LENGTH = (byte) 0x19;
  private static final byte UINT32_LENGTH = (byte) 0x1A;
  private static final byte UINT64_LENGTH = (byte) 0x1B;
  private static final short TINY_PAYLOAD = 0x17;
  private static final short SHORT_PAYLOAD = 0x100;
  private static final byte STACK_SIZE = 50;
  private static final byte SCRATCH_BUF_SIZE = 6;
  private static final byte START_OFFSET = 0;
  private static final byte LEN_OFFSET = 2;
  private static final byte STACK_PTR_OFFSET = 4;

  private Object[] bufferRef;
  private short[] scratchBuf;
  private short[] stack;

  public KMEncoder() {
    bufferRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    scratchBuf = JCSystem.makeTransientShortArray(SCRATCH_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
    stack = JCSystem.makeTransientShortArray(STACK_SIZE, JCSystem.CLEAR_ON_RESET);
    bufferRef[0] = null;
    scratchBuf[START_OFFSET] = (short) 0;
    scratchBuf[LEN_OFFSET] = (short) 0;
    scratchBuf[STACK_PTR_OFFSET] = (short) 0;
  }

  private void push(short objPtr) {
    stack[scratchBuf[STACK_PTR_OFFSET]] = objPtr;
    scratchBuf[STACK_PTR_OFFSET]++;
  }

  private short pop() {
    scratchBuf[STACK_PTR_OFFSET]--;
    return stack[scratchBuf[STACK_PTR_OFFSET]];
  }

  private void encode(short obj) {
    push(obj);
  }

  /**
   * This functions encodes the given object into the provider buffer space in cbor format.
   *
   * @param object Object to be encoded into cbor data.
   * @param buffer Output where cbor data is copied.
   * @param startOff is the start offset of the buffer.
   * @param bufLen length of the buffer
   * @param encoderOutLimitLen excepted encoded output length.
   * @return length of the encoded buffer.
   */
  public short encode(
      short object, byte[] buffer, short startOff, short bufLen, short encoderOutLimitLen) {
    scratchBuf[STACK_PTR_OFFSET] = 0;
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    if ((short) (startOff + encoderOutLimitLen) > bufLen) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    scratchBuf[LEN_OFFSET] = (short) (startOff + encoderOutLimitLen);
    push(object);
    encode();
    return (short) (scratchBuf[START_OFFSET] - startOff);
  }

  public short encode(short object, byte[] buffer, short startOff, short bufLen) {
    return encode(object, buffer, startOff, bufLen, (short) (bufLen - startOff));
  }

  private void encode() {
    while (scratchBuf[STACK_PTR_OFFSET] > 0) {
      short exp = pop();
      byte type = KMType.getType(exp);
      switch (type) {
        case KMType.INTEGER_TYPE:
          encodeUnsignedInteger(exp);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
    }
  }

  private void encodeInteger(byte[] val, short len, short startOff, short majorType) {
    // find out the most significant byte
    short msbIndex = findMsb(val, startOff, len);
    // find the difference between most significant byte and len
    short diff = (short) (len - msbIndex);
    if (diff == 0) {
      writeByte((byte) (majorType | 0));
    } else if ((diff == 1)
        && (val[(short) (startOff + msbIndex)] < UINT8_LENGTH)
        && (val[(short) (startOff + msbIndex)] >= 0)) {
      writeByte((byte) (majorType | val[(short) (startOff + msbIndex)]));
    } else if (diff == 1) {
      writeByte((byte) (majorType | UINT8_LENGTH));
      writeByte(val[(short) (startOff + msbIndex)]);
    } else if (diff == 2) {
      writeByte((byte) (majorType | UINT16_LENGTH));
      writeBytes(val, (short) (startOff + msbIndex), (short) 2);
    } else if (diff <= 4) {
      writeByte((byte) (majorType | UINT32_LENGTH));
      writeBytes(val, (short) (startOff + len - 4), (short) 4);
    } else {
      writeByte((byte) (majorType | UINT64_LENGTH));
      writeBytes(val, startOff, (short) 8);
    }
  }

  // find out the most significant byte
  public short findMsb(byte[] buf, short offset, short len) {
    byte index = 0;
    // find out the most significant byte
    while (index < len) {
      if (buf[(short) (offset + index)] > 0) {
        break;
      } else if (buf[(short) (offset + index)] < 0) {
        break;
      }
      index++; // index will be equal to len if value is 0.
    }
    return index;
  }

  private void encodeUnsignedInteger(short obj) {
    byte[] val = KMInteger.cast(obj).getBuffer();
    short len = KMInteger.cast(obj).length();
    short startOff = KMInteger.cast(obj).getStartOff();
    encodeInteger(val, len, startOff, UINT_TYPE);
  }


  private void writeByteValue(byte val) {
    if ((val < UINT8_LENGTH) && (val >= 0)) {
      writeByte((byte) (UINT_TYPE | val));
    } else {
      writeByte((byte) (UINT_TYPE | UINT8_LENGTH));
      writeByte(val);
    }
  }

  private void writeTag(short tagType, short tagKey) {
    writeByte((byte) (UINT_TYPE | UINT32_LENGTH));
    writeShort(tagType);
    writeShort(tagKey);
  }

  private void writeMajorTypeWithLength(byte majorType, short len) {
    if (len <= TINY_PAYLOAD) {
      writeByte((byte) (majorType | (byte) (len & ADDITIONAL_MASK)));
    } else if (len < SHORT_PAYLOAD) {
      writeByte((byte) (majorType | UINT8_LENGTH));
      writeByte((byte) (len & 0xFF));
    } else {
      writeByte((byte) (majorType | UINT16_LENGTH));
      writeShort(len);
    }
  }

  private void writeBytes(byte[] buf, short start, short len) {
    byte[] buffer = (byte[]) bufferRef[0];
    Util.arrayCopyNonAtomic(buf, start, buffer, scratchBuf[START_OFFSET], len);
    incrementStartOff(len);
  }

  private void writeShort(short val) {
    byte[] buffer = (byte[]) bufferRef[0];
    buffer[scratchBuf[START_OFFSET]] = (byte) ((val >> 8) & 0xFF);
    incrementStartOff((short) 1);
    buffer[scratchBuf[START_OFFSET]] = (byte) ((val & 0xFF));
    incrementStartOff((short) 1);
  }

  private void writeByte(byte val) {
    byte[] buffer = (byte[]) bufferRef[0];
    buffer[scratchBuf[START_OFFSET]] = val;
    incrementStartOff((short) 1);
  }

  private void incrementStartOff(short inc) {
    scratchBuf[START_OFFSET] += inc;
    if (scratchBuf[START_OFFSET] >= scratchBuf[LEN_OFFSET]) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  public short encodeArrayHeader(short bufLen, byte[] buffer, short startOff, short length) {
    bufferRef[0] = buffer;
    scratchBuf[START_OFFSET] = startOff;
    scratchBuf[LEN_OFFSET] = (short) (startOff + length + 1);
    writeMajorTypeWithLength(ARRAY_TYPE, bufLen);
    return (short) (scratchBuf[START_OFFSET] - startOff);
  }
}
