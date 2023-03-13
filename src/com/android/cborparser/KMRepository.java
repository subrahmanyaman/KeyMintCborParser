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
 * KMRepository class manages volatile memory usage by the applet. Note the repository is only used
 * by applet and it is not intended to be used by seProvider.
 */
public class KMRepository {

  // The maximum available heap memory.
  public static final short HEAP_SIZE = 10000;
  // Index pointing from the back of heap.
  private static short[] reclaimIndex;
  // Singleton instance
  private static KMRepository repository;
  // Heap buffer
  private byte[] heap;
  // Index to the heap buffer.
  private short[] heapIndex;

  public KMRepository(boolean isUpgrading) {
    heap = JCSystem.makeTransientByteArray(HEAP_SIZE, JCSystem.CLEAR_ON_RESET);
    heapIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
    reclaimIndex[0] = HEAP_SIZE;
    repository = this;
  }

  public static KMRepository instance() {
    return repository;
  }

  public void onUninstall() {
    // Javacard Runtime environment cleans up the data.

  }

  public void onProcess() {
  }

  public void clean() {
    Util.arrayFillNonAtomic(heap, (short) 0, HEAP_SIZE, (byte) 0);
    heapIndex[0] = 0;
    reclaimIndex[0] = HEAP_SIZE;
  }

  public void onDeselect() {
  }

  public void onSelect() {
    // If write through caching is implemented then this method will restore the data into cache
  }

  // This function uses memory from the back of the heap(transient memory). Call
  // reclaimMemory function immediately after the use.
  public short allocReclaimableMemory(short length) {
    if ((((short) (reclaimIndex[0] - length)) <= heapIndex[0]) || (length >= HEAP_SIZE / 2)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    reclaimIndex[0] -= length;
    return reclaimIndex[0];
  }

  // Reclaims the memory back.
  public void reclaimMemory(short length) {
    if (reclaimIndex[0] < heapIndex[0]) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayFillNonAtomic(heap, reclaimIndex[0], length, (byte) 0);
    reclaimIndex[0] += length;
  }

  public short allocAvailableMemory() {
    if (heapIndex[0] >= heap.length) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short index = heapIndex[0];
    heapIndex[0] = reclaimIndex[0];
    return index;
  }

  public short alloc(short length) {
    if ((((short) (heapIndex[0] + length)) > heap.length)
        || (((short) (heapIndex[0] + length)) > reclaimIndex[0])) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    heapIndex[0] += length;
    return (short) (heapIndex[0] - length);
  }

  public byte[] getHeap() {
    return heap;
  }

  public short getHeapIndex() {
    return heapIndex[0];
  }

  // Use this function to reset the heapIndex to its previous state.
  // Some of the data might be lost so use it carefully.
  public void setHeapIndex(short offset) {
    if (offset > heapIndex[0] || offset < 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    Util.arrayFillNonAtomic(heap, offset, (short) (heapIndex[0] - offset), (byte) 0);
    heapIndex[0] = offset;
  }

  private void moveChunk(short startOff, short length, byte[] scratchPad, short offset) {
    Util.arrayCopyNonAtomic(heap, startOff, scratchPad, offset, length);
    short moveStart = (short) (startOff + length);
    short moveLength = (short) (heapIndex[0] - startOff - length);
    Util.arrayCopyNonAtomic(heap, moveStart, heap, startOff, moveLength);
    moveStart = (short) (heapIndex[0] - length);
    Util.arrayCopyNonAtomic(scratchPad, offset, heap, moveStart, length);
  }

  /*
  This function moves the 2nd block after the 4th block as shown below.
  This move changes the pointers of BLOCK-2, BLOCK-3 and BLOCK-4, so it is the responsibility
  of the caller to update the pointers of BLOCK-2, BLOCK-3 and BLOCK-4.
                                          HEAP_IDX                                   RECLAIM_IDX
   ____________________________________________________________________________________________
  | BLOCK-1 | BLOCK-2 | BLOCK-3 | BLOCK-4 |..........................................| BLOCK-N |
   --------------------------------------------------------------------------------------------
                                          HEAP_IDX                                   RECLAIM_IDX
   ____________________________________________________________________________________________
  | BLOCK-1 | BLOCK-3 | BLOCK-4 | BLOCK-2 |..........................................| BLOCK-N |
   --------------------------------------------------------------------------------------------
  */
  public short move(short startOff, short length, byte[] scratchPad, short offset) {
    // move chunks of 256.
    short noOfLoops = (short) (length / 256);
    short remaining = (short) (length % 256);
    for (short i = 0; i < noOfLoops; i++) {
      moveChunk(startOff, (short) 256, scratchPad, offset);
    }
    if (remaining != 0) {
      moveChunk(startOff, remaining, scratchPad, offset);
    }
    return (short) (heapIndex[0] - length);
  }

  private void moveTowardsReclaimIndex(short startOff, short length, byte[] scratchPad, short offset) {
    Util.arrayCopyNonAtomic(heap, startOff, scratchPad, offset, length);
    short reclaimIdx = allocReclaimableMemory(length);
    Util.arrayCopyNonAtomic(scratchPad, offset, heap, reclaimIdx, length);
    Util.arrayFillNonAtomic(heap, startOff, length, (byte) 0);
    setHeapIndex((short) startOff);
  }

  /*
  This function moves the 2nd block before the nth block as shown below
  This move changes the pointers of BLOCK-2, so it is the responsibility of the caller to update
  the pointers of BLOCK-2.
                      HEAP_IDX                                                       RECLAIM_IDX
   ____________________________________________________________________________________________
  | BLOCK-1 | BLOCK-2 |..............................................................| BLOCK-N |
   --------------------------------------------------------------------------------------------
            HEAP_IDX                                                       RECLAIM_IDX
   ____________________________________________________________________________________________
  | BLOCK-1 | .............................................................| BLOCK-2 | BLOCK-N |
   --------------------------------------------------------------------------------------------
  */
  public short moveTowardsReclaimIndex(short length, byte[] scratchPad, short offset) {
    // move chunks of 256.
    short startOff = (short) (heapIndex[0] - length);
    short noOfLoops = (short) (length / 256);
    short remaining = (short) (length % 256);
    for (short i = 0; i < noOfLoops; i++) {
      moveTowardsReclaimIndex((short) (startOff + length - 256), (short) 256, scratchPad, offset);
      length -= 256;
    }
    if (remaining != 0) {
      moveTowardsReclaimIndex(startOff, remaining, scratchPad, offset);
    }
    return reclaimIndex[0];
  }

  private void moveTowardsHeapIndex(short startOff, short length, byte[] scratchPad, short offset) {
    Util.arrayCopyNonAtomic(heap, startOff, scratchPad, offset, length);
    Util.arrayFillNonAtomic(heap, startOff, length, (byte) 0);
    reclaimIndex[0] += length;
    short index = alloc(length);
    Util.arrayCopyNonAtomic(scratchPad, offset, heap, index, length);
  }

  /*
  This function moves the (N-1)th block after 1st block as shown below.
  This move changes the pointers of BLOCK-(N-1), so it is the responsibility of the caller to update
  the pointers of BLOCK-(N-1).

            HEAP_IDX                                                   RECLAIM_IDX
   ____________________________________________________________________________________________
  | BLOCK-1 | .........................................................| BLOCK-(N-1) | BLOCK-N |
   --------------------------------------------------------------------------------------------
                          HEAP_IDX                                                   RECLAIM_IDX
   ____________________________________________________________________________________________
  | BLOCK-1 | BLOCK-(N-1) |..........................................................| BLOCK-N |
   --------------------------------------------------------------------------------------------
  */
  public short moveTowardsHeapIndex(short length, byte[] scratchPad, short offset) {
    // move chunks of 256.
    short startOff = reclaimIndex[0];
    short noOfLoops = (short) (length / 256);
    short remaining = (short) (length % 256);
    for (short i = 0; i < noOfLoops; i++) {
      moveTowardsHeapIndex(startOff, (short) 256, scratchPad, offset);
    }
    if (remaining != 0) {
      moveTowardsHeapIndex(startOff, remaining, scratchPad, offset);
    }
    return (short) (heapIndex[0] - length);
  }

  public short getHeapReclaimIndex() {
    return reclaimIndex[0];
  }
}
