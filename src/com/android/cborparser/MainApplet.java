package com.android.cborparser;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacardx.apdu.ExtendedLength;

public class MainApplet extends Applet implements ExtendedLength {


  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new MainApplet().register();
  }

  @Override
  public void process(APDU apdu) throws ISOException {
    byte[] apduBuffer = apdu.getBuffer();
    if (apdu.isISOInterindustryCLA()) {
      if (selectingApplet()) {
        return;
      }
    }
    switch (apduBuffer[ISO7816.OFFSET_INS]) {
      case 0x00:
        break;
    }
  }
}
