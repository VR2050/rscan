package im.uwrkaxlmjj.ui.utils.translate.utils;

import kotlin.UByte;

/* JADX INFO: loaded from: classes5.dex */
public class AudioBitUtils {
    public static boolean isEmpty(CharSequence text) {
        if (text == null || text.length() == 0) {
            return true;
        }
        return false;
    }

    public static byte[] GetBytes(short shortValue, boolean bigEnding) {
        byte[] byteArray = new byte[2];
        if (bigEnding) {
            byteArray[1] = (byte) (shortValue & 255);
            byteArray[0] = (byte) (((short) (shortValue >> 8)) & 255);
        } else {
            byteArray[0] = (byte) (shortValue & 255);
            byteArray[1] = (byte) (((short) (shortValue >> 8)) & 255);
        }
        return byteArray;
    }

    public static short GetShort(byte firstByte, byte secondByte, boolean bigEnding) {
        if (bigEnding) {
            short shortValue = (short) ((firstByte & UByte.MAX_VALUE) | 0);
            return (short) ((secondByte & UByte.MAX_VALUE) | ((short) (shortValue << 8)));
        }
        short shortValue2 = (short) ((secondByte & UByte.MAX_VALUE) | 0);
        return (short) ((firstByte & UByte.MAX_VALUE) | ((short) (shortValue2 << 8)));
    }

    public static short GetInt(byte firstByte, byte secondByte, byte thirdByte, byte fourthByte, boolean bigEnding) {
        if (bigEnding) {
            short shortValue = (short) (((byte) (firstByte << 24)) | 0);
            return (short) (((byte) (fourthByte << 0)) | ((short) (((byte) (thirdByte << 8)) | ((short) (((byte) (secondByte << 16)) | shortValue)))));
        }
        short shortValue2 = (short) (((byte) (firstByte << 0)) | 0);
        return (short) (((byte) (fourthByte << 24)) | ((short) (((byte) (thirdByte << 16)) | ((short) (((byte) (secondByte << 8)) | shortValue2)))));
    }

    public static byte[] AverageShortByteArray(byte firstShortHighByte, byte firstShortLowByte, byte secondShortHighByte, byte secondShortLowByte, boolean bigEnding) {
        short firstShort = GetShort(firstShortHighByte, firstShortLowByte, bigEnding);
        short secondShort = GetShort(secondShortHighByte, secondShortLowByte, bigEnding);
        return GetBytes((short) ((firstShort / 2) + (secondShort / 2)), bigEnding);
    }
}
