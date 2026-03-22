package com.yalantis.ucrop.util;

import android.text.TextUtils;
import android.util.Log;
import androidx.exifinterface.media.ExifInterface;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/* loaded from: classes2.dex */
public class ImageHeaderParser {
    private static final int EXIF_MAGIC_NUMBER = 65496;
    private static final int EXIF_SEGMENT_TYPE = 225;
    private static final int INTEL_TIFF_MAGIC_NUMBER = 18761;
    private static final int MARKER_EOI = 217;
    private static final int MOTOROLA_TIFF_MAGIC_NUMBER = 19789;
    private static final int ORIENTATION_TAG_TYPE = 274;
    private static final int SEGMENT_SOS = 218;
    private static final int SEGMENT_START_ID = 255;
    private static final String TAG = "ImageHeaderParser";
    public static final int UNKNOWN_ORIENTATION = -1;
    private final Reader reader;
    private static final String JPEG_EXIF_SEGMENT_PREAMBLE = "Exif\u0000\u0000";
    private static final byte[] JPEG_EXIF_SEGMENT_PREAMBLE_BYTES = JPEG_EXIF_SEGMENT_PREAMBLE.getBytes(StandardCharsets.UTF_8);
    private static final int[] BYTES_PER_FORMAT = {0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8};

    public static class RandomAccessReader {
        private final ByteBuffer data;

        public RandomAccessReader(byte[] bArr, int i2) {
            this.data = (ByteBuffer) ByteBuffer.wrap(bArr).order(ByteOrder.BIG_ENDIAN).limit(i2);
        }

        public short getInt16(int i2) {
            return this.data.getShort(i2);
        }

        public int getInt32(int i2) {
            return this.data.getInt(i2);
        }

        public int length() {
            return this.data.remaining();
        }

        public void order(ByteOrder byteOrder) {
            this.data.order(byteOrder);
        }
    }

    public interface Reader {
        int getUInt16();

        short getUInt8();

        int read(byte[] bArr, int i2);

        long skip(long j2);
    }

    public static class StreamReader implements Reader {

        /* renamed from: is */
        private final InputStream f10922is;

        public StreamReader(InputStream inputStream) {
            this.f10922is = inputStream;
        }

        @Override // com.yalantis.ucrop.util.ImageHeaderParser.Reader
        public int getUInt16() {
            return ((this.f10922is.read() << 8) & 65280) | (this.f10922is.read() & 255);
        }

        @Override // com.yalantis.ucrop.util.ImageHeaderParser.Reader
        public short getUInt8() {
            return (short) (this.f10922is.read() & 255);
        }

        @Override // com.yalantis.ucrop.util.ImageHeaderParser.Reader
        public int read(byte[] bArr, int i2) {
            int i3 = i2;
            while (i3 > 0) {
                int read = this.f10922is.read(bArr, i2 - i3, i3);
                if (read == -1) {
                    break;
                }
                i3 -= read;
            }
            return i2 - i3;
        }

        @Override // com.yalantis.ucrop.util.ImageHeaderParser.Reader
        public long skip(long j2) {
            if (j2 < 0) {
                return 0L;
            }
            long j3 = j2;
            while (j3 > 0) {
                long skip = this.f10922is.skip(j3);
                if (skip <= 0) {
                    if (this.f10922is.read() == -1) {
                        break;
                    }
                    skip = 1;
                }
                j3 -= skip;
            }
            return j2 - j3;
        }
    }

    public ImageHeaderParser(InputStream inputStream) {
        this.reader = new StreamReader(inputStream);
    }

    private static int calcTagOffset(int i2, int i3) {
        return (i3 * 12) + i2 + 2;
    }

    public static void copyExif(ExifInterface exifInterface, int i2, int i3, String str) {
        String[] strArr = {ExifInterface.TAG_F_NUMBER, ExifInterface.TAG_DATETIME, ExifInterface.TAG_DATETIME_DIGITIZED, ExifInterface.TAG_EXPOSURE_TIME, ExifInterface.TAG_FLASH, ExifInterface.TAG_FOCAL_LENGTH, ExifInterface.TAG_GPS_ALTITUDE, ExifInterface.TAG_GPS_ALTITUDE_REF, ExifInterface.TAG_GPS_DATESTAMP, ExifInterface.TAG_GPS_LATITUDE, ExifInterface.TAG_GPS_LATITUDE_REF, ExifInterface.TAG_GPS_LONGITUDE, ExifInterface.TAG_GPS_LONGITUDE_REF, ExifInterface.TAG_GPS_PROCESSING_METHOD, ExifInterface.TAG_GPS_TIMESTAMP, ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY, ExifInterface.TAG_MAKE, ExifInterface.TAG_MODEL, ExifInterface.TAG_SUBSEC_TIME, ExifInterface.TAG_SUBSEC_TIME_DIGITIZED, ExifInterface.TAG_SUBSEC_TIME_ORIGINAL, ExifInterface.TAG_WHITE_BALANCE};
        try {
            ExifInterface exifInterface2 = new ExifInterface(str);
            for (int i4 = 0; i4 < 22; i4++) {
                String str2 = strArr[i4];
                String attribute = exifInterface.getAttribute(str2);
                if (!TextUtils.isEmpty(attribute)) {
                    exifInterface2.setAttribute(str2, attribute);
                }
            }
            exifInterface2.setAttribute(ExifInterface.TAG_IMAGE_WIDTH, String.valueOf(i2));
            exifInterface2.setAttribute(ExifInterface.TAG_IMAGE_LENGTH, String.valueOf(i3));
            exifInterface2.setAttribute(ExifInterface.TAG_ORIENTATION, "0");
            exifInterface2.saveAttributes();
        } catch (IOException e2) {
            e2.getMessage();
        }
    }

    private static boolean handles(int i2) {
        return (i2 & EXIF_MAGIC_NUMBER) == EXIF_MAGIC_NUMBER || i2 == MOTOROLA_TIFF_MAGIC_NUMBER || i2 == INTEL_TIFF_MAGIC_NUMBER;
    }

    private boolean hasJpegExifPreamble(byte[] bArr, int i2) {
        boolean z = bArr != null && i2 > JPEG_EXIF_SEGMENT_PREAMBLE_BYTES.length;
        if (z) {
            int i3 = 0;
            while (true) {
                byte[] bArr2 = JPEG_EXIF_SEGMENT_PREAMBLE_BYTES;
                if (i3 >= bArr2.length) {
                    break;
                }
                if (bArr[i3] != bArr2[i3]) {
                    return false;
                }
                i3++;
            }
        }
        return z;
    }

    private int moveToExifSegmentAndGetLength() {
        while (this.reader.getUInt8() == 255) {
            short uInt8 = this.reader.getUInt8();
            if (uInt8 == SEGMENT_SOS) {
                return -1;
            }
            if (uInt8 == MARKER_EOI) {
                Log.isLoggable(TAG, 3);
                return -1;
            }
            int uInt16 = this.reader.getUInt16() - 2;
            if (uInt8 == 225) {
                return uInt16;
            }
            long j2 = uInt16;
            if (this.reader.skip(j2) != j2) {
                Log.isLoggable(TAG, 3);
                return -1;
            }
        }
        Log.isLoggable(TAG, 3);
        return -1;
    }

    private int parseExifSegment(byte[] bArr, int i2) {
        if (this.reader.read(bArr, i2) != i2) {
            Log.isLoggable(TAG, 3);
            return -1;
        }
        if (hasJpegExifPreamble(bArr, i2)) {
            return parseExifSegment(new RandomAccessReader(bArr, i2));
        }
        Log.isLoggable(TAG, 3);
        return -1;
    }

    public int getOrientation() {
        if (!handles(this.reader.getUInt16())) {
            Log.isLoggable(TAG, 3);
            return -1;
        }
        int moveToExifSegmentAndGetLength = moveToExifSegmentAndGetLength();
        if (moveToExifSegmentAndGetLength != -1) {
            return parseExifSegment(new byte[moveToExifSegmentAndGetLength], moveToExifSegmentAndGetLength);
        }
        Log.isLoggable(TAG, 3);
        return -1;
    }

    private static int parseExifSegment(RandomAccessReader randomAccessReader) {
        ByteOrder byteOrder;
        short int16 = randomAccessReader.getInt16(6);
        if (int16 == MOTOROLA_TIFF_MAGIC_NUMBER) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (int16 == INTEL_TIFF_MAGIC_NUMBER) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            Log.isLoggable(TAG, 3);
            byteOrder = ByteOrder.BIG_ENDIAN;
        }
        randomAccessReader.order(byteOrder);
        int int32 = randomAccessReader.getInt32(10) + 6;
        short int162 = randomAccessReader.getInt16(int32);
        for (int i2 = 0; i2 < int162; i2++) {
            int calcTagOffset = calcTagOffset(int32, i2);
            if (randomAccessReader.getInt16(calcTagOffset) == ORIENTATION_TAG_TYPE) {
                short int163 = randomAccessReader.getInt16(calcTagOffset + 2);
                if (int163 >= 1 && int163 <= 12) {
                    int int322 = randomAccessReader.getInt32(calcTagOffset + 4);
                    if (int322 < 0) {
                        Log.isLoggable(TAG, 3);
                    } else {
                        Log.isLoggable(TAG, 3);
                        int i3 = int322 + BYTES_PER_FORMAT[int163];
                        if (i3 > 4) {
                            Log.isLoggable(TAG, 3);
                        } else {
                            int i4 = calcTagOffset + 8;
                            if (i4 >= 0 && i4 <= randomAccessReader.length()) {
                                if (i3 >= 0 && i3 + i4 <= randomAccessReader.length()) {
                                    return randomAccessReader.getInt16(i4);
                                }
                                Log.isLoggable(TAG, 3);
                            } else {
                                Log.isLoggable(TAG, 3);
                            }
                        }
                    }
                } else {
                    Log.isLoggable(TAG, 3);
                }
            }
        }
        return -1;
    }
}
