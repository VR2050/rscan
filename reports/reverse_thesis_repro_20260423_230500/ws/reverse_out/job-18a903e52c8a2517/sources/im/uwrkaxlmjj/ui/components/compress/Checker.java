package im.uwrkaxlmjj.ui.components.compress;

import android.graphics.BitmapFactory;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import kotlin.UByte;

/* JADX INFO: loaded from: classes5.dex */
enum Checker {
    SINGLE;

    private static final String JPG = ".jpg";
    private static final String TAG = "Luban";
    private final byte[] JPEG_SIGNATURE = {-1, -40, -1};

    Checker() {
    }

    boolean isJPG(InputStream is) {
        return isJPG(toByteArray(is));
    }

    int getOrientation(InputStream is) {
        return getOrientation(toByteArray(is));
    }

    private boolean isJPG(byte[] data) {
        if (data == null || data.length < 3) {
            return false;
        }
        byte[] signatureB = {data[0], data[1], data[2]};
        return Arrays.equals(this.JPEG_SIGNATURE, signatureB);
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x0063, code lost:
    
        android.util.Log.e(im.uwrkaxlmjj.ui.components.compress.Checker.TAG, "Invalid length");
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0068, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0069, code lost:
    
        r1 = r3;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int getOrientation(byte[] r12) {
        /*
            Method dump skipped, instruction units count: 225
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.compress.Checker.getOrientation(byte[]):int");
    }

    String extSuffix(InputStreamProvider input) {
        try {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inJustDecodeBounds = true;
            BitmapFactory.decodeStream(input.open(), null, options);
            return options.outMimeType.replace("image/", ".");
        } catch (Exception e) {
            return JPG;
        }
    }

    boolean needCompress(int leastCompressSize, String path) {
        if (leastCompressSize <= 0) {
            return true;
        }
        File source = new File(path);
        return source.exists() && source.length() > ((long) (leastCompressSize << 10));
    }

    private int pack(byte[] bytes, int offset, int length, boolean littleEndian) {
        int step = 1;
        if (littleEndian) {
            offset += length - 1;
            step = -1;
        }
        int value = 0;
        while (true) {
            int length2 = length - 1;
            if (length > 0) {
                value = (value << 8) | (bytes[offset] & UByte.MAX_VALUE);
                offset += step;
                length = length2;
            } else {
                return value;
            }
        }
    }

    private byte[] toByteArray(InputStream is) {
        if (is == null) {
            return new byte[0];
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        while (true) {
            try {
                try {
                    int read = is.read(data, 0, data.length);
                    if (read != -1) {
                        buffer.write(data, 0, read);
                    } else {
                        try {
                            break;
                        } catch (IOException e) {
                        }
                    }
                } catch (Exception e2) {
                    byte[] bArr = new byte[0];
                    try {
                        buffer.close();
                    } catch (IOException e3) {
                    }
                    return bArr;
                }
            } finally {
                try {
                    buffer.close();
                } catch (IOException e4) {
                }
            }
        }
        return buffer.toByteArray();
    }
}
