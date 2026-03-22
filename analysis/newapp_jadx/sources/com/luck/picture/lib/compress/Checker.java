package com.luck.picture.lib.compress;

import android.graphics.BitmapFactory;
import android.text.TextUtils;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/* loaded from: classes2.dex */
public enum Checker {
    SINGLE;

    private static final String JPG = ".jpg";
    public static final String MIME_TYPE_HEIC = "image/heic";
    public static final String MIME_TYPE_JPEG = "image/jpeg";
    public static final String MIME_TYPE_JPG = "image/jpg";
    private static final String TAG = "Luban";
    private final byte[] JPEG_SIGNATURE = {-1, -40, -1};

    Checker() {
    }

    private int pack(byte[] bArr, int i2, int i3, boolean z) {
        int i4;
        if (z) {
            i2 += i3 - 1;
            i4 = -1;
        } else {
            i4 = 1;
        }
        int i5 = 0;
        while (true) {
            int i6 = i3 - 1;
            if (i3 <= 0) {
                return i5;
            }
            i5 = (bArr[i2] & 255) | (i5 << 8);
            i2 += i4;
            i3 = i6;
        }
    }

    private byte[] toByteArray(InputStream inputStream) {
        if (inputStream == null) {
            return new byte[0];
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] bArr = new byte[4096];
        while (true) {
            try {
                try {
                    int read = inputStream.read(bArr, 0, 4096);
                    if (read != -1) {
                        byteArrayOutputStream.write(bArr, 0, read);
                    } else {
                        try {
                            break;
                        } catch (IOException unused) {
                        }
                    }
                } finally {
                    try {
                        byteArrayOutputStream.close();
                    } catch (IOException unused2) {
                    }
                }
            } catch (Exception unused3) {
                byte[] bArr2 = new byte[0];
                try {
                    byteArrayOutputStream.close();
                } catch (IOException unused4) {
                }
                return bArr2;
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    public String extSuffix(InputStreamProvider inputStreamProvider) {
        try {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inJustDecodeBounds = true;
            BitmapFactory.decodeStream(inputStreamProvider.open(), null, options);
            return options.outMimeType.replace("image/", ".");
        } catch (Exception unused) {
            return JPG;
        }
    }

    public int getOrientation(InputStream inputStream) {
        return getOrientation(toByteArray(inputStream));
    }

    public boolean isJPG(InputStream inputStream) {
        return isJPG(toByteArray(inputStream));
    }

    public boolean needCompress(int i2, String str) {
        if (i2 <= 0) {
            return true;
        }
        File file = new File(str);
        return file.exists() && file.length() > ((long) (i2 << 10));
    }

    public boolean needCompressToLocalMedia(int i2, String str) {
        if (i2 <= 0 || TextUtils.isEmpty(str)) {
            return true;
        }
        File file = new File(str);
        return file.exists() && file.length() > ((long) (i2 << 10));
    }

    /* JADX WARN: Code restructure failed: missing block: B:37:0x0061, code lost:
    
        if (r3 <= 8) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0063, code lost:
    
        r2 = pack(r11, r1, 4, false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x006a, code lost:
    
        if (r2 == 1229531648) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x006f, code lost:
    
        if (r2 == 1296891946) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0071, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0072, code lost:
    
        if (r2 != 1229531648) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0075, code lost:
    
        r5 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0076, code lost:
    
        r2 = pack(r11, r1 + 4, 4, r5) + 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x007f, code lost:
    
        if (r2 < 10) goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0081, code lost:
    
        if (r2 <= r3) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0084, code lost:
    
        r1 = r1 + r2;
        r3 = r3 - r2;
        r2 = pack(r11, r1 - 2, 2, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x008c, code lost:
    
        r4 = r2 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x008e, code lost:
    
        if (r2 <= 0) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0092, code lost:
    
        if (r3 < 12) goto L88;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x009a, code lost:
    
        if (pack(r11, r1, 2, r5) != 274) goto L72;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00b3, code lost:
    
        r1 = r1 + 12;
        r3 = r3 - 12;
        r2 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x009c, code lost:
    
        r11 = pack(r11, r1 + 8, 2, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00a2, code lost:
    
        if (r11 == 3) goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x00a5, code lost:
    
        if (r11 == 6) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x00a7, code lost:
    
        if (r11 == 8) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x00a9, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00aa, code lost:
    
        return com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView.ORIENTATION_270;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x00ad, code lost:
    
        return 90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x00b0, code lost:
    
        return 180;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x00b9, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x005f, code lost:
    
        r1 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0060, code lost:
    
        r3 = 0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int getOrientation(byte[] r11) {
        /*
            Method dump skipped, instructions count: 186
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.compress.Checker.getOrientation(byte[]):int");
    }

    public boolean isJPG(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.startsWith(MIME_TYPE_HEIC) || str.startsWith("image/jpeg") || str.startsWith(MIME_TYPE_JPG);
    }

    private boolean isJPG(byte[] bArr) {
        if (bArr == null || bArr.length < 3) {
            return false;
        }
        return Arrays.equals(this.JPEG_SIGNATURE, new byte[]{bArr[0], bArr[1], bArr[2]});
    }

    public String extSuffix(String str) {
        try {
            return TextUtils.isEmpty(str) ? JPG : str.startsWith("video") ? str.replace("video/", ".") : str.replace("image/", ".");
        } catch (Exception unused) {
            return JPG;
        }
    }
}
