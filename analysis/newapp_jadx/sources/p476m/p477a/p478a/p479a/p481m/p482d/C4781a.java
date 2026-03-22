package p476m.p477a.p478a.p479a.p481m.p482d;

import java.io.IOException;
import java.io.OutputStream;

/* renamed from: m.a.a.a.m.d.a */
/* loaded from: classes3.dex */
public final class C4781a {

    /* renamed from: a */
    public static final byte[] f12253a = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47};

    /* renamed from: b */
    public static final byte[] f12254b = new byte[256];

    static {
        int i2 = 0;
        int i3 = 0;
        while (true) {
            byte[] bArr = f12254b;
            if (i3 >= bArr.length) {
                break;
            }
            bArr[i3] = -1;
            i3++;
        }
        while (true) {
            byte[] bArr2 = f12253a;
            if (i2 >= bArr2.length) {
                f12254b[61] = -2;
                return;
            } else {
                f12254b[bArr2[i2]] = (byte) i2;
                i2++;
            }
        }
    }

    /* renamed from: a */
    public static int m5460a(byte[] bArr, OutputStream outputStream) {
        byte[] bArr2 = new byte[4];
        int i2 = 0;
        int i3 = 0;
        for (byte b2 : bArr) {
            byte b3 = f12254b[b2 & 255];
            if (b3 != -1) {
                int i4 = i2 + 1;
                bArr2[i2] = b3;
                if (i4 == 4) {
                    byte b4 = bArr2[0];
                    byte b5 = bArr2[1];
                    byte b6 = bArr2[2];
                    byte b7 = bArr2[3];
                    if (b4 == -2 || b5 == -2) {
                        throw new IOException("Invalid Base64 input: incorrect padding, first two bytes cannot be padding");
                    }
                    outputStream.write((b4 << 2) | (b5 >> 4));
                    i3++;
                    if (b6 != -2) {
                        outputStream.write((b5 << 4) | (b6 >> 2));
                        i3++;
                        if (b7 != -2) {
                            outputStream.write((b6 << 6) | b7);
                            i3++;
                        }
                    } else if (b7 != -2) {
                        throw new IOException("Invalid Base64 input: incorrect padding, 4th byte must be padding if 3rd byte is");
                    }
                    i2 = 0;
                } else {
                    i2 = i4;
                }
            }
        }
        if (i2 == 0) {
            return i3;
        }
        throw new IOException("Invalid Base64 input: truncated");
    }
}
