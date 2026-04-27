package Q2;

import Q2.l;
import java.util.Arrays;

/* JADX INFO: renamed from: Q2.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0205a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final byte[] f2527a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final byte[] f2528b;

    static {
        l.a aVar = l.f2556f;
        f2527a = aVar.e("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/").g();
        f2528b = aVar.e("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_").g();
    }

    public static final byte[] a(String str) {
        int i3;
        char cCharAt;
        t2.j.f(str, "$this$decodeBase64ToArray");
        int length = str.length();
        while (length > 0 && ((cCharAt = str.charAt(length - 1)) == '=' || cCharAt == '\n' || cCharAt == '\r' || cCharAt == ' ' || cCharAt == '\t')) {
            length--;
        }
        int i4 = (int) ((((long) length) * 6) / 8);
        byte[] bArr = new byte[i4];
        int i5 = 0;
        int i6 = 0;
        int i7 = 0;
        for (int i8 = 0; i8 < length; i8++) {
            char cCharAt2 = str.charAt(i8);
            if ('A' <= cCharAt2 && 'Z' >= cCharAt2) {
                i3 = cCharAt2 - 'A';
            } else if ('a' <= cCharAt2 && 'z' >= cCharAt2) {
                i3 = cCharAt2 - 'G';
            } else if ('0' <= cCharAt2 && '9' >= cCharAt2) {
                i3 = cCharAt2 + 4;
            } else if (cCharAt2 == '+' || cCharAt2 == '-') {
                i3 = 62;
            } else if (cCharAt2 == '/' || cCharAt2 == '_') {
                i3 = 63;
            } else {
                if (cCharAt2 != '\n' && cCharAt2 != '\r' && cCharAt2 != ' ' && cCharAt2 != '\t') {
                    return null;
                }
            }
            i6 = (i6 << 6) | i3;
            i5++;
            if (i5 % 4 == 0) {
                bArr[i7] = (byte) (i6 >> 16);
                int i9 = i7 + 2;
                bArr[i7 + 1] = (byte) (i6 >> 8);
                i7 += 3;
                bArr[i9] = (byte) i6;
            }
        }
        int i10 = i5 % 4;
        if (i10 == 1) {
            return null;
        }
        if (i10 == 2) {
            bArr[i7] = (byte) ((i6 << 12) >> 16);
            i7++;
        } else if (i10 == 3) {
            int i11 = i6 << 6;
            int i12 = i7 + 1;
            bArr[i7] = (byte) (i11 >> 16);
            i7 += 2;
            bArr[i12] = (byte) (i11 >> 8);
        }
        if (i7 == i4) {
            return bArr;
        }
        byte[] bArrCopyOf = Arrays.copyOf(bArr, i7);
        t2.j.e(bArrCopyOf, "java.util.Arrays.copyOf(this, newSize)");
        return bArrCopyOf;
    }

    public static final String b(byte[] bArr, byte[] bArr2) {
        t2.j.f(bArr, "$this$encodeBase64");
        t2.j.f(bArr2, "map");
        byte[] bArr3 = new byte[((bArr.length + 2) / 3) * 4];
        int length = bArr.length - (bArr.length % 3);
        int i3 = 0;
        int i4 = 0;
        while (i3 < length) {
            byte b3 = bArr[i3];
            int i5 = i3 + 2;
            byte b4 = bArr[i3 + 1];
            i3 += 3;
            byte b5 = bArr[i5];
            bArr3[i4] = bArr2[(b3 & 255) >> 2];
            bArr3[i4 + 1] = bArr2[((b3 & 3) << 4) | ((b4 & 255) >> 4)];
            int i6 = i4 + 3;
            bArr3[i4 + 2] = bArr2[((b4 & 15) << 2) | ((b5 & 255) >> 6)];
            i4 += 4;
            bArr3[i6] = bArr2[b5 & 63];
        }
        int length2 = bArr.length - length;
        if (length2 == 1) {
            byte b6 = bArr[i3];
            bArr3[i4] = bArr2[(b6 & 255) >> 2];
            bArr3[i4 + 1] = bArr2[(b6 & 3) << 4];
            byte b7 = (byte) 61;
            bArr3[i4 + 2] = b7;
            bArr3[i4 + 3] = b7;
        } else if (length2 == 2) {
            int i7 = i3 + 1;
            byte b8 = bArr[i3];
            byte b9 = bArr[i7];
            bArr3[i4] = bArr2[(b8 & 255) >> 2];
            bArr3[i4 + 1] = bArr2[((b8 & 3) << 4) | ((b9 & 255) >> 4)];
            bArr3[i4 + 2] = bArr2[(b9 & 15) << 2];
            bArr3[i4 + 3] = (byte) 61;
        }
        return AbstractC0209e.b(bArr3);
    }

    public static /* synthetic */ String c(byte[] bArr, byte[] bArr2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            bArr2 = f2527a;
        }
        return b(bArr, bArr2);
    }
}
