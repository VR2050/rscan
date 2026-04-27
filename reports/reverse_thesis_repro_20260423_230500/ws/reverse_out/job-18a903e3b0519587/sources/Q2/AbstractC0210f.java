package Q2;

/* JADX INFO: renamed from: Q2.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0210f {
    public static final boolean a(byte[] bArr, int i3, byte[] bArr2, int i4, int i5) {
        t2.j.f(bArr, "a");
        t2.j.f(bArr2, "b");
        for (int i6 = 0; i6 < i5; i6++) {
            if (bArr[i6 + i3] != bArr2[i6 + i4]) {
                return false;
            }
        }
        return true;
    }

    public static final void b(long j3, long j4, long j5) {
        if ((j4 | j5) < 0 || j4 > j3 || j3 - j4 < j5) {
            throw new ArrayIndexOutOfBoundsException("size=" + j3 + " offset=" + j4 + " byteCount=" + j5);
        }
    }

    public static final int c(int i3) {
        return ((i3 & 255) << 24) | (((-16777216) & i3) >>> 24) | ((16711680 & i3) >>> 8) | ((65280 & i3) << 8);
    }

    public static final short d(short s3) {
        return (short) (((s3 & 255) << 8) | ((65280 & s3) >>> 8));
    }

    public static final String e(byte b3) {
        return new String(new char[]{R2.b.h()[(b3 >> 4) & 15], R2.b.h()[b3 & 15]});
    }

    public static final String f(int i3) {
        int i4 = 0;
        if (i3 == 0) {
            return "0";
        }
        char[] cArr = {R2.b.h()[(i3 >> 28) & 15], R2.b.h()[(i3 >> 24) & 15], R2.b.h()[(i3 >> 20) & 15], R2.b.h()[(i3 >> 16) & 15], R2.b.h()[(i3 >> 12) & 15], R2.b.h()[(i3 >> 8) & 15], R2.b.h()[(i3 >> 4) & 15], R2.b.h()[i3 & 15]};
        while (i4 < 8 && cArr[i4] == '0') {
            i4++;
        }
        return new String(cArr, i4, 8 - i4);
    }
}
