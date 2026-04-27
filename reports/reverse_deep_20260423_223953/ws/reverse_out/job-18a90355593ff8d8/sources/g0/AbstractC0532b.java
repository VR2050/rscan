package g0;

import androidx.activity.result.d;
import java.io.UnsupportedEncodingException;

/* JADX INFO: renamed from: g0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0532b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final boolean f9203a = true;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final boolean f9204b = e();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static boolean f9205c = false;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final byte[] f9206d = a("RIFF");

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final byte[] f9207e = a("WEBP");

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final byte[] f9208f = a("VP8 ");

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final byte[] f9209g = a("VP8L");

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final byte[] f9210h = a("VP8X");

    private static byte[] a(String str) {
        try {
            return str.getBytes("ASCII");
        } catch (UnsupportedEncodingException e3) {
            throw new RuntimeException("ASCII not found!", e3);
        }
    }

    public static boolean b(byte[] bArr, int i3) {
        return j(bArr, i3 + 12, f9210h) && ((bArr[i3 + 20] & 2) == 2);
    }

    public static boolean c(byte[] bArr, int i3, int i4) {
        return i4 >= 21 && j(bArr, i3 + 12, f9210h);
    }

    public static boolean d(byte[] bArr, int i3) {
        return j(bArr, i3 + 12, f9210h) && ((bArr[i3 + 20] & 16) == 16);
    }

    private static boolean e() {
        return true;
    }

    public static boolean f(byte[] bArr, int i3) {
        return j(bArr, i3 + 12, f9209g);
    }

    public static boolean g(byte[] bArr, int i3) {
        return j(bArr, i3 + 12, f9208f);
    }

    public static boolean h(byte[] bArr, int i3, int i4) {
        return i4 >= 20 && j(bArr, i3, f9206d) && j(bArr, i3 + 8, f9207e);
    }

    public static InterfaceC0531a i() {
        if (f9205c) {
            return null;
        }
        try {
            d.a(Class.forName("com.facebook.webpsupport.WebpBitmapFactoryImpl").newInstance());
        } catch (Throwable unused) {
        }
        f9205c = true;
        return null;
    }

    private static boolean j(byte[] bArr, int i3, byte[] bArr2) {
        if (bArr2 == null || bArr == null || bArr2.length + i3 > bArr.length) {
            return false;
        }
        for (int i4 = 0; i4 < bArr2.length; i4++) {
            if (bArr[i4 + i3] != bArr2[i4]) {
                return false;
            }
        }
        return true;
    }
}
