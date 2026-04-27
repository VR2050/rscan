package Q2;

/* JADX INFO: renamed from: Q2.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0209e {
    public static final byte[] a(String str) {
        t2.j.f(str, "$this$asUtf8ToByteArray");
        byte[] bytes = str.getBytes(z2.d.f10544b);
        t2.j.e(bytes, "(this as java.lang.String).getBytes(charset)");
        return bytes;
    }

    public static final String b(byte[] bArr) {
        t2.j.f(bArr, "$this$toUtf8String");
        return new String(bArr, z2.d.f10544b);
    }
}
