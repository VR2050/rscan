package C0;

import i2.AbstractC0580h;
import i2.C;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Iterator;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final f f574a = new f();

    private f() {
    }

    public static final byte[] a(String str) {
        j.f(str, "value");
        try {
            Charset charsetForName = Charset.forName("ASCII");
            j.e(charsetForName, "forName(...)");
            byte[] bytes = str.getBytes(charsetForName);
            j.e(bytes, "getBytes(...)");
            return bytes;
        } catch (UnsupportedEncodingException e3) {
            throw new RuntimeException("ASCII not found!", e3);
        }
    }

    public static final boolean b(byte[] bArr, byte[] bArr2, int i3) {
        j.f(bArr, "byteArray");
        j.f(bArr2, "pattern");
        if (bArr2.length + i3 > bArr.length) {
            return false;
        }
        Iterable iterableO = AbstractC0580h.o(bArr2);
        if (!(iterableO instanceof Collection) || !((Collection) iterableO).isEmpty()) {
            Iterator it = iterableO.iterator();
            while (it.hasNext()) {
                int iA = ((C) it).a();
                if (bArr[i3 + iA] != bArr2[iA]) {
                    return false;
                }
            }
        }
        return true;
    }

    public static final boolean c(byte[] bArr, byte[] bArr2) {
        j.f(bArr, "byteArray");
        j.f(bArr2, "pattern");
        return b(bArr, bArr2, 0);
    }
}
