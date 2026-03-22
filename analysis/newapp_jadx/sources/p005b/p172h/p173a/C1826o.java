package p005b.p172h.p173a;

import java.io.Closeable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

/* renamed from: b.h.a.o */
/* loaded from: classes.dex */
public class C1826o {
    /* renamed from: a */
    public static void m1186a(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e2) {
                C1817f.m1164a("Error closing resource", e2);
            }
        }
    }

    /* renamed from: b */
    public static String m1187b(String str) {
        try {
            return URLDecoder.decode(str, "utf-8");
        } catch (UnsupportedEncodingException e2) {
            throw new RuntimeException("Error decoding url", e2);
        }
    }
}
