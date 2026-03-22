package p005b.p172h.p173a;

import android.text.TextUtils;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import p005b.p172h.p173a.p175s.C1836a;
import p005b.p172h.p173a.p176t.C1839b;

/* renamed from: b.h.a.l */
/* loaded from: classes.dex */
public class C1823l {

    /* renamed from: a */
    public final ExecutorService f2817a = Executors.newSingleThreadExecutor();

    /* renamed from: b */
    public final String f2818b;

    /* renamed from: c */
    public final int f2819c;

    /* renamed from: b.h.a.l$b */
    public class b implements Callable<Boolean> {
        public b(a aVar) {
        }

        @Override // java.util.concurrent.Callable
        public Boolean call() {
            boolean z;
            C1820i c1820i = new C1820i(C1823l.this.m1179a(), new C1839b(), new C1836a());
            try {
                try {
                    byte[] bytes = "ping ok".getBytes();
                    c1820i.mo1176a(0L);
                    byte[] bArr = new byte[bytes.length];
                    c1820i.read(bArr);
                    z = Arrays.equals(bytes, bArr);
                    String str = "Ping response: `" + new String(bArr) + "`, pinged? " + z;
                    if (str != null) {
                        TextUtils.isEmpty(str);
                    }
                } catch (C1825n e2) {
                    C1817f.m1164a("Error reading ping response", e2);
                    z = false;
                }
                c1820i.close();
                return Boolean.valueOf(z);
            } catch (Throwable th) {
                c1820i.close();
                throw th;
            }
        }
    }

    public C1823l(String str, int i2) {
        this.f2818b = str;
        this.f2819c = i2;
    }

    /* renamed from: a */
    public final String m1179a() {
        return String.format(Locale.US, "http://%s:%d/%s", this.f2818b, Integer.valueOf(this.f2819c), "ping");
    }

    /* renamed from: b */
    public void m1180b(Socket socket) {
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write("HTTP/1.1 200 OK\n\n".getBytes());
        outputStream.write("ping ok".getBytes());
    }
}
