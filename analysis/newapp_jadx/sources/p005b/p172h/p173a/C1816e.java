package p005b.p172h.p173a;

import android.text.TextUtils;
import java.io.BufferedOutputStream;
import java.lang.Thread;
import java.net.Socket;
import java.util.Locale;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p172h.p173a.C1824m;
import p005b.p172h.p173a.p174r.C1830b;

/* renamed from: b.h.a.e */
/* loaded from: classes.dex */
public class C1816e extends C1824m {

    /* renamed from: i */
    public final C1820i f2785i;

    /* renamed from: j */
    public final C1830b f2786j;

    /* renamed from: k */
    public InterfaceC1813b f2787k;

    public C1816e(C1820i c1820i, C1830b c1830b) {
        super(c1820i, c1830b);
        this.f2786j = c1830b;
        this.f2785i = c1820i;
    }

    @Override // p005b.p172h.p173a.C1824m
    /* renamed from: d */
    public void mo1161d(int i2) {
        InterfaceC1813b interfaceC1813b = this.f2787k;
        if (interfaceC1813b != null) {
            interfaceC1813b.mo1159a(this.f2786j.f2834b, this.f2785i.f2810c.f2830a, i2);
        }
    }

    /* renamed from: g */
    public final String m1162g(String str, Object... objArr) {
        return String.format(Locale.US, str, objArr);
    }

    /* renamed from: h */
    public void m1163h(C1815d c1815d, Socket socket) {
        String str;
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(socket.getOutputStream());
        C1820i c1820i = this.f2785i;
        synchronized (c1820i) {
            if (TextUtils.isEmpty(c1820i.f2810c.f2832c)) {
                c1820i.m1177b();
            }
            str = c1820i.f2810c.f2832c;
        }
        boolean z = !TextUtils.isEmpty(str);
        long available = this.f2786j.mo1157b() ? this.f2786j.available() : this.f2785i.length();
        boolean z2 = available >= 0;
        boolean z3 = c1815d.f2784e;
        long j2 = z3 ? available - c1815d.f2783d : available;
        boolean z4 = z2 && z3;
        StringBuilder sb = new StringBuilder();
        sb.append(c1815d.f2784e ? "HTTP/1.1 206 PARTIAL CONTENT\n" : "HTTP/1.1 200 OK\n");
        sb.append("Accept-Ranges: bytes\n");
        sb.append(z2 ? m1162g("Content-Length: %d\n", Long.valueOf(j2)) : "");
        sb.append(z4 ? m1162g("Content-Range: bytes %d-%d/%d\n", Long.valueOf(c1815d.f2783d), Long.valueOf(available - 1), Long.valueOf(available)) : "");
        sb.append(z ? m1162g("Content-Type: %s\n", str) : "");
        sb.append("\n");
        bufferedOutputStream.write(sb.toString().getBytes("UTF-8"));
        long j3 = c1815d.f2783d;
        long length = this.f2785i.length();
        if ((((length > 0L ? 1 : (length == 0L ? 0 : -1)) > 0) && c1815d.f2784e && ((float) c1815d.f2783d) > (((float) length) * 0.2f) + ((float) this.f2786j.available())) ? false : true) {
            byte[] bArr = new byte[8192];
            while (true) {
                if (!(j3 >= 0)) {
                    throw new IllegalArgumentException("Data offset must be positive!");
                }
                while (!this.f2822b.mo1157b() && this.f2822b.available() < 8192 + j3 && !this.f2827g) {
                    synchronized (this) {
                        boolean z5 = (this.f2826f == null || this.f2826f.getState() == Thread.State.TERMINATED) ? false : true;
                        if (!this.f2827g && !this.f2822b.mo1157b() && !z5) {
                            this.f2826f = new Thread(new C1824m.b(null), "Source reader for " + this.f2821a);
                            this.f2826f.start();
                        }
                    }
                    synchronized (this.f2823c) {
                        try {
                            this.f2823c.wait(1000L);
                        } catch (InterruptedException e2) {
                            throw new C1825n("Waiting source data is interrupted!", e2);
                        }
                    }
                    int i2 = this.f2825e.get();
                    if (i2 >= 1) {
                        this.f2825e.set(0);
                        throw new C1825n(C1499a.m628n("Error reading source ", i2, " times"));
                    }
                }
                int mo1158c = this.f2822b.mo1158c(bArr, j3, 8192);
                if (this.f2822b.mo1157b() && this.f2828h != 100) {
                    this.f2828h = 100;
                    mo1161d(100);
                }
                if (mo1158c == -1) {
                    bufferedOutputStream.flush();
                    return;
                } else {
                    bufferedOutputStream.write(bArr, 0, mo1158c);
                    j3 += mo1158c;
                }
            }
        } else {
            C1820i c1820i2 = new C1820i(this.f2785i);
            try {
                c1820i2.mo1176a((int) j3);
                byte[] bArr2 = new byte[8192];
                while (true) {
                    int read = c1820i2.read(bArr2);
                    if (read == -1) {
                        bufferedOutputStream.flush();
                        return;
                    }
                    bufferedOutputStream.write(bArr2, 0, read);
                }
            } finally {
                c1820i2.close();
            }
        }
    }
}
