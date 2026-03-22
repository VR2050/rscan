package p005b.p143g.p144a.p147m.p150t.p152d0;

import android.util.Log;
import java.io.File;
import java.io.IOException;
import p005b.p143g.p144a.p145k.C1561a;
import p005b.p143g.p144a.p145k.C1563c;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.C1638f;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1627c;
import p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1625a;

/* renamed from: b.g.a.m.t.d0.e */
/* loaded from: classes.dex */
public class C1629e implements InterfaceC1625a {

    /* renamed from: b */
    public final File f2113b;

    /* renamed from: c */
    public final long f2114c;

    /* renamed from: e */
    public C1561a f2116e;

    /* renamed from: d */
    public final C1627c f2115d = new C1627c();

    /* renamed from: a */
    public final C1635k f2112a = new C1635k();

    @Deprecated
    public C1629e(File file, long j2) {
        this.f2113b = file;
        this.f2114c = j2;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1625a
    /* renamed from: a */
    public void mo894a(InterfaceC1579k interfaceC1579k, InterfaceC1625a.b bVar) {
        C1627c.a aVar;
        boolean z;
        String m902a = this.f2112a.m902a(interfaceC1579k);
        C1627c c1627c = this.f2115d;
        synchronized (c1627c) {
            aVar = c1627c.f2105a.get(m902a);
            if (aVar == null) {
                C1627c.b bVar2 = c1627c.f2106b;
                synchronized (bVar2.f2109a) {
                    aVar = bVar2.f2109a.poll();
                }
                if (aVar == null) {
                    aVar = new C1627c.a();
                }
                c1627c.f2105a.put(m902a, aVar);
            }
            aVar.f2108b++;
        }
        aVar.f2107a.lock();
        try {
            if (Log.isLoggable("DiskLruCacheWrapper", 2)) {
                String str = "Put: Obtained: " + m902a + " for for Key: " + interfaceC1579k;
            }
            try {
                C1561a m897c = m897c();
                if (m897c.m795s(m902a) == null) {
                    C1561a.c m794o = m897c.m794o(m902a);
                    if (m794o == null) {
                        throw new IllegalStateException("Had two simultaneous puts for: " + m902a);
                    }
                    try {
                        C1638f c1638f = (C1638f) bVar;
                        if (c1638f.f2146a.mo822a(c1638f.f2147b, m794o.m798b(0), c1638f.f2148c)) {
                            C1561a.m783b(C1561a.this, m794o, true);
                            m794o.f1904c = true;
                        }
                        if (!z) {
                            try {
                                m794o.m797a();
                            } catch (IOException unused) {
                            }
                        }
                    } finally {
                        if (!m794o.f1904c) {
                            try {
                                m794o.m797a();
                            } catch (IOException unused2) {
                            }
                        }
                    }
                }
            } catch (IOException unused3) {
                Log.isLoggable("DiskLruCacheWrapper", 5);
            }
        } finally {
            this.f2115d.m896a(m902a);
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1625a
    /* renamed from: b */
    public File mo895b(InterfaceC1579k interfaceC1579k) {
        String m902a = this.f2112a.m902a(interfaceC1579k);
        if (Log.isLoggable("DiskLruCacheWrapper", 2)) {
            String str = "Get: Obtained: " + m902a + " for for Key: " + interfaceC1579k;
        }
        try {
            C1561a.e m795s = m897c().m795s(m902a);
            if (m795s != null) {
                return m795s.f1914a[0];
            }
            return null;
        } catch (IOException unused) {
            Log.isLoggable("DiskLruCacheWrapper", 5);
            return null;
        }
    }

    /* renamed from: c */
    public final synchronized C1561a m897c() {
        if (this.f2116e == null) {
            this.f2116e = C1561a.m787v(this.f2113b, 1, 1, this.f2114c);
        }
        return this.f2116e;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1625a
    public synchronized void clear() {
        try {
            try {
                C1561a m897c = m897c();
                m897c.close();
                C1563c.m803a(m897c.f1887c);
            } catch (IOException unused) {
                Log.isLoggable("DiskLruCacheWrapper", 5);
            }
        } finally {
            m898d();
        }
    }

    /* renamed from: d */
    public final synchronized void m898d() {
        this.f2116e = null;
    }
}
