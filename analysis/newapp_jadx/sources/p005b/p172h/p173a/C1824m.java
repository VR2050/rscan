package p005b.p172h.p173a;

import android.text.TextUtils;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.h.a.m */
/* loaded from: classes.dex */
public class C1824m {

    /* renamed from: a */
    public final InterfaceC1827p f2821a;

    /* renamed from: b */
    public final InterfaceC1812a f2822b;

    /* renamed from: e */
    public final AtomicInteger f2825e;

    /* renamed from: f */
    public volatile Thread f2826f;

    /* renamed from: g */
    public volatile boolean f2827g;

    /* renamed from: c */
    public final Object f2823c = new Object();

    /* renamed from: d */
    public final Object f2824d = new Object();

    /* renamed from: h */
    public volatile int f2828h = -1;

    /* renamed from: b.h.a.m$b */
    public class b implements Runnable {
        public b(a aVar) {
        }

        /* JADX WARN: Code restructure failed: missing block: B:13:0x0038, code lost:
        
            r3 = r3 + r6;
         */
        /* JADX WARN: Code restructure failed: missing block: B:26:0x0041, code lost:
        
            r5 = r0.f2824d;
         */
        /* JADX WARN: Code restructure failed: missing block: B:27:0x0043, code lost:
        
            monitor-enter(r5);
         */
        /* JADX WARN: Code restructure failed: missing block: B:30:0x0048, code lost:
        
            if (r0.m1182b() != false) goto L27;
         */
        /* JADX WARN: Code restructure failed: missing block: B:32:0x0058, code lost:
        
            if (r0.f2822b.available() != r0.f2821a.length()) goto L27;
         */
        /* JADX WARN: Code restructure failed: missing block: B:33:0x005a, code lost:
        
            r0.f2822b.complete();
         */
        /* JADX WARN: Code restructure failed: missing block: B:34:0x005f, code lost:
        
            monitor-exit(r5);
         */
        /* JADX WARN: Code restructure failed: missing block: B:36:0x0062, code lost:
        
            r0.f2828h = 100;
            r0.mo1161d(r0.f2828h);
         */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void run() {
            /*
                r11 = this;
                b.h.a.m r0 = p005b.p172h.p173a.C1824m.this
                java.util.Objects.requireNonNull(r0)
                r1 = -1
                r3 = 0
                b.h.a.a r5 = r0.f2822b     // Catch: java.lang.Throwable -> L6d
                long r3 = r5.available()     // Catch: java.lang.Throwable -> L6d
                b.h.a.p r5 = r0.f2821a     // Catch: java.lang.Throwable -> L6d
                r5.mo1176a(r3)     // Catch: java.lang.Throwable -> L6d
                b.h.a.p r5 = r0.f2821a     // Catch: java.lang.Throwable -> L6d
                long r1 = r5.length()     // Catch: java.lang.Throwable -> L6d
                r5 = 8192(0x2000, float:1.148E-41)
                byte[] r5 = new byte[r5]     // Catch: java.lang.Throwable -> L6d
            L1e:
                b.h.a.p r6 = r0.f2821a     // Catch: java.lang.Throwable -> L6d
                int r6 = r6.read(r5)     // Catch: java.lang.Throwable -> L6d
                r7 = -1
                if (r6 == r7) goto L41
                java.lang.Object r7 = r0.f2824d     // Catch: java.lang.Throwable -> L6d
                monitor-enter(r7)     // Catch: java.lang.Throwable -> L6d
                boolean r8 = r0.m1182b()     // Catch: java.lang.Throwable -> L3e
                if (r8 == 0) goto L32
                monitor-exit(r7)     // Catch: java.lang.Throwable -> L3e
                goto L76
            L32:
                b.h.a.a r8 = r0.f2822b     // Catch: java.lang.Throwable -> L3e
                r8.mo1156a(r5, r6)     // Catch: java.lang.Throwable -> L3e
                monitor-exit(r7)     // Catch: java.lang.Throwable -> L3e
                long r6 = (long) r6
                long r3 = r3 + r6
                r0.m1183c(r3, r1)     // Catch: java.lang.Throwable -> L6d
                goto L1e
            L3e:
                r5 = move-exception
                monitor-exit(r7)     // Catch: java.lang.Throwable -> L3e
                throw r5     // Catch: java.lang.Throwable -> L6d
            L41:
                java.lang.Object r5 = r0.f2824d     // Catch: java.lang.Throwable -> L6d
                monitor-enter(r5)     // Catch: java.lang.Throwable -> L6d
                boolean r6 = r0.m1182b()     // Catch: java.lang.Throwable -> L6a
                if (r6 != 0) goto L5f
                b.h.a.a r6 = r0.f2822b     // Catch: java.lang.Throwable -> L6a
                long r6 = r6.available()     // Catch: java.lang.Throwable -> L6a
                b.h.a.p r8 = r0.f2821a     // Catch: java.lang.Throwable -> L6a
                long r8 = r8.length()     // Catch: java.lang.Throwable -> L6a
                int r10 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1))
                if (r10 != 0) goto L5f
                b.h.a.a r6 = r0.f2822b     // Catch: java.lang.Throwable -> L6a
                r6.complete()     // Catch: java.lang.Throwable -> L6a
            L5f:
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L6a
                r5 = 100
                r0.f2828h = r5     // Catch: java.lang.Throwable -> L6d
                int r5 = r0.f2828h     // Catch: java.lang.Throwable -> L6d
                r0.mo1161d(r5)     // Catch: java.lang.Throwable -> L6d
                goto L76
            L6a:
                r6 = move-exception
                monitor-exit(r5)     // Catch: java.lang.Throwable -> L6a
                throw r6     // Catch: java.lang.Throwable -> L6d
            L6d:
                r5 = move-exception
                java.util.concurrent.atomic.AtomicInteger r6 = r0.f2825e     // Catch: java.lang.Throwable -> L7d
                r6.incrementAndGet()     // Catch: java.lang.Throwable -> L7d
                r0.m1184e(r5)     // Catch: java.lang.Throwable -> L7d
            L76:
                r0.m1181a()
                r0.m1183c(r3, r1)
                return
            L7d:
                r5 = move-exception
                r0.m1181a()
                r0.m1183c(r3, r1)
                throw r5
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p172h.p173a.C1824m.b.run():void");
        }
    }

    public C1824m(InterfaceC1827p interfaceC1827p, InterfaceC1812a interfaceC1812a) {
        Objects.requireNonNull(interfaceC1827p);
        this.f2821a = interfaceC1827p;
        Objects.requireNonNull(interfaceC1812a);
        this.f2822b = interfaceC1812a;
        this.f2825e = new AtomicInteger();
    }

    /* renamed from: a */
    public final void m1181a() {
        try {
            this.f2821a.close();
        } catch (C1825n e2) {
            StringBuilder m586H = C1499a.m586H("Error closing source ");
            m586H.append(this.f2821a);
            m1184e(new C1825n(m586H.toString(), e2));
        }
    }

    /* renamed from: b */
    public final boolean m1182b() {
        return Thread.currentThread().isInterrupted() || this.f2827g;
    }

    /* renamed from: c */
    public final void m1183c(long j2, long j3) {
        int i2 = (j3 > 0L ? 1 : (j3 == 0L ? 0 : -1)) == 0 ? 100 : (int) ((j2 / j3) * 100.0f);
        boolean z = i2 != this.f2828h;
        if ((j3 >= 0) && z) {
            mo1161d(i2);
        }
        this.f2828h = i2;
        synchronized (this.f2823c) {
            this.f2823c.notifyAll();
        }
    }

    /* renamed from: d */
    public void mo1161d(int i2) {
        throw null;
    }

    /* renamed from: e */
    public final void m1184e(Throwable th) {
        if (th instanceof C1822k) {
            TextUtils.isEmpty("ProxyCache is interrupted");
        } else {
            TextUtils.isEmpty(th.getMessage());
        }
    }

    /* renamed from: f */
    public void m1185f() {
        synchronized (this.f2824d) {
            try {
                this.f2827g = true;
                if (this.f2826f != null) {
                    this.f2826f.interrupt();
                }
                this.f2822b.close();
            } catch (C1825n e2) {
                m1184e(e2);
            }
        }
    }
}
