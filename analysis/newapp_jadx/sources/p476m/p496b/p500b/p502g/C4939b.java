package p476m.p496b.p500b.p502g;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import p476m.p496b.p500b.p503h.C4944c;

/* renamed from: m.b.b.g.b */
/* loaded from: classes3.dex */
public class C4939b<T> implements InterfaceC4938a<Long, T> {

    /* renamed from: a */
    public final C4944c<Reference<T>> f12589a = new C4944c<>();

    /* renamed from: b */
    public final ReentrantLock f12590b = new ReentrantLock();

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /* renamed from: a */
    public void mo5606a(Long l2, Object obj) {
        this.f12589a.m5613b(l2.longValue(), new WeakReference(obj));
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /* renamed from: b */
    public Object mo5607b(Long l2) {
        Reference<T> m5612a = this.f12589a.m5612a(l2.longValue());
        if (m5612a != null) {
            return m5612a.get();
        }
        return null;
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /* renamed from: c */
    public void mo5608c(int i2) {
        C4944c<Reference<T>> c4944c = this.f12589a;
        Objects.requireNonNull(c4944c);
        c4944c.m5614c((i2 * 5) / 3);
    }

    /* renamed from: d */
    public T m5609d(long j2) {
        this.f12590b.lock();
        try {
            Reference<T> m5612a = this.f12589a.m5612a(j2);
            if (m5612a != null) {
                return m5612a.get();
            }
            return null;
        } finally {
            this.f12590b.unlock();
        }
    }

    /* renamed from: e */
    public void m5610e(long j2, T t) {
        this.f12590b.lock();
        try {
            this.f12589a.m5613b(j2, new WeakReference(t));
        } finally {
            this.f12590b.unlock();
        }
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public Object get(Long l2) {
        return m5609d(l2.longValue());
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void lock() {
        this.f12590b.lock();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void put(Long l2, Object obj) {
        m5610e(l2.longValue(), obj);
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x002c, code lost:
    
        ((p476m.p496b.p500b.p503h.C4944c.a<java.lang.ref.Reference<T>>[]) r0.f12609a)[r10] = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0033, code lost:
    
        r0.f12612d--;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0031, code lost:
    
        r4.f12615c = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x002a, code lost:
    
        if (r4 != null) goto L9;
     */
    /* JADX WARN: Multi-variable type inference failed */
    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void remove(java.lang.Long r10) {
        /*
            r9 = this;
            java.lang.Long r10 = (java.lang.Long) r10
            java.util.concurrent.locks.ReentrantLock r0 = r9.f12590b
            r0.lock()
            m.b.b.h.c<java.lang.ref.Reference<T>> r0 = r9.f12589a     // Catch: java.lang.Throwable -> L43
            long r1 = r10.longValue()     // Catch: java.lang.Throwable -> L43
            r10 = 32
            long r3 = r1 >>> r10
            int r10 = (int) r3     // Catch: java.lang.Throwable -> L43
            int r3 = (int) r1     // Catch: java.lang.Throwable -> L43
            r10 = r10 ^ r3
            r3 = 2147483647(0x7fffffff, float:NaN)
            r10 = r10 & r3
            int r3 = r0.f12610b     // Catch: java.lang.Throwable -> L43
            int r10 = r10 % r3
            m.b.b.h.c$a<T>[] r3 = r0.f12609a     // Catch: java.lang.Throwable -> L43
            r3 = r3[r10]     // Catch: java.lang.Throwable -> L43
            r4 = 0
        L20:
            if (r3 == 0) goto L3d
            m.b.b.h.c$a<T> r5 = r3.f12615c     // Catch: java.lang.Throwable -> L43
            long r6 = r3.f12613a     // Catch: java.lang.Throwable -> L43
            int r8 = (r6 > r1 ? 1 : (r6 == r1 ? 0 : -1))
            if (r8 != 0) goto L3a
            if (r4 != 0) goto L31
            m.b.b.h.c$a<T>[] r1 = r0.f12609a     // Catch: java.lang.Throwable -> L43
            r1[r10] = r5     // Catch: java.lang.Throwable -> L43
            goto L33
        L31:
            r4.f12615c = r5     // Catch: java.lang.Throwable -> L43
        L33:
            int r10 = r0.f12612d     // Catch: java.lang.Throwable -> L43
            int r10 = r10 + (-1)
            r0.f12612d = r10     // Catch: java.lang.Throwable -> L43
            goto L3d
        L3a:
            r4 = r3
            r3 = r5
            goto L20
        L3d:
            java.util.concurrent.locks.ReentrantLock r10 = r9.f12590b
            r10.unlock()
            return
        L43:
            r10 = move-exception
            java.util.concurrent.locks.ReentrantLock r0 = r9.f12590b
            r0.unlock()
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: p476m.p496b.p500b.p502g.C4939b.remove(java.lang.Object):void");
    }

    @Override // p476m.p496b.p500b.p502g.InterfaceC4938a
    public void unlock() {
        this.f12590b.unlock();
    }
}
