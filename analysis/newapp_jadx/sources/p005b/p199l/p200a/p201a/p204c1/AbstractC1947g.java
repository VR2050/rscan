package p005b.p199l.p200a.p201a.p204c1;

import androidx.annotation.CallSuper;
import androidx.annotation.Nullable;
import java.lang.Exception;
import java.util.ArrayDeque;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p204c1.AbstractC1946f;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2209d;
import p005b.p199l.p200a.p201a.p236l1.C2212g;
import p005b.p199l.p200a.p201a.p236l1.C2214i;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.c1.g */
/* loaded from: classes.dex */
public abstract class AbstractC1947g<I extends C1945e, O extends AbstractC1946f, E extends Exception> implements InterfaceC1943c<I, O, E> {

    /* renamed from: a */
    public final Thread f3310a;

    /* renamed from: b */
    public final Object f3311b = new Object();

    /* renamed from: c */
    public final ArrayDeque<I> f3312c = new ArrayDeque<>();

    /* renamed from: d */
    public final ArrayDeque<O> f3313d = new ArrayDeque<>();

    /* renamed from: e */
    public final I[] f3314e;

    /* renamed from: f */
    public final O[] f3315f;

    /* renamed from: g */
    public int f3316g;

    /* renamed from: h */
    public int f3317h;

    /* renamed from: i */
    public I f3318i;

    /* renamed from: j */
    public E f3319j;

    /* renamed from: k */
    public boolean f3320k;

    /* renamed from: l */
    public boolean f3321l;

    /* renamed from: m */
    public int f3322m;

    /* renamed from: b.l.a.a.c1.g$a */
    public class a extends Thread {
        public a() {
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            AbstractC1947g abstractC1947g = AbstractC1947g.this;
            Objects.requireNonNull(abstractC1947g);
            do {
                try {
                } catch (InterruptedException e2) {
                    throw new IllegalStateException(e2);
                }
            } while (abstractC1947g.m1384f());
        }
    }

    public AbstractC1947g(I[] iArr, O[] oArr) {
        this.f3314e = iArr;
        this.f3316g = iArr.length;
        for (int i2 = 0; i2 < this.f3316g; i2++) {
            this.f3314e[i2] = new C2214i();
        }
        this.f3315f = oArr;
        this.f3317h = oArr.length;
        for (int i3 = 0; i3 < this.f3317h; i3++) {
            this.f3315f[i3] = new C2209d((AbstractC2208c) this);
        }
        a aVar = new a();
        this.f3310a = aVar;
        aVar.start();
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    @Nullable
    /* renamed from: b */
    public Object mo1377b() {
        O removeFirst;
        synchronized (this.f3311b) {
            m1386h();
            removeFirst = this.f3313d.isEmpty() ? null : this.f3313d.removeFirst();
        }
        return removeFirst;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    @Nullable
    /* renamed from: c */
    public Object mo1378c() {
        I i2;
        synchronized (this.f3311b) {
            m1386h();
            C4195m.m4771I(this.f3318i == null);
            int i3 = this.f3316g;
            if (i3 == 0) {
                i2 = null;
            } else {
                I[] iArr = this.f3314e;
                int i4 = i3 - 1;
                this.f3316g = i4;
                i2 = iArr[i4];
            }
            this.f3318i = i2;
        }
        return i2;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    /* renamed from: d */
    public void mo1379d(Object obj) {
        C1945e c1945e = (C1945e) obj;
        synchronized (this.f3311b) {
            m1386h();
            C4195m.m4765F(c1945e == this.f3318i);
            this.f3312c.addLast(c1945e);
            m1385g();
            this.f3318i = null;
        }
    }

    @Nullable
    /* renamed from: e */
    public abstract E mo1383e(I i2, O o, boolean z);

    /* renamed from: f */
    public final boolean m1384f() {
        synchronized (this.f3311b) {
            while (!this.f3321l) {
                if (!this.f3312c.isEmpty() && this.f3317h > 0) {
                    break;
                }
                this.f3311b.wait();
            }
            if (this.f3321l) {
                return false;
            }
            I removeFirst = this.f3312c.removeFirst();
            O[] oArr = this.f3315f;
            int i2 = this.f3317h - 1;
            this.f3317h = i2;
            O o = oArr[i2];
            boolean z = this.f3320k;
            this.f3320k = false;
            if (removeFirst.isEndOfStream()) {
                o.addFlag(4);
            } else {
                if (removeFirst.isDecodeOnly()) {
                    o.addFlag(Integer.MIN_VALUE);
                }
                try {
                    this.f3319j = mo1383e(removeFirst, o, z);
                } catch (OutOfMemoryError e2) {
                    this.f3319j = new C2212g("Unexpected decode error", e2);
                } catch (RuntimeException e3) {
                    this.f3319j = new C2212g("Unexpected decode error", e3);
                }
                if (this.f3319j != null) {
                    synchronized (this.f3311b) {
                    }
                    return false;
                }
            }
            synchronized (this.f3311b) {
                if (this.f3320k) {
                    o.release();
                } else if (o.isDecodeOnly()) {
                    this.f3322m++;
                    o.release();
                } else {
                    o.skippedOutputBufferCount = this.f3322m;
                    this.f3322m = 0;
                    this.f3313d.addLast(o);
                }
                m1387i(removeFirst);
            }
            return true;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    public final void flush() {
        synchronized (this.f3311b) {
            this.f3320k = true;
            this.f3322m = 0;
            I i2 = this.f3318i;
            if (i2 != null) {
                m1387i(i2);
                this.f3318i = null;
            }
            while (!this.f3312c.isEmpty()) {
                m1387i(this.f3312c.removeFirst());
            }
            while (!this.f3313d.isEmpty()) {
                this.f3313d.removeFirst().release();
            }
        }
    }

    /* renamed from: g */
    public final void m1385g() {
        if (!this.f3312c.isEmpty() && this.f3317h > 0) {
            this.f3311b.notify();
        }
    }

    /* renamed from: h */
    public final void m1386h() {
        E e2 = this.f3319j;
        if (e2 != null) {
            throw e2;
        }
    }

    /* renamed from: i */
    public final void m1387i(I i2) {
        i2.clear();
        I[] iArr = this.f3314e;
        int i3 = this.f3316g;
        this.f3316g = i3 + 1;
        iArr[i3] = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.InterfaceC1943c
    @CallSuper
    public void release() {
        synchronized (this.f3311b) {
            this.f3321l = true;
            this.f3311b.notify();
        }
        try {
            this.f3310a.join();
        } catch (InterruptedException unused) {
            Thread.currentThread().interrupt();
        }
    }
}
