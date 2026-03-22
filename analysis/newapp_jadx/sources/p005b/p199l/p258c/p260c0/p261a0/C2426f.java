package p005b.p199l.p258c.p260c0.p261a0;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p258c.AbstractC2485o;
import p005b.p199l.p258c.C2482l;
import p005b.p199l.p258c.C2487q;
import p005b.p199l.p258c.C2488r;
import p005b.p199l.p258c.C2490t;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.c0.a0.f */
/* loaded from: classes2.dex */
public final class C2426f extends C2474c {

    /* renamed from: o */
    public static final Writer f6473o = new a();

    /* renamed from: p */
    public static final C2490t f6474p = new C2490t("closed");

    /* renamed from: q */
    public final List<AbstractC2485o> f6475q;

    /* renamed from: r */
    public String f6476r;

    /* renamed from: s */
    public AbstractC2485o f6477s;

    /* renamed from: b.l.c.c0.a0.f$a */
    public static class a extends Writer {
        @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            throw new AssertionError();
        }

        @Override // java.io.Writer, java.io.Flushable
        public void flush() {
            throw new AssertionError();
        }

        @Override // java.io.Writer
        public void write(char[] cArr, int i2, int i3) {
            throw new AssertionError();
        }
    }

    public C2426f() {
        super(f6473o);
        this.f6475q = new ArrayList();
        this.f6477s = C2487q.f6695a;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: P */
    public C2474c mo2788P(long j2) {
        m2794Z(new C2490t(Long.valueOf(j2)));
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: S */
    public C2474c mo2789S(Boolean bool) {
        if (bool == null) {
            m2794Z(C2487q.f6695a);
            return this;
        }
        m2794Z(new C2490t(bool));
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: U */
    public C2474c mo2790U(Number number) {
        if (number == null) {
            m2794Z(C2487q.f6695a);
            return this;
        }
        if (!this.f6673k) {
            double doubleValue = number.doubleValue();
            if (Double.isNaN(doubleValue) || Double.isInfinite(doubleValue)) {
                throw new IllegalArgumentException("JSON forbids NaN and infinities: " + number);
            }
        }
        m2794Z(new C2490t(number));
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: V */
    public C2474c mo2791V(String str) {
        if (str == null) {
            m2794Z(C2487q.f6695a);
            return this;
        }
        m2794Z(new C2490t(str));
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: W */
    public C2474c mo2792W(boolean z) {
        m2794Z(new C2490t(Boolean.valueOf(z)));
        return this;
    }

    /* renamed from: Y */
    public final AbstractC2485o m2793Y() {
        return this.f6475q.get(r0.size() - 1);
    }

    /* renamed from: Z */
    public final void m2794Z(AbstractC2485o abstractC2485o) {
        if (this.f6476r != null) {
            if (!(abstractC2485o instanceof C2487q) || this.f6676n) {
                C2488r c2488r = (C2488r) m2793Y();
                c2488r.f6696a.put(this.f6476r, abstractC2485o);
            }
            this.f6476r = null;
            return;
        }
        if (this.f6475q.isEmpty()) {
            this.f6477s = abstractC2485o;
            return;
        }
        AbstractC2485o m2793Y = m2793Y();
        if (!(m2793Y instanceof C2482l)) {
            throw new IllegalStateException();
        }
        ((C2482l) m2793Y).f6694c.add(abstractC2485o);
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (!this.f6475q.isEmpty()) {
            throw new IOException("Incomplete document");
        }
        this.f6475q.add(f6474p);
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: d */
    public C2474c mo2795d() {
        C2482l c2482l = new C2482l();
        m2794Z(c2482l);
        this.f6475q.add(c2482l);
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: e */
    public C2474c mo2796e() {
        C2488r c2488r = new C2488r();
        m2794Z(c2488r);
        this.f6475q.add(c2488r);
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c, java.io.Flushable
    public void flush() {
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: o */
    public C2474c mo2797o() {
        if (this.f6475q.isEmpty() || this.f6476r != null) {
            throw new IllegalStateException();
        }
        if (!(m2793Y() instanceof C2482l)) {
            throw new IllegalStateException();
        }
        this.f6475q.remove(r0.size() - 1);
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: q */
    public C2474c mo2798q() {
        if (this.f6475q.isEmpty() || this.f6476r != null) {
            throw new IllegalStateException();
        }
        if (!(m2793Y() instanceof C2488r)) {
            throw new IllegalStateException();
        }
        this.f6475q.remove(r0.size() - 1);
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: s */
    public C2474c mo2799s(String str) {
        if (this.f6475q.isEmpty() || this.f6476r != null) {
            throw new IllegalStateException();
        }
        if (!(m2793Y() instanceof C2488r)) {
            throw new IllegalStateException();
        }
        this.f6476r = str;
        return this;
    }

    @Override // p005b.p199l.p258c.p265e0.C2474c
    /* renamed from: v */
    public C2474c mo2800v() {
        m2794Z(C2487q.f6695a);
        return this;
    }
}
