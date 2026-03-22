package p005b.p199l.p258c;

import java.util.concurrent.atomic.AtomicLong;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.h */
/* loaded from: classes2.dex */
public final class C2478h extends AbstractC2496z<AtomicLong> {

    /* renamed from: a */
    public final /* synthetic */ AbstractC2496z f6677a;

    public C2478h(AbstractC2496z abstractC2496z) {
        this.f6677a = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public AtomicLong mo2766b(C2472a c2472a) {
        return new AtomicLong(((Number) this.f6677a.mo2766b(c2472a)).longValue());
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, AtomicLong atomicLong) {
        this.f6677a.mo2767c(c2474c, Long.valueOf(atomicLong.get()));
    }
}
