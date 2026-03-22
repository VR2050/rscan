package p005b.p199l.p258c;

import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: b.l.c.y */
/* loaded from: classes2.dex */
public class C2495y<T> extends AbstractC2496z<T> {

    /* renamed from: a */
    public final /* synthetic */ AbstractC2496z f6702a;

    public C2495y(AbstractC2496z abstractC2496z) {
        this.f6702a = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public T mo2766b(C2472a c2472a) {
        if (c2472a.mo2777Z() != EnumC2473b.NULL) {
            return (T) this.f6702a.mo2766b(c2472a);
        }
        c2472a.mo2775V();
        return null;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, T t) {
        if (t == null) {
            c2474c.mo2800v();
        } else {
            this.f6702a.mo2767c(c2474c, t);
        }
    }
}
