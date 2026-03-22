package p005b.p199l.p258c.p260c0.p261a0;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;

/* renamed from: b.l.c.c0.a0.p */
/* loaded from: classes2.dex */
public final class C2436p implements InterfaceC2415a0 {

    /* renamed from: c */
    public final /* synthetic */ Class f6570c;

    /* renamed from: e */
    public final /* synthetic */ AbstractC2496z f6571e;

    public C2436p(Class cls, AbstractC2496z abstractC2496z) {
        this.f6570c = cls;
        this.f6571e = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        if (c2470a.getRawType() == this.f6570c) {
            return this.f6571e;
        }
        return null;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Factory[type=");
        m586H.append(this.f6570c.getName());
        m586H.append(",adapter=");
        m586H.append(this.f6571e);
        m586H.append("]");
        return m586H.toString();
    }
}
