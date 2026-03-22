package p005b.p199l.p258c.p260c0.p261a0;

import com.google.android.material.badge.BadgeDrawable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;

/* renamed from: b.l.c.c0.a0.q */
/* loaded from: classes2.dex */
public final class C2437q implements InterfaceC2415a0 {

    /* renamed from: c */
    public final /* synthetic */ Class f6572c;

    /* renamed from: e */
    public final /* synthetic */ Class f6573e;

    /* renamed from: f */
    public final /* synthetic */ AbstractC2496z f6574f;

    public C2437q(Class cls, Class cls2, AbstractC2496z abstractC2496z) {
        this.f6572c = cls;
        this.f6573e = cls2;
        this.f6574f = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        Class<? super T> rawType = c2470a.getRawType();
        if (rawType == this.f6572c || rawType == this.f6573e) {
            return this.f6574f;
        }
        return null;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Factory[type=");
        m586H.append(this.f6573e.getName());
        m586H.append(BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX);
        m586H.append(this.f6572c.getName());
        m586H.append(",adapter=");
        m586H.append(this.f6574f);
        m586H.append("]");
        return m586H.toString();
    }
}
