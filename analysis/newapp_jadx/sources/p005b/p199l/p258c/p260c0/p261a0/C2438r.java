package p005b.p199l.p258c.p260c0.p261a0;

import com.google.android.material.badge.BadgeDrawable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;

/* renamed from: b.l.c.c0.a0.r */
/* loaded from: classes2.dex */
public final class C2438r implements InterfaceC2415a0 {

    /* renamed from: c */
    public final /* synthetic */ Class f6575c;

    /* renamed from: e */
    public final /* synthetic */ Class f6576e;

    /* renamed from: f */
    public final /* synthetic */ AbstractC2496z f6577f;

    public C2438r(Class cls, Class cls2, AbstractC2496z abstractC2496z) {
        this.f6575c = cls;
        this.f6576e = cls2;
        this.f6577f = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        Class<? super T> rawType = c2470a.getRawType();
        if (rawType == this.f6575c || rawType == this.f6576e) {
            return this.f6577f;
        }
        return null;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Factory[type=");
        m586H.append(this.f6575c.getName());
        m586H.append(BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX);
        m586H.append(this.f6576e.getName());
        m586H.append(",adapter=");
        m586H.append(this.f6577f);
        m586H.append("]");
        return m586H.toString();
    }
}
