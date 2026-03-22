package p005b.p199l.p258c.p260c0.p261a0;

import java.lang.reflect.Field;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.p260c0.p261a0.C2430j;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.c0.a0.i */
/* loaded from: classes2.dex */
public class C2429i extends C2430j.b {

    /* renamed from: d */
    public final /* synthetic */ Field f6486d;

    /* renamed from: e */
    public final /* synthetic */ boolean f6487e;

    /* renamed from: f */
    public final /* synthetic */ AbstractC2496z f6488f;

    /* renamed from: g */
    public final /* synthetic */ C2480j f6489g;

    /* renamed from: h */
    public final /* synthetic */ C2470a f6490h;

    /* renamed from: i */
    public final /* synthetic */ boolean f6491i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2429i(C2430j c2430j, String str, boolean z, boolean z2, Field field, boolean z3, AbstractC2496z abstractC2496z, C2480j c2480j, C2470a c2470a, boolean z4) {
        super(str, z, z2);
        this.f6486d = field;
        this.f6487e = z3;
        this.f6488f = abstractC2496z;
        this.f6489g = c2480j;
        this.f6490h = c2470a;
        this.f6491i = z4;
    }

    @Override // p005b.p199l.p258c.p260c0.p261a0.C2430j.b
    /* renamed from: a */
    public void mo2801a(C2472a c2472a, Object obj) {
        Object mo2766b = this.f6488f.mo2766b(c2472a);
        if (mo2766b == null && this.f6491i) {
            return;
        }
        this.f6486d.set(obj, mo2766b);
    }

    @Override // p005b.p199l.p258c.p260c0.p261a0.C2430j.b
    /* renamed from: b */
    public void mo2802b(C2474c c2474c, Object obj) {
        (this.f6487e ? this.f6488f : new C2434n(this.f6489g, this.f6488f, this.f6490h.getType())).mo2767c(c2474c, this.f6486d.get(obj));
    }

    @Override // p005b.p199l.p258c.p260c0.p261a0.C2430j.b
    /* renamed from: c */
    public boolean mo2803c(Object obj) {
        return this.f6500b && this.f6486d.get(obj) != obj;
    }
}
