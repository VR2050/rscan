package p476m.p477a.p485b.p488j0.p490i;

import p476m.p477a.p485b.C4793b0;
import p476m.p477a.p485b.InterfaceC4891n;
import p476m.p477a.p485b.p487i0.InterfaceC4811d;

/* renamed from: m.a.b.j0.i.a */
/* loaded from: classes3.dex */
public class C4827a implements InterfaceC4811d {

    /* renamed from: a */
    public static final C4827a f12362a = new C4827a(new C4828b(0));

    /* renamed from: b */
    public final InterfaceC4811d f12363b;

    public C4827a(InterfaceC4811d interfaceC4811d) {
        this.f12363b = interfaceC4811d;
    }

    @Override // p476m.p477a.p485b.p487i0.InterfaceC4811d
    /* renamed from: a */
    public long mo5479a(InterfaceC4891n interfaceC4891n) {
        long mo5479a = this.f12363b.mo5479a(interfaceC4891n);
        if (mo5479a != -1) {
            return mo5479a;
        }
        throw new C4793b0("Identity transfer encoding cannot be used");
    }
}
