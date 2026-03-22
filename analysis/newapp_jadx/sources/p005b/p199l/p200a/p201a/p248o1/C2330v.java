package p005b.p199l.p200a.p201a.p248o1;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.o1.v */
/* loaded from: classes.dex */
public final class C2330v extends InterfaceC2333y.a {

    /* renamed from: a */
    public final String f6007a;

    /* renamed from: b */
    @Nullable
    public final InterfaceC2291f0 f6008b;

    /* renamed from: c */
    public final int f6009c;

    /* renamed from: d */
    public final int f6010d;

    /* renamed from: e */
    public final boolean f6011e;

    public C2330v(String str, @Nullable InterfaceC2291f0 interfaceC2291f0, int i2, int i3, boolean z) {
        C4195m.m4769H(str);
        this.f6007a = str;
        this.f6008b = interfaceC2291f0;
        this.f6009c = i2;
        this.f6010d = i3;
        this.f6011e = z;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y.a
    public InterfaceC2333y createDataSourceInternal(InterfaceC2333y.e eVar) {
        C2329u c2329u = new C2329u(this.f6007a, this.f6009c, this.f6010d, this.f6011e, eVar);
        InterfaceC2291f0 interfaceC2291f0 = this.f6008b;
        if (interfaceC2291f0 != null) {
            c2329u.addTransferListener(interfaceC2291f0);
        }
        return c2329u;
    }
}
