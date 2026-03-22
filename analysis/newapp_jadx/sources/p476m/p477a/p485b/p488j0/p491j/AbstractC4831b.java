package p476m.p477a.p485b.p488j0.p491j;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4891n;
import p476m.p477a.p485b.p492k0.InterfaceC4851e;
import p476m.p477a.p485b.p493l0.C4860h;
import p476m.p477a.p485b.p493l0.InterfaceC4869q;
import p476m.p477a.p485b.p495n0.C4893b;

/* renamed from: m.a.b.j0.j.b */
/* loaded from: classes3.dex */
public abstract class AbstractC4831b<T extends InterfaceC4891n> {

    /* renamed from: a */
    public final InterfaceC4851e f12373a;

    /* renamed from: b */
    public final C4893b f12374b;

    /* renamed from: c */
    public final InterfaceC4869q f12375c;

    public AbstractC4831b(InterfaceC4851e interfaceC4851e, InterfaceC4869q interfaceC4869q) {
        C2354n.m2470e1(interfaceC4851e, "Session input buffer");
        this.f12373a = interfaceC4851e;
        this.f12375c = interfaceC4869q == null ? C4860h.f12449a : interfaceC4869q;
        this.f12374b = new C4893b(128);
    }
}
