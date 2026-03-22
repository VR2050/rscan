package p005b.p199l.p258c.p260c0.p261a0;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.C2495y;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.InterfaceC2484n;
import p005b.p199l.p258c.InterfaceC2492v;
import p005b.p199l.p258c.p259b0.InterfaceC2417a;
import p005b.p199l.p258c.p260c0.C2449g;
import p005b.p199l.p258c.p264d0.C2470a;

/* renamed from: b.l.c.c0.a0.d */
/* loaded from: classes2.dex */
public final class C2424d implements InterfaceC2415a0 {

    /* renamed from: c */
    public final C2449g f6467c;

    public C2424d(C2449g c2449g) {
        this.f6467c = c2449g;
    }

    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
        InterfaceC2417a interfaceC2417a = (InterfaceC2417a) c2470a.getRawType().getAnnotation(InterfaceC2417a.class);
        if (interfaceC2417a == null) {
            return null;
        }
        return (AbstractC2496z<T>) m2768b(this.f6467c, c2480j, c2470a, interfaceC2417a);
    }

    /* renamed from: b */
    public AbstractC2496z<?> m2768b(C2449g c2449g, C2480j c2480j, C2470a<?> c2470a, InterfaceC2417a interfaceC2417a) {
        AbstractC2496z<?> c2433m;
        Object mo2810a = c2449g.m2812a(C2470a.get((Class) interfaceC2417a.value())).mo2810a();
        if (mo2810a instanceof AbstractC2496z) {
            c2433m = (AbstractC2496z) mo2810a;
        } else if (mo2810a instanceof InterfaceC2415a0) {
            c2433m = ((InterfaceC2415a0) mo2810a).mo2753a(c2480j, c2470a);
        } else {
            boolean z = mo2810a instanceof InterfaceC2492v;
            if (!z && !(mo2810a instanceof InterfaceC2484n)) {
                StringBuilder m586H = C1499a.m586H("Invalid attempt to bind an instance of ");
                m586H.append(mo2810a.getClass().getName());
                m586H.append(" as a @JsonAdapter for ");
                m586H.append(c2470a.toString());
                m586H.append(". @JsonAdapter value must be a TypeAdapter, TypeAdapterFactory, JsonSerializer or JsonDeserializer.");
                throw new IllegalArgumentException(m586H.toString());
            }
            c2433m = new C2433m<>(z ? (InterfaceC2492v) mo2810a : null, mo2810a instanceof InterfaceC2484n ? (InterfaceC2484n) mo2810a : null, c2480j, c2470a, null);
        }
        return (c2433m == null || !interfaceC2417a.nullSafe()) ? c2433m : new C2495y(c2433m);
    }
}
