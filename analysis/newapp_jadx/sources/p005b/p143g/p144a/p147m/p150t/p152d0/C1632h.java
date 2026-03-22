package p005b.p143g.p144a.p147m.p150t.p152d0;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1633i;
import p005b.p143g.p144a.p170s.C1804f;

/* renamed from: b.g.a.m.t.d0.h */
/* loaded from: classes.dex */
public class C1632h extends C1804f<InterfaceC1579k, InterfaceC1655w<?>> implements InterfaceC1633i {

    /* renamed from: d */
    public InterfaceC1633i.a f2119d;

    public C1632h(long j2) {
        super(j2);
    }

    @Override // p005b.p143g.p144a.p170s.C1804f
    /* renamed from: b */
    public int mo899b(@Nullable InterfaceC1655w<?> interfaceC1655w) {
        InterfaceC1655w<?> interfaceC1655w2 = interfaceC1655w;
        if (interfaceC1655w2 == null) {
            return 1;
        }
        return interfaceC1655w2.getSize();
    }

    @Override // p005b.p143g.p144a.p170s.C1804f
    /* renamed from: c */
    public void mo900c(@NonNull InterfaceC1579k interfaceC1579k, @Nullable InterfaceC1655w<?> interfaceC1655w) {
        InterfaceC1655w<?> interfaceC1655w2 = interfaceC1655w;
        InterfaceC1633i.a aVar = this.f2119d;
        if (aVar == null || interfaceC1655w2 == null) {
            return;
        }
        ((C1644l) aVar).f2231f.m959a(interfaceC1655w2, true);
    }
}
