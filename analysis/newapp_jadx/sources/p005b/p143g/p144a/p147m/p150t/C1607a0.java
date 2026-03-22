package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1639g;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.t.a0 */
/* loaded from: classes.dex */
public class C1607a0 implements InterfaceC1590d.a<Object> {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC1672n.a f2048c;

    /* renamed from: e */
    public final /* synthetic */ C1609b0 f2049e;

    public C1607a0(C1609b0 c1609b0, InterfaceC1672n.a aVar) {
        this.f2049e = c1609b0;
        this.f2048c = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
    /* renamed from: c */
    public void mo839c(@NonNull Exception exc) {
        C1609b0 c1609b0 = this.f2049e;
        InterfaceC1672n.a<?> aVar = this.f2048c;
        InterfaceC1672n.a<?> aVar2 = c1609b0.f2056i;
        if (aVar2 != null && aVar2 == aVar) {
            C1609b0 c1609b02 = this.f2049e;
            InterfaceC1672n.a aVar3 = this.f2048c;
            InterfaceC1639g.a aVar4 = c1609b02.f2052e;
            InterfaceC1579k interfaceC1579k = c1609b02.f2057j;
            InterfaceC1590d<Data> interfaceC1590d = aVar3.f2383c;
            aVar4.mo853a(interfaceC1579k, exc, interfaceC1590d, interfaceC1590d.getDataSource());
        }
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d.a
    /* renamed from: e */
    public void mo840e(@Nullable Object obj) {
        C1609b0 c1609b0 = this.f2049e;
        InterfaceC1672n.a<?> aVar = this.f2048c;
        InterfaceC1672n.a<?> aVar2 = c1609b0.f2056i;
        if (aVar2 != null && aVar2 == aVar) {
            C1609b0 c1609b02 = this.f2049e;
            InterfaceC1672n.a aVar3 = this.f2048c;
            AbstractC1643k abstractC1643k = c1609b02.f2051c.f2164p;
            if (obj != null && abstractC1643k.mo929c(aVar3.f2383c.getDataSource())) {
                c1609b02.f2055h = obj;
                c1609b02.f2052e.mo855c();
            } else {
                InterfaceC1639g.a aVar4 = c1609b02.f2052e;
                InterfaceC1579k interfaceC1579k = aVar3.f2381a;
                InterfaceC1590d<Data> interfaceC1590d = aVar3.f2383c;
                aVar4.mo856d(interfaceC1579k, obj, interfaceC1590d, interfaceC1590d.getDataSource(), c1609b02.f2057j);
            }
        }
    }
}
