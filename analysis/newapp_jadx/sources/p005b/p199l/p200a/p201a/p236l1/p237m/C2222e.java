package p005b.p199l.p200a.p201a.p236l1.p237m;

import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.m.e */
/* loaded from: classes.dex */
public final class C2222e implements InterfaceC2210e {

    /* renamed from: c */
    public final List<C2207b> f5397c;

    public C2222e(List<C2207b> list) {
        this.f5397c = list;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: a */
    public int mo2048a(long j2) {
        return j2 < 0 ? 0 : -1;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: b */
    public long mo2049b(int i2) {
        C4195m.m4765F(i2 == 0);
        return 0L;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: c */
    public List<C2207b> mo2050c(long j2) {
        return j2 >= 0 ? this.f5397c : Collections.emptyList();
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        return 1;
    }
}
