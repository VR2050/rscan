package p005b.p199l.p200a.p201a.p236l1.p243s;

import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.s.b */
/* loaded from: classes.dex */
public final class C2240b implements InterfaceC2210e {

    /* renamed from: c */
    public static final C2240b f5553c = new C2240b();

    /* renamed from: e */
    public final List<C2207b> f5554e;

    public C2240b(C2207b c2207b) {
        this.f5554e = Collections.singletonList(c2207b);
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
        return j2 >= 0 ? this.f5554e : Collections.emptyList();
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        return 1;
    }

    public C2240b() {
        this.f5554e = Collections.emptyList();
    }
}
