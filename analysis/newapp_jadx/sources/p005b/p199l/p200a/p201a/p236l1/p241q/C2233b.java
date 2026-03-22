package p005b.p199l.p200a.p201a.p236l1.p241q;

import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.q.b */
/* loaded from: classes.dex */
public final class C2233b implements InterfaceC2210e {

    /* renamed from: c */
    public final C2207b[] f5490c;

    /* renamed from: e */
    public final long[] f5491e;

    public C2233b(C2207b[] c2207bArr, long[] jArr) {
        this.f5490c = c2207bArr;
        this.f5491e = jArr;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: a */
    public int mo2048a(long j2) {
        int m2324b = C2344d0.m2324b(this.f5491e, j2, false, false);
        if (m2324b < this.f5491e.length) {
            return m2324b;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: b */
    public long mo2049b(int i2) {
        C4195m.m4765F(i2 >= 0);
        C4195m.m4765F(i2 < this.f5491e.length);
        return this.f5491e[i2];
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: c */
    public List<C2207b> mo2050c(long j2) {
        int m2326d = C2344d0.m2326d(this.f5491e, j2, true, false);
        if (m2326d != -1) {
            C2207b[] c2207bArr = this.f5490c;
            if (c2207bArr[m2326d] != C2207b.f5274c) {
                return Collections.singletonList(c2207bArr[m2326d]);
            }
        }
        return Collections.emptyList();
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        return this.f5491e.length;
    }
}
