package p005b.p199l.p200a.p201a.p236l1.p240p;

import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.p.d */
/* loaded from: classes.dex */
public final class C2231d implements InterfaceC2210e {

    /* renamed from: c */
    public final List<List<C2207b>> f5484c;

    /* renamed from: e */
    public final List<Long> f5485e;

    public C2231d(List<List<C2207b>> list, List<Long> list2) {
        this.f5484c = list;
        this.f5485e = list2;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: a */
    public int mo2048a(long j2) {
        int i2;
        List<Long> list = this.f5485e;
        Long valueOf = Long.valueOf(j2);
        int i3 = C2344d0.f6035a;
        int binarySearch = Collections.binarySearch(list, valueOf);
        if (binarySearch < 0) {
            i2 = ~binarySearch;
        } else {
            int size = list.size();
            do {
                binarySearch++;
                if (binarySearch >= size) {
                    break;
                }
            } while (list.get(binarySearch).compareTo(valueOf) == 0);
            i2 = binarySearch;
        }
        if (i2 < this.f5485e.size()) {
            return i2;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: b */
    public long mo2049b(int i2) {
        C4195m.m4765F(i2 >= 0);
        C4195m.m4765F(i2 < this.f5485e.size());
        return this.f5485e.get(i2).longValue();
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: c */
    public List<C2207b> mo2050c(long j2) {
        int m2325c = C2344d0.m2325c(this.f5485e, Long.valueOf(j2), true, false);
        return m2325c == -1 ? Collections.emptyList() : this.f5484c.get(m2325c);
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        return this.f5485e.size();
    }
}
