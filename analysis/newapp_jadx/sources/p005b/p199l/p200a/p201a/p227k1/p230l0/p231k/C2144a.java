package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import java.util.Collections;
import java.util.List;

/* renamed from: b.l.a.a.k1.l0.k.a */
/* loaded from: classes.dex */
public class C2144a {

    /* renamed from: a */
    public final int f4775a;

    /* renamed from: b */
    public final int f4776b;

    /* renamed from: c */
    public final List<AbstractC2152i> f4777c;

    /* renamed from: d */
    public final List<C2147d> f4778d;

    /* renamed from: e */
    public final List<C2147d> f4779e;

    public C2144a(int i2, int i3, List<AbstractC2152i> list, List<C2147d> list2, List<C2147d> list3) {
        this.f4775a = i2;
        this.f4776b = i3;
        this.f4777c = Collections.unmodifiableList(list);
        this.f4778d = list2 == null ? Collections.emptyList() : Collections.unmodifiableList(list2);
        this.f4779e = list3 == null ? Collections.emptyList() : Collections.unmodifiableList(list3);
    }
}
