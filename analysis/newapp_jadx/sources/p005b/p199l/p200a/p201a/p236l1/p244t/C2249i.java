package p005b.p199l.p200a.p201a.p236l1.p244t;

import android.text.SpannableStringBuilder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2245e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.l1.t.i */
/* loaded from: classes.dex */
public final class C2249i implements InterfaceC2210e {

    /* renamed from: c */
    public final List<C2245e> f5603c;

    /* renamed from: e */
    public final int f5604e;

    /* renamed from: f */
    public final long[] f5605f;

    /* renamed from: g */
    public final long[] f5606g;

    public C2249i(List<C2245e> list) {
        this.f5603c = list;
        int size = list.size();
        this.f5604e = size;
        this.f5605f = new long[size * 2];
        for (int i2 = 0; i2 < this.f5604e; i2++) {
            C2245e c2245e = list.get(i2);
            int i3 = i2 * 2;
            long[] jArr = this.f5605f;
            jArr[i3] = c2245e.f5575s;
            jArr[i3 + 1] = c2245e.f5576t;
        }
        long[] jArr2 = this.f5605f;
        long[] copyOf = Arrays.copyOf(jArr2, jArr2.length);
        this.f5606g = copyOf;
        Arrays.sort(copyOf);
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: a */
    public int mo2048a(long j2) {
        int m2324b = C2344d0.m2324b(this.f5606g, j2, false, false);
        if (m2324b < this.f5606g.length) {
            return m2324b;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: b */
    public long mo2049b(int i2) {
        C4195m.m4765F(i2 >= 0);
        C4195m.m4765F(i2 < this.f5606g.length);
        return this.f5606g[i2];
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: c */
    public List<C2207b> mo2050c(long j2) {
        ArrayList arrayList = new ArrayList();
        SpannableStringBuilder spannableStringBuilder = null;
        C2245e c2245e = null;
        for (int i2 = 0; i2 < this.f5604e; i2++) {
            long[] jArr = this.f5605f;
            int i3 = i2 * 2;
            if (jArr[i3] <= j2 && j2 < jArr[i3 + 1]) {
                C2245e c2245e2 = this.f5603c.get(i2);
                if (!(c2245e2.f5278h == -3.4028235E38f && c2245e2.f5281k == 0.5f)) {
                    arrayList.add(c2245e2);
                } else if (c2245e == null) {
                    c2245e = c2245e2;
                } else if (spannableStringBuilder == null) {
                    spannableStringBuilder = new SpannableStringBuilder();
                    CharSequence charSequence = c2245e.f5275e;
                    Objects.requireNonNull(charSequence);
                    SpannableStringBuilder append = spannableStringBuilder.append(charSequence).append((CharSequence) "\n");
                    CharSequence charSequence2 = c2245e2.f5275e;
                    Objects.requireNonNull(charSequence2);
                    append.append(charSequence2);
                } else {
                    SpannableStringBuilder append2 = spannableStringBuilder.append((CharSequence) "\n");
                    CharSequence charSequence3 = c2245e2.f5275e;
                    Objects.requireNonNull(charSequence3);
                    append2.append(charSequence3);
                }
            }
        }
        if (spannableStringBuilder != null) {
            C2245e.b bVar = new C2245e.b();
            bVar.f5579c = spannableStringBuilder;
            arrayList.add(bVar.m2128a());
        } else if (c2245e != null) {
            arrayList.add(c2245e);
        }
        return arrayList;
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e
    /* renamed from: d */
    public int mo2051d() {
        return this.f5606g.length;
    }
}
