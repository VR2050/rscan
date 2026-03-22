package p005b.p199l.p258c;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLongArray;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;

/* renamed from: b.l.c.i */
/* loaded from: classes2.dex */
public final class C2479i extends AbstractC2496z<AtomicLongArray> {

    /* renamed from: a */
    public final /* synthetic */ AbstractC2496z f6678a;

    public C2479i(AbstractC2496z abstractC2496z) {
        this.f6678a = abstractC2496z;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public AtomicLongArray mo2766b(C2472a c2472a) {
        ArrayList arrayList = new ArrayList();
        c2472a.mo2778b();
        while (c2472a.mo2787t()) {
            arrayList.add(Long.valueOf(((Number) this.f6678a.mo2766b(c2472a)).longValue()));
        }
        c2472a.mo2785o();
        int size = arrayList.size();
        AtomicLongArray atomicLongArray = new AtomicLongArray(size);
        for (int i2 = 0; i2 < size; i2++) {
            atomicLongArray.set(i2, ((Long) arrayList.get(i2)).longValue());
        }
        return atomicLongArray;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, AtomicLongArray atomicLongArray) {
        AtomicLongArray atomicLongArray2 = atomicLongArray;
        c2474c.mo2795d();
        int length = atomicLongArray2.length();
        for (int i2 = 0; i2 < length; i2++) {
            this.f6678a.mo2767c(c2474c, Long.valueOf(atomicLongArray2.get(i2)));
        }
        c2474c.mo2797o();
    }
}
