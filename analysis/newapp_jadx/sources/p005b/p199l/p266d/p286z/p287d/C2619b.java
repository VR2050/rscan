package p005b.p199l.p266d.p286z.p287d;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import p005b.p199l.p266d.p286z.C2615a;

/* renamed from: b.l.d.z.d.b */
/* loaded from: classes2.dex */
public final class C2619b {

    /* renamed from: a */
    public final Map<Integer, Integer> f7137a = new HashMap();

    /* renamed from: a */
    public int[] m3063a() {
        ArrayList arrayList = new ArrayList();
        int i2 = -1;
        for (Map.Entry<Integer, Integer> entry : this.f7137a.entrySet()) {
            if (entry.getValue().intValue() > i2) {
                i2 = entry.getValue().intValue();
                arrayList.clear();
                arrayList.add(entry.getKey());
            } else if (entry.getValue().intValue() == i2) {
                arrayList.add(entry.getKey());
            }
        }
        return C2615a.m3060b(arrayList);
    }

    /* renamed from: b */
    public void m3064b(int i2) {
        Integer num = this.f7137a.get(Integer.valueOf(i2));
        if (num == null) {
            num = 0;
        }
        this.f7137a.put(Integer.valueOf(i2), Integer.valueOf(num.intValue() + 1));
    }
}
