package p005b.p143g.p144a.p170s;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/* renamed from: b.g.a.s.f */
/* loaded from: classes.dex */
public class C1804f<T, Y> {

    /* renamed from: a */
    public final Map<T, Y> f2760a = new LinkedHashMap(100, 0.75f, true);

    /* renamed from: b */
    public long f2761b;

    /* renamed from: c */
    public long f2762c;

    public C1804f(long j2) {
        this.f2761b = j2;
    }

    @Nullable
    /* renamed from: a */
    public synchronized Y m1139a(@NonNull T t) {
        return this.f2760a.get(t);
    }

    /* renamed from: b */
    public int mo899b(@Nullable Y y) {
        return 1;
    }

    /* renamed from: c */
    public void mo900c(@NonNull T t, @Nullable Y y) {
    }

    @Nullable
    /* renamed from: d */
    public synchronized Y m1140d(@NonNull T t, @Nullable Y y) {
        long mo899b = mo899b(y);
        if (mo899b >= this.f2761b) {
            mo900c(t, y);
            return null;
        }
        if (y != null) {
            this.f2762c += mo899b;
        }
        Y put = this.f2760a.put(t, y);
        if (put != null) {
            this.f2762c -= mo899b(put);
            if (!put.equals(y)) {
                mo900c(t, put);
            }
        }
        m1141e(this.f2761b);
        return put;
    }

    /* renamed from: e */
    public synchronized void m1141e(long j2) {
        while (this.f2762c > j2) {
            Iterator<Map.Entry<T, Y>> it = this.f2760a.entrySet().iterator();
            Map.Entry<T, Y> next = it.next();
            Y value = next.getValue();
            this.f2762c -= mo899b(value);
            T key = next.getKey();
            it.remove();
            mo900c(key, value);
        }
    }
}
