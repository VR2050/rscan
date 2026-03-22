package p005b.p199l.p200a.p201a.p248o1.p249h0;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/* renamed from: b.l.a.a.o1.h0.q */
/* loaded from: classes.dex */
public class C2311q {

    /* renamed from: a */
    public final Map<String, Object> f5893a = new HashMap();

    /* renamed from: b */
    public final List<String> f5894b = new ArrayList();

    /* renamed from: a */
    public static C2311q m2249a(C2311q c2311q, long j2) {
        Long valueOf = Long.valueOf(j2);
        Map<String, Object> map = c2311q.f5893a;
        Objects.requireNonNull(valueOf);
        map.put("exo_len", valueOf);
        c2311q.f5894b.remove("exo_len");
        return c2311q;
    }
}
