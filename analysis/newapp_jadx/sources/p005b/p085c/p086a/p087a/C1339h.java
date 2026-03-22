package p005b.p085c.p086a.p087a;

import java.util.Map;
import java.util.TreeMap;

/* renamed from: b.c.a.a.h */
/* loaded from: classes.dex */
public final class C1339h implements InterfaceC1340i, InterfaceC1341j {
    @Override // p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final Object mo340a(Object obj) {
        TreeMap treeMap = new TreeMap();
        for (Map.Entry entry : ((Map) obj).entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new IllegalArgumentException("Map key must be String!");
            }
            treeMap.put((String) entry.getKey(), C1337f.m346b(entry.getValue()));
        }
        return treeMap;
    }

    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i, p005b.p085c.p086a.p087a.InterfaceC1341j
    /* renamed from: a */
    public final boolean mo341a(Class<?> cls) {
        return Map.class.isAssignableFrom(cls);
    }

    /* JADX WARN: Code restructure failed: missing block: B:64:0x009b, code lost:
    
        r0 = new java.util.HashMap();
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x00a1, code lost:
    
        r0 = new java.util.concurrent.ConcurrentHashMap();
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x00a7, code lost:
    
        r0 = new java.util.TreeMap();
     */
    @Override // p005b.p085c.p086a.p087a.InterfaceC1340i
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object mo342b(java.lang.Object r5, java.lang.reflect.Type r6) {
        /*
            Method dump skipped, instructions count: 255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p086a.p087a.C1339h.mo342b(java.lang.Object, java.lang.reflect.Type):java.lang.Object");
    }
}
