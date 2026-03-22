package p005b.p199l.p266d;

import java.util.EnumMap;
import java.util.Map;

/* renamed from: b.l.d.p */
/* loaded from: classes2.dex */
public final class C2534p {

    /* renamed from: a */
    public final String f6854a;

    /* renamed from: b */
    public final byte[] f6855b;

    /* renamed from: c */
    public C2536r[] f6856c;

    /* renamed from: d */
    public final EnumC2497a f6857d;

    /* renamed from: e */
    public Map<EnumC2535q, Object> f6858e;

    public C2534p(String str, byte[] bArr, C2536r[] c2536rArr, EnumC2497a enumC2497a) {
        System.currentTimeMillis();
        this.f6854a = str;
        this.f6855b = bArr;
        this.f6856c = c2536rArr;
        this.f6857d = enumC2497a;
        this.f6858e = null;
    }

    /* renamed from: a */
    public void m2932a(Map<EnumC2535q, Object> map) {
        if (map != null) {
            Map<EnumC2535q, Object> map2 = this.f6858e;
            if (map2 == null) {
                this.f6858e = map;
            } else {
                map2.putAll(map);
            }
        }
    }

    /* renamed from: b */
    public void m2933b(EnumC2535q enumC2535q, Object obj) {
        if (this.f6858e == null) {
            this.f6858e = new EnumMap(EnumC2535q.class);
        }
        this.f6858e.put(enumC2535q, obj);
    }

    public String toString() {
        return this.f6854a;
    }

    public C2534p(String str, byte[] bArr, int i2, C2536r[] c2536rArr, EnumC2497a enumC2497a, long j2) {
        this.f6854a = str;
        this.f6855b = bArr;
        this.f6856c = c2536rArr;
        this.f6857d = enumC2497a;
        this.f6858e = null;
    }
}
