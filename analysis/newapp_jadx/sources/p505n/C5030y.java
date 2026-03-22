package p505n;

import javax.annotation.Nullable;
import p458k.AbstractC4393m0;
import p458k.C4389k0;

/* renamed from: n.y */
/* loaded from: classes3.dex */
public final class C5030y<T> {

    /* renamed from: a */
    public final C4389k0 f12957a;

    /* renamed from: b */
    @Nullable
    public final T f12958b;

    public C5030y(C4389k0 c4389k0, @Nullable T t, @Nullable AbstractC4393m0 abstractC4393m0) {
        this.f12957a = c4389k0;
        this.f12958b = t;
    }

    /* renamed from: b */
    public static <T> C5030y<T> m5684b(@Nullable T t, C4389k0 c4389k0) {
        if (c4389k0.m4989e()) {
            return new C5030y<>(c4389k0, t, null);
        }
        throw new IllegalArgumentException("rawResponse must be successful response");
    }

    /* renamed from: a */
    public boolean m5685a() {
        return this.f12957a.m4989e();
    }

    public String toString() {
        return this.f12957a.toString();
    }
}
