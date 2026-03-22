package p379c.p380a;

import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.v1 */
/* loaded from: classes2.dex */
public final class C3107v1 {

    /* renamed from: a */
    public static final ThreadLocal<AbstractC3091q0> f8467a = new ThreadLocal<>();

    /* renamed from: b */
    public static final C3107v1 f8468b = null;

    @NotNull
    /* renamed from: a */
    public static final AbstractC3091q0 m3642a() {
        ThreadLocal<AbstractC3091q0> threadLocal = f8467a;
        AbstractC3091q0 abstractC3091q0 = threadLocal.get();
        if (abstractC3091q0 != null) {
            return abstractC3091q0;
        }
        C3057f c3057f = new C3057f(Thread.currentThread());
        threadLocal.set(c3057f);
        return c3057f;
    }
}
