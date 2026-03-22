package p379c.p380a.p385c2;

import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.c2.h */
/* loaded from: classes2.dex */
public abstract class AbstractRunnableC3045h implements Runnable {

    /* renamed from: c */
    @JvmField
    public long f8379c;

    /* renamed from: e */
    @JvmField
    @NotNull
    public InterfaceC3046i f8380e;

    public AbstractRunnableC3045h(long j2, @NotNull InterfaceC3046i interfaceC3046i) {
        this.f8379c = j2;
        this.f8380e = interfaceC3046i;
    }

    public AbstractRunnableC3045h() {
        C3044g c3044g = C3044g.f8378c;
        this.f8379c = 0L;
        this.f8380e = c3044g;
    }
}
