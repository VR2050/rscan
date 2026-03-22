package p379c.p380a.p385c2;

import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: c.a.c2.j */
/* loaded from: classes2.dex */
public final class C3047j extends AbstractRunnableC3045h {

    /* renamed from: f */
    @JvmField
    @NotNull
    public final Runnable f8381f;

    public C3047j(@NotNull Runnable runnable, long j2, @NotNull InterfaceC3046i interfaceC3046i) {
        super(j2, interfaceC3046i);
        this.f8381f = runnable;
    }

    @Override // java.lang.Runnable
    public void run() {
        try {
            this.f8381f.run();
        } finally {
            this.f8380e.mo3539k();
        }
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Task[");
        m586H.append(C2354n.m2489k0(this.f8381f));
        m586H.append('@');
        m586H.append(C2354n.m2495m0(this.f8381f));
        m586H.append(", ");
        m586H.append(this.f8379c);
        m586H.append(", ");
        m586H.append(this.f8380e);
        m586H.append(']');
        return m586H.toString();
    }
}
