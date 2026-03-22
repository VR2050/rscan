package p379c.p380a;

import java.util.Objects;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3053d1;

/* renamed from: c.a.h1 */
/* loaded from: classes2.dex */
public abstract class AbstractC3065h1<J extends InterfaceC3053d1> extends AbstractC3114y implements InterfaceC3082n0, InterfaceC3115y0 {

    /* renamed from: g */
    @JvmField
    @NotNull
    public final J f8403g;

    public AbstractC3065h1(@NotNull J j2) {
        this.f8403g = j2;
    }

    @Override // p379c.p380a.InterfaceC3115y0
    /* renamed from: b */
    public boolean mo3559b() {
        return true;
    }

    @Override // p379c.p380a.InterfaceC3115y0
    @Nullable
    /* renamed from: d */
    public C3080m1 mo3560d() {
        return null;
    }

    @Override // p379c.p380a.InterfaceC3082n0
    public void dispose() {
        Object m3576L;
        J j2 = this.f8403g;
        Objects.requireNonNull(j2, "null cannot be cast to non-null type kotlinx.coroutines.JobSupport");
        C3068i1 c3068i1 = (C3068i1) j2;
        do {
            m3576L = c3068i1.m3576L();
            if (!(m3576L instanceof AbstractC3065h1)) {
                if (!(m3576L instanceof InterfaceC3115y0) || ((InterfaceC3115y0) m3576L).mo3560d() == null) {
                    return;
                }
                mo3424o();
                return;
            }
            if (m3576L != this) {
                return;
            }
        } while (!C3068i1.f8404c.compareAndSet(c3068i1, m3576L, C3071j1.f8423g));
    }
}
