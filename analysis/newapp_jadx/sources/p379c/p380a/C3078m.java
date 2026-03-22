package p379c.p380a;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.p381a.C2957f;
import p379c.p380a.p381a.C2958g;
import p379c.p380a.p381a.C2970s;

/* renamed from: c.a.m */
/* loaded from: classes2.dex */
public final class C3078m extends AbstractC3059f1<InterfaceC3053d1> {

    /* renamed from: h */
    @JvmField
    @NotNull
    public final C3069j<?> f8429h;

    public C3078m(@NotNull InterfaceC3053d1 interfaceC3053d1, @NotNull C3069j<?> c3069j) {
        super(interfaceC3053d1);
        this.f8429h = c3069j;
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(Throwable th) {
        mo3514r(th);
        return Unit.INSTANCE;
    }

    @Override // p379c.p380a.AbstractC3114y
    /* renamed from: r */
    public void mo3514r(@Nullable Throwable th) {
        C3069j<?> c3069j = this.f8429h;
        Throwable mo3595t = c3069j.mo3595t(this.f8403g);
        boolean z = true;
        boolean z2 = false;
        if (c3069j.f8428f == 2) {
            Continuation<?> continuation = c3069j.f8416j;
            if (!(continuation instanceof C2957f)) {
                continuation = null;
            }
            C2957f c2957f = (C2957f) continuation;
            if (c2957f != null) {
                while (true) {
                    Object obj = c2957f._reusableCancellableContinuation;
                    C2970s c2970s = C2958g.f8109b;
                    if (!Intrinsics.areEqual(obj, c2970s)) {
                        if (obj instanceof Throwable) {
                            break;
                        } else if (C2957f.f8102g.compareAndSet(c2957f, obj, null)) {
                            z = false;
                            break;
                        }
                    } else if (C2957f.f8102g.compareAndSet(c2957f, c2970s, mo3595t)) {
                        break;
                    }
                }
                z2 = z;
            }
        }
        if (z2) {
            return;
        }
        c3069j.mo3566l(mo3595t);
        c3069j.m3610q();
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("ChildContinuation[");
        m586H.append(this.f8429h);
        m586H.append(']');
        return m586H.toString();
    }
}
