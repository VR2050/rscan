package p379c.p380a;

import java.util.concurrent.CancellationException;
import kotlin.ExceptionsKt__ExceptionsKt;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2952a;
import p379c.p380a.p381a.C2957f;
import p379c.p380a.p385c2.AbstractRunnableC3045h;
import p379c.p380a.p385c2.InterfaceC3046i;

/* renamed from: c.a.l0 */
/* loaded from: classes2.dex */
public abstract class AbstractC3076l0<T> extends AbstractRunnableC3045h {

    /* renamed from: f */
    @JvmField
    public int f8428f;

    public AbstractC3076l0(int i2) {
        this.f8428f = i2;
    }

    /* renamed from: b */
    public void mo3418b(@Nullable Object obj, @NotNull Throwable th) {
    }

    @NotNull
    /* renamed from: c */
    public abstract Continuation<T> mo3419c();

    @Nullable
    /* renamed from: d */
    public Throwable mo3604d(@Nullable Object obj) {
        if (!(obj instanceof C3108w)) {
            obj = null;
        }
        C3108w c3108w = (C3108w) obj;
        if (c3108w != null) {
            return c3108w.f8470b;
        }
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: e */
    public <T> T mo3605e(@Nullable Object obj) {
        return obj;
    }

    /* renamed from: j */
    public final void m3619j(@Nullable Throwable th, @Nullable Throwable th2) {
        if (th == null && th2 == null) {
            return;
        }
        if (th != null && th2 != null) {
            ExceptionsKt__ExceptionsKt.addSuppressed(th, th2);
        }
        if (th == null) {
            th = th2;
        }
        Intrinsics.checkNotNull(th);
        C2354n.m2516t0(mo3419c().get$context(), new C3058f0("Fatal exception in coroutines machinery for " + this + ". Please read KDoc to 'handleFatalException' method and report this incident to maintainers", th));
    }

    @Nullable
    /* renamed from: k */
    public abstract Object mo3420k();

    @Override // java.lang.Runnable
    public final void run() {
        Object m6055constructorimpl;
        Object m6055constructorimpl2;
        InterfaceC3046i interfaceC3046i = this.f8380e;
        try {
            Continuation<T> mo3419c = mo3419c();
            if (mo3419c == null) {
                throw new NullPointerException("null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T>");
            }
            C2957f c2957f = (C2957f) mo3419c;
            Continuation<T> continuation = c2957f.f8107l;
            CoroutineContext coroutineContext = continuation.get$context();
            Object mo3420k = mo3420k();
            Object m3414c = C2952a.m3414c(coroutineContext, c2957f.f8105j);
            try {
                Throwable mo3604d = mo3604d(mo3420k);
                InterfaceC3053d1 interfaceC3053d1 = (mo3604d == null && C2354n.m2402J0(this.f8428f)) ? (InterfaceC3053d1) coroutineContext.get(InterfaceC3053d1.f8393b) : null;
                if (interfaceC3053d1 != null && !interfaceC3053d1.mo3507b()) {
                    CancellationException mo3553q = interfaceC3053d1.mo3553q();
                    mo3418b(mo3420k, mo3553q);
                    Result.Companion companion = Result.INSTANCE;
                    continuation.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(mo3553q)));
                } else if (mo3604d != null) {
                    Result.Companion companion2 = Result.INSTANCE;
                    continuation.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(mo3604d)));
                } else {
                    T mo3605e = mo3605e(mo3420k);
                    Result.Companion companion3 = Result.INSTANCE;
                    continuation.resumeWith(Result.m6055constructorimpl(mo3605e));
                }
                Unit unit = Unit.INSTANCE;
                try {
                    Result.Companion companion4 = Result.INSTANCE;
                    interfaceC3046i.mo3539k();
                    m6055constructorimpl2 = Result.m6055constructorimpl(unit);
                } catch (Throwable th) {
                    Result.Companion companion5 = Result.INSTANCE;
                    m6055constructorimpl2 = Result.m6055constructorimpl(ResultKt.createFailure(th));
                }
                m3619j(null, Result.m6058exceptionOrNullimpl(m6055constructorimpl2));
            } finally {
                C2952a.m3412a(coroutineContext, m3414c);
            }
        } catch (Throwable th2) {
            try {
                Result.Companion companion6 = Result.INSTANCE;
                interfaceC3046i.mo3539k();
                m6055constructorimpl = Result.m6055constructorimpl(Unit.INSTANCE);
            } catch (Throwable th3) {
                Result.Companion companion7 = Result.INSTANCE;
                m6055constructorimpl = Result.m6055constructorimpl(ResultKt.createFailure(th3));
            }
            m3619j(th2, Result.m6058exceptionOrNullimpl(m6055constructorimpl));
        }
    }
}
