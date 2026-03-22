package p379c.p380a;

import kotlin.NoWhenBranchMatchedException;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.ContinuationKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2952a;

/* renamed from: c.a.b */
/* loaded from: classes2.dex */
public abstract class AbstractC3002b<T> extends C3068i1 implements InterfaceC3053d1, Continuation<T>, InterfaceC3055e0 {

    /* renamed from: e */
    @NotNull
    public final CoroutineContext f8190e;

    /* renamed from: f */
    @JvmField
    @NotNull
    public final CoroutineContext f8191f;

    public AbstractC3002b(@NotNull CoroutineContext coroutineContext, boolean z) {
        super(z);
        this.f8191f = coroutineContext;
        this.f8190e = coroutineContext.plus(this);
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: N */
    public final void mo3503N(@NotNull Throwable th) {
        C2354n.m2516t0(this.f8190e, th);
    }

    @Override // p379c.p380a.C3068i1
    @NotNull
    /* renamed from: V */
    public String mo3504V() {
        boolean z = C2976a0.f8141a;
        return super.mo3504V();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [boolean, int] */
    @Override // p379c.p380a.C3068i1
    /* renamed from: Y */
    public final void mo3505Y(@Nullable Object obj) {
        if (!(obj instanceof C3108w)) {
            m3510k0(obj);
        } else {
            C3108w c3108w = (C3108w) obj;
            m3509j0(c3108w.f8470b, c3108w._handled);
        }
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: Z */
    public final void mo3506Z() {
        mo3511l0();
    }

    @Override // p379c.p380a.C3068i1, p379c.p380a.InterfaceC3053d1
    /* renamed from: b */
    public boolean mo3507b() {
        return super.mo3507b();
    }

    @Override // kotlin.coroutines.Continuation
    @NotNull
    /* renamed from: getContext */
    public final CoroutineContext get$context() {
        return this.f8190e;
    }

    @Override // p379c.p380a.InterfaceC3055e0
    @NotNull
    public CoroutineContext getCoroutineContext() {
        return this.f8190e;
    }

    /* renamed from: h0 */
    public void mo3445h0(@Nullable Object obj) {
        mo3446v(obj);
    }

    /* renamed from: i0 */
    public final void m3508i0() {
        m3578O((InterfaceC3053d1) this.f8191f.get(InterfaceC3053d1.f8393b));
    }

    /* renamed from: j0 */
    public void m3509j0(@NotNull Throwable th, boolean z) {
    }

    /* renamed from: k0 */
    public void m3510k0(T t) {
    }

    /* renamed from: l0 */
    public void mo3511l0() {
    }

    /* JADX WARN: Incorrect types in method signature: <R:Ljava/lang/Object;>(Ljava/lang/Object;TR;Lkotlin/jvm/functions/Function2<-TR;-Lkotlin/coroutines/Continuation<-TT;>;+Ljava/lang/Object;>;)V */
    /* renamed from: m0 */
    public final void m3512m0(@NotNull int i2, Object obj, @NotNull Function2 function2) {
        m3508i0();
        int m350b = C1345b.m350b(i2);
        if (m350b == 0) {
            C2354n.m2403J1(function2, obj, this, null, 4);
            return;
        }
        if (m350b != 1) {
            if (m350b == 2) {
                ContinuationKt.startCoroutine(function2, obj, this);
                return;
            }
            if (m350b != 3) {
                throw new NoWhenBranchMatchedException();
            }
            Continuation probeCoroutineCreated = DebugProbesKt.probeCoroutineCreated(this);
            try {
                CoroutineContext coroutineContext = this.f8190e;
                Object m3414c = C2952a.m3414c(coroutineContext, null);
                try {
                    if (function2 == null) {
                        throw new NullPointerException("null cannot be cast to non-null type (R, kotlin.coroutines.Continuation<T>) -> kotlin.Any?");
                    }
                    Object invoke = ((Function2) TypeIntrinsics.beforeCheckcastToFunctionOfArity(function2, 2)).invoke(obj, probeCoroutineCreated);
                    if (invoke != IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                        Result.Companion companion = Result.INSTANCE;
                        probeCoroutineCreated.resumeWith(Result.m6055constructorimpl(invoke));
                    }
                } finally {
                    C2952a.m3412a(coroutineContext, m3414c);
                }
            } catch (Throwable th) {
                Result.Companion companion2 = Result.INSTANCE;
                probeCoroutineCreated.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(th)));
            }
        }
    }

    @Override // kotlin.coroutines.Continuation
    public final void resumeWith(@NotNull Object obj) {
        Object m3580T = m3580T(C2354n.m2448Y1(obj, null));
        if (m3580T == C3071j1.f8418b) {
            return;
        }
        mo3445h0(m3580T);
    }

    @Override // p379c.p380a.C3068i1
    @NotNull
    /* renamed from: z */
    public String mo3513z() {
        return getClass().getSimpleName() + " was cancelled";
    }
}
