package p379c.p380a;

import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.p381a.C2958g;

/* renamed from: c.a.k1 */
/* loaded from: classes2.dex */
public final class C3074k1 extends C3098s1 {

    /* renamed from: g */
    public final Continuation<Unit> f8426g;

    public C3074k1(@NotNull CoroutineContext coroutineContext, @NotNull Function2<? super InterfaceC3055e0, ? super Continuation<? super Unit>, ? extends Object> function2) {
        super(coroutineContext, false);
        this.f8426g = IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted(function2, this, this);
    }

    @Override // p379c.p380a.AbstractC3002b
    /* renamed from: l0 */
    public void mo3511l0() {
        try {
            Continuation intercepted = IntrinsicsKt__IntrinsicsJvmKt.intercepted(this.f8426g);
            Result.Companion companion = Result.INSTANCE;
            C2958g.m3422b(intercepted, Result.m6055constructorimpl(Unit.INSTANCE), null, 2);
        } catch (Throwable th) {
            Result.Companion companion2 = Result.INSTANCE;
            resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(th)));
        }
    }
}
