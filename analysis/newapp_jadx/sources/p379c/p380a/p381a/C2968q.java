package p379c.p380a.p381a;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.jvm.internal.CoroutineStackFrame;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3002b;

/* renamed from: c.a.a.q */
/* loaded from: classes2.dex */
public class C2968q<T> extends AbstractC3002b<T> implements CoroutineStackFrame {

    /* renamed from: g */
    @JvmField
    @NotNull
    public final Continuation<T> f8132g;

    /* JADX WARN: Multi-variable type inference failed */
    public C2968q(@NotNull CoroutineContext coroutineContext, @NotNull Continuation<? super T> continuation) {
        super(coroutineContext, true);
        this.f8132g = continuation;
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: Q */
    public final boolean mo3444Q() {
        return true;
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public final CoroutineStackFrame getCallerFrame() {
        return (CoroutineStackFrame) this.f8132g;
    }

    @Override // kotlin.coroutines.jvm.internal.CoroutineStackFrame
    @Nullable
    public final StackTraceElement getStackTraceElement() {
        return null;
    }

    @Override // p379c.p380a.AbstractC3002b
    /* renamed from: h0 */
    public void mo3445h0(@Nullable Object obj) {
        Continuation<T> continuation = this.f8132g;
        continuation.resumeWith(C2354n.m2505p1(obj, continuation));
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: v */
    public void mo3446v(@Nullable Object obj) {
        C2958g.m3422b(IntrinsicsKt__IntrinsicsJvmKt.intercepted(this.f8132g), C2354n.m2505p1(obj, this.f8132g), null, 2);
    }
}
