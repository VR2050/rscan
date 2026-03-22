package p379c.p380a.p382a2;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.a2.u */
/* loaded from: classes2.dex */
public interface InterfaceC2998u<E> {
    /* renamed from: j */
    boolean mo3480j(@Nullable Throwable th);

    /* renamed from: m */
    void mo3482m(@NotNull Function1<? super Throwable, Unit> function1);

    boolean offer(E e2);

    @Nullable
    /* renamed from: p */
    Object mo3484p(E e2, @NotNull Continuation<? super Unit> continuation);
}
