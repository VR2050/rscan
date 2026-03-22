package p379c.p380a;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.i */
/* loaded from: classes2.dex */
public interface InterfaceC3066i<T> extends Continuation<T> {
    @Nullable
    /* renamed from: a */
    Object mo3561a(T t, @Nullable Object obj);

    /* renamed from: f */
    void mo3562f(@NotNull Function1<? super Throwable, Unit> function1);

    @Nullable
    /* renamed from: g */
    Object mo3563g(@NotNull Throwable th);

    @Nullable
    /* renamed from: h */
    Object mo3564h(T t, @Nullable Object obj, @Nullable Function1<? super Throwable, Unit> function1);

    /* renamed from: i */
    void mo3565i(@NotNull AbstractC3036c0 abstractC3036c0, T t);

    /* renamed from: l */
    boolean mo3566l(@Nullable Throwable th);

    /* renamed from: r */
    void mo3567r(@NotNull Object obj);
}
