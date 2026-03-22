package p379c.p380a.p383b2;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.b2.m */
/* loaded from: classes2.dex */
public final class C3017m implements InterfaceC3007c<Object> {

    /* renamed from: c */
    public final Throwable f8265c;

    public C3017m(@NotNull Throwable th) {
        this.f8265c = th;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3007c
    @Nullable
    public Object emit(@Nullable Object obj, @NotNull Continuation<? super Unit> continuation) {
        throw this.f8265c;
    }
}
