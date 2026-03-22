package p379c.p380a;

import java.util.concurrent.locks.LockSupport;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.e */
/* loaded from: classes2.dex */
public final class C3054e<T> extends AbstractC3002b<T> {

    /* renamed from: g */
    public final Thread f8395g;

    /* renamed from: h */
    public final AbstractC3091q0 f8396h;

    public C3054e(@NotNull CoroutineContext coroutineContext, @NotNull Thread thread, @Nullable AbstractC3091q0 abstractC3091q0) {
        super(coroutineContext, true);
        this.f8395g = thread;
        this.f8396h = abstractC3091q0;
    }

    @Override // p379c.p380a.C3068i1
    /* renamed from: v */
    public void mo3446v(@Nullable Object obj) {
        if (!Intrinsics.areEqual(Thread.currentThread(), this.f8395g)) {
            LockSupport.unpark(this.f8395g);
        }
    }
}
