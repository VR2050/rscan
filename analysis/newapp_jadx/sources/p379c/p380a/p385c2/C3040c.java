package p379c.p380a.p385c2;

import java.util.concurrent.RejectedExecutionException;
import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.AbstractC3106v0;
import p379c.p380a.RunnableC3061g0;

/* renamed from: c.a.c2.c */
/* loaded from: classes2.dex */
public class C3040c extends AbstractC3106v0 {

    /* renamed from: c */
    public ExecutorC3038a f8366c;

    /* renamed from: e */
    public final int f8367e;

    /* renamed from: f */
    public final int f8368f;

    /* renamed from: g */
    public final long f8369g;

    /* renamed from: h */
    public final String f8370h;

    public C3040c(int i2, int i3, String str, int i4) {
        int i5 = (i4 & 1) != 0 ? C3048k.f8383b : i2;
        int i6 = (i4 & 2) != 0 ? C3048k.f8384c : i3;
        String str2 = (i4 & 4) != 0 ? "DefaultDispatcher" : null;
        long j2 = C3048k.f8385d;
        this.f8367e = i5;
        this.f8368f = i6;
        this.f8369g = j2;
        this.f8370h = str2;
        this.f8366c = new ExecutorC3038a(i5, i6, j2, str2);
    }

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        try {
            ExecutorC3038a.m3521o(this.f8366c, runnable, null, false, 6);
        } catch (RejectedExecutionException unused) {
            RunnableC3061g0.f8400k.m3633c0(runnable);
        }
    }

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatchYield(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        try {
            ExecutorC3038a.m3521o(this.f8366c, runnable, null, true, 2);
        } catch (RejectedExecutionException unused) {
            RunnableC3061g0.f8400k.dispatchYield(coroutineContext, runnable);
        }
    }
}
