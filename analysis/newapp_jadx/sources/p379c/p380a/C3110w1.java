package p379c.p380a;

import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.w1 */
/* loaded from: classes2.dex */
public final class C3110w1 extends AbstractC3036c0 {

    /* renamed from: c */
    public static final C3110w1 f8472c = new C3110w1();

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        if (((C3116y1) coroutineContext.get(C3116y1.f8476c)) == null) {
            throw new UnsupportedOperationException("Dispatchers.Unconfined.dispatch function can only be used by the yield function. If you wrap Unconfined dispatcher in your code, make sure you properly delegate isDispatchNeeded and dispatch calls.");
        }
    }

    @Override // p379c.p380a.AbstractC3036c0
    public boolean isDispatchNeeded(@NotNull CoroutineContext coroutineContext) {
        return false;
    }

    @Override // p379c.p380a.AbstractC3036c0
    @NotNull
    public String toString() {
        return "Dispatchers.Unconfined";
    }
}
