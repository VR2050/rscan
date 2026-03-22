package p379c.p380a;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2958g;
import p379c.p380a.p381a.C2968q;

/* renamed from: c.a.k0 */
/* loaded from: classes2.dex */
public final class C3073k0<T> extends C2968q<T> {

    /* renamed from: h */
    public static final AtomicIntegerFieldUpdater f8425h = AtomicIntegerFieldUpdater.newUpdater(C3073k0.class, "_decision");
    public volatile int _decision;

    public C3073k0(@NotNull CoroutineContext coroutineContext, @NotNull Continuation<? super T> continuation) {
        super(coroutineContext, continuation);
        this._decision = 0;
    }

    @Override // p379c.p380a.p381a.C2968q, p379c.p380a.AbstractC3002b
    /* renamed from: h0 */
    public void mo3445h0(@Nullable Object obj) {
        boolean z;
        while (true) {
            int i2 = this._decision;
            z = false;
            if (i2 != 0) {
                if (i2 != 1) {
                    throw new IllegalStateException("Already resumed".toString());
                }
            } else if (f8425h.compareAndSet(this, 0, 2)) {
                z = true;
                break;
            }
        }
        if (z) {
            return;
        }
        C2958g.m3422b(IntrinsicsKt__IntrinsicsJvmKt.intercepted(this.f8132g), C2354n.m2505p1(obj, this.f8132g), null, 2);
    }

    @Override // p379c.p380a.p381a.C2968q, p379c.p380a.C3068i1
    /* renamed from: v */
    public void mo3446v(@Nullable Object obj) {
        mo3445h0(obj);
    }
}
