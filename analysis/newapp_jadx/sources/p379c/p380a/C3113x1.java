package p379c.p380a;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2952a;
import p379c.p380a.p381a.C2968q;

/* renamed from: c.a.x1 */
/* loaded from: classes2.dex */
public final class C3113x1<T> extends C2968q<T> {
    public C3113x1(@NotNull CoroutineContext coroutineContext, @NotNull Continuation<? super T> continuation) {
        super(coroutineContext, continuation);
    }

    @Override // p379c.p380a.p381a.C2968q, p379c.p380a.AbstractC3002b
    /* renamed from: h0 */
    public void mo3445h0(@Nullable Object obj) {
        Object m2505p1 = C2354n.m2505p1(obj, this.f8132g);
        CoroutineContext coroutineContext = this.f8132g.get$context();
        Object m3414c = C2952a.m3414c(coroutineContext, null);
        try {
            this.f8132g.resumeWith(m2505p1);
            Unit unit = Unit.INSTANCE;
        } finally {
            C2952a.m3412a(coroutineContext, m3414c);
        }
    }
}
