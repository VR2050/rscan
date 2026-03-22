package p379c.p380a.p383b2;

import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@DebugMetadata(m5319c = "kotlinx.coroutines.flow.FlowKt__ErrorsKt", m5320f = "Errors.kt", m5321i = {0, 0, 0, 0}, m5322l = {230}, m5323m = "catchImpl", m5324n = {"$this$catchImpl", "collector", "fromDownstream", "$this$collect$iv"}, m5325s = {"L$0", "L$1", "L$2", "L$3"})
/* renamed from: c.a.b2.h */
/* loaded from: classes2.dex */
public final class C3012h extends ContinuationImpl {

    /* renamed from: c */
    public /* synthetic */ Object f8240c;

    /* renamed from: e */
    public int f8241e;

    /* renamed from: f */
    public Object f8242f;

    /* renamed from: g */
    public Object f8243g;

    /* renamed from: h */
    public Object f8244h;

    /* renamed from: i */
    public Object f8245i;

    public C3012h(Continuation continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        this.f8240c = obj;
        this.f8241e |= Integer.MIN_VALUE;
        return C2354n.m2521v(null, null, this);
    }
}
