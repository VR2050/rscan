package kotlin.reflect.full;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0003\"\u0004\b\u0000\u0010\u0000*\b\u0012\u0004\u0012\u00028\u00000\u00012\u0016\u0010\u0004\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00030\u0002\"\u0004\u0018\u00010\u00032\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00028\u00000\u0005H\u0087@¢\u0006\u0004\b\u0007\u0010\b"}, m5311d2 = {"R", "Lkotlin/reflect/KCallable;", "", "", "args", "Lkotlin/coroutines/Continuation;", "continuation", "callSuspend", "(Lkotlin/reflect/KCallable;Lkotlin/Array;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "kotlin.reflect.full.KCallables", m5320f = "KCallables.kt", m5321i = {}, m5322l = {55}, m5323m = "callSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class KCallables$callSuspend$1 extends ContinuationImpl {
    public Object L$0;
    public Object L$1;
    public int label;
    public /* synthetic */ Object result;

    public KCallables$callSuspend$1(Continuation continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return KCallables.callSuspend(null, null, this);
    }
}
