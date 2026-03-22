package kotlin.reflect.jvm.internal.calls;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0004\"\u001e\u0010\u0004\u001a\u00020\u0001*\u0006\u0012\u0002\b\u00030\u00008@@\u0000X\u0080\u0004¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0003¨\u0006\u0005"}, m5311d2 = {"Lkotlin/reflect/jvm/internal/calls/Caller;", "", "getArity", "(Lkotlin/reflect/jvm/internal/calls/Caller;)I", "arity", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class CallerKt {
    public static final int getArity(@NotNull Caller<?> arity) {
        Intrinsics.checkNotNullParameter(arity, "$this$arity");
        return arity.getParameterTypes().size();
    }
}
