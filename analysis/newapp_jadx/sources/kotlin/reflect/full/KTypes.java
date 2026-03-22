package kotlin.reflect.full;

import kotlin.Metadata;
import kotlin.SinceKotlin;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KType;
import kotlin.reflect.jvm.internal.KTypeImpl;
import kotlin.reflect.jvm.internal.impl.types.typeUtil.TypeUtilsKt;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\b\u001a\u001b\u0010\u0003\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u0001H\u0007¢\u0006\u0004\b\u0003\u0010\u0004\u001a\u001b\u0010\u0006\u001a\u00020\u0001*\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u0000H\u0007¢\u0006\u0004\b\u0006\u0010\u0007\u001a\u001b\u0010\b\u001a\u00020\u0001*\u00020\u00002\u0006\u0010\u0005\u001a\u00020\u0000H\u0007¢\u0006\u0004\b\b\u0010\u0007¨\u0006\t"}, m5311d2 = {"Lkotlin/reflect/KType;", "", "nullable", "withNullability", "(Lkotlin/reflect/KType;Z)Lkotlin/reflect/KType;", "other", "isSubtypeOf", "(Lkotlin/reflect/KType;Lkotlin/reflect/KType;)Z", "isSupertypeOf", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KTypes")
/* loaded from: classes2.dex */
public final class KTypes {
    @SinceKotlin(version = "1.1")
    public static final boolean isSubtypeOf(@NotNull KType isSubtypeOf, @NotNull KType other) {
        Intrinsics.checkNotNullParameter(isSubtypeOf, "$this$isSubtypeOf");
        Intrinsics.checkNotNullParameter(other, "other");
        return TypeUtilsKt.isSubtypeOf(((KTypeImpl) isSubtypeOf).getType(), ((KTypeImpl) other).getType());
    }

    @SinceKotlin(version = "1.1")
    public static final boolean isSupertypeOf(@NotNull KType isSupertypeOf, @NotNull KType other) {
        Intrinsics.checkNotNullParameter(isSupertypeOf, "$this$isSupertypeOf");
        Intrinsics.checkNotNullParameter(other, "other");
        return isSubtypeOf(other, isSupertypeOf);
    }

    @SinceKotlin(version = "1.1")
    @NotNull
    public static final KType withNullability(@NotNull KType withNullability, boolean z) {
        Intrinsics.checkNotNullParameter(withNullability, "$this$withNullability");
        return ((KTypeImpl) withNullability).makeNullableAsSpecified$kotlin_reflection(z);
    }
}
