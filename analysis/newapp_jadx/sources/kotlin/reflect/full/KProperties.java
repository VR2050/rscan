package kotlin.reflect.full;

import kotlin.Metadata;
import kotlin.SinceKotlin;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KProperty1;
import kotlin.reflect.KProperty2;
import kotlin.reflect.jvm.internal.KPropertyImpl;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u001d\u0010\u0002\u001a\u0004\u0018\u00010\u0001*\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u0000H\u0007¢\u0006\u0004\b\u0002\u0010\u0003\u001a1\u0010\u0002\u001a\u0004\u0018\u00010\u0001\"\u0004\b\u0000\u0010\u0004*\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u00052\u0006\u0010\u0006\u001a\u00028\u0000H\u0007¢\u0006\u0004\b\u0002\u0010\u0007¨\u0006\b"}, m5311d2 = {"Lkotlin/reflect/KProperty1;", "", "getExtensionDelegate", "(Lkotlin/reflect/KProperty1;)Ljava/lang/Object;", "D", "Lkotlin/reflect/KProperty2;", "receiver", "(Lkotlin/reflect/KProperty2;Ljava/lang/Object;)Ljava/lang/Object;", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KProperties")
/* loaded from: classes2.dex */
public final class KProperties {
    @SinceKotlin(version = "1.1")
    @Nullable
    public static final Object getExtensionDelegate(@NotNull KProperty1<?, ?> getExtensionDelegate) {
        Intrinsics.checkNotNullParameter(getExtensionDelegate, "$this$getExtensionDelegate");
        return getExtensionDelegate.getDelegate(KPropertyImpl.INSTANCE.getEXTENSION_PROPERTY_DELEGATE());
    }

    @SinceKotlin(version = "1.1")
    @Nullable
    public static final <D> Object getExtensionDelegate(@NotNull KProperty2<D, ?, ?> getExtensionDelegate, D d2) {
        Intrinsics.checkNotNullParameter(getExtensionDelegate, "$this$getExtensionDelegate");
        return getExtensionDelegate.getDelegate(d2, KPropertyImpl.INSTANCE.getEXTENSION_PROPERTY_DELEGATE());
    }
}
