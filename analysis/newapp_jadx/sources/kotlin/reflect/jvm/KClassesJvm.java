package kotlin.reflect.jvm;

import kotlin.Metadata;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KClass;
import kotlin.reflect.jvm.internal.KClassImpl;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\"\u001b\u0010\u0004\u001a\u00020\u0001*\u0006\u0012\u0002\b\u00030\u00008F@\u0006¢\u0006\u0006\u001a\u0004\b\u0002\u0010\u0003¨\u0006\u0005"}, m5311d2 = {"Lkotlin/reflect/KClass;", "", "getJvmName", "(Lkotlin/reflect/KClass;)Ljava/lang/String;", "jvmName", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KClassesJvm")
/* loaded from: classes.dex */
public final class KClassesJvm {
    @NotNull
    public static final String getJvmName(@NotNull KClass<?> jvmName) {
        Intrinsics.checkNotNullParameter(jvmName, "$this$jvmName");
        String name = ((KClassImpl) jvmName).getJClass().getName();
        Intrinsics.checkNotNullExpressionValue(name, "(this as KClassImpl).jClass.name");
        return name;
    }
}
