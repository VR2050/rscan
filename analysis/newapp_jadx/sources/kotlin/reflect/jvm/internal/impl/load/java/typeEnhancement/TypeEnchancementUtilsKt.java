package kotlin.reflect.jvm.internal.impl.load.java.typeEnhancement;

import java.util.Set;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.collections.SetsKt___SetsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.load.java.JvmAnnotationNames;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.types.TypeSystemCommonBackendContext;
import kotlin.reflect.jvm.internal.impl.types.model.KotlinTypeMarker;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class TypeEnchancementUtilsKt {
    @NotNull
    public static final JavaTypeQualifiers createJavaTypeQualifiers(@Nullable NullabilityQualifier nullabilityQualifier, @Nullable MutabilityQualifier mutabilityQualifier, boolean z, boolean z2) {
        return (z2 && nullabilityQualifier == NullabilityQualifier.NOT_NULL) ? new JavaTypeQualifiers(nullabilityQualifier, mutabilityQualifier, true, z) : new JavaTypeQualifiers(nullabilityQualifier, mutabilityQualifier, false, z);
    }

    public static final boolean hasEnhancedNullability(@NotNull TypeSystemCommonBackendContext typeSystemCommonBackendContext, @NotNull KotlinTypeMarker type) {
        Intrinsics.checkNotNullParameter(typeSystemCommonBackendContext, "<this>");
        Intrinsics.checkNotNullParameter(type, "type");
        FqName ENHANCED_NULLABILITY_ANNOTATION = JvmAnnotationNames.ENHANCED_NULLABILITY_ANNOTATION;
        Intrinsics.checkNotNullExpressionValue(ENHANCED_NULLABILITY_ANNOTATION, "ENHANCED_NULLABILITY_ANNOTATION");
        return typeSystemCommonBackendContext.hasAnnotation(type, ENHANCED_NULLABILITY_ANNOTATION);
    }

    @Nullable
    public static final <T> T select(@NotNull Set<? extends T> set, @NotNull T low, @NotNull T high, @Nullable T t, boolean z) {
        Set<? extends T> set2;
        Intrinsics.checkNotNullParameter(set, "<this>");
        Intrinsics.checkNotNullParameter(low, "low");
        Intrinsics.checkNotNullParameter(high, "high");
        if (!z) {
            if (t != null && (set2 = CollectionsKt___CollectionsKt.toSet(SetsKt___SetsKt.plus(set, t))) != null) {
                set = set2;
            }
            return (T) CollectionsKt___CollectionsKt.singleOrNull(set);
        }
        T t2 = set.contains(low) ? low : set.contains(high) ? high : null;
        if (Intrinsics.areEqual(t2, low) && Intrinsics.areEqual(t, high)) {
            return null;
        }
        return t == null ? t2 : t;
    }

    @Nullable
    public static final NullabilityQualifier select(@NotNull Set<? extends NullabilityQualifier> set, @Nullable NullabilityQualifier nullabilityQualifier, boolean z) {
        Intrinsics.checkNotNullParameter(set, "<this>");
        NullabilityQualifier nullabilityQualifier2 = NullabilityQualifier.FORCE_FLEXIBILITY;
        return nullabilityQualifier == nullabilityQualifier2 ? nullabilityQualifier2 : (NullabilityQualifier) select(set, NullabilityQualifier.NOT_NULL, NullabilityQualifier.NULLABLE, nullabilityQualifier, z);
    }
}
