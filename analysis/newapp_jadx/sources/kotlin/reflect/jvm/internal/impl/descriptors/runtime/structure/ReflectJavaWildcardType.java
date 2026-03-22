package kotlin.reflect.jvm.internal.impl.descriptors.runtime.structure;

import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.util.Collection;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.runtime.structure.ReflectJavaType;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaAnnotation;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaWildcardType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class ReflectJavaWildcardType extends ReflectJavaType implements JavaWildcardType {

    @NotNull
    private final Collection<JavaAnnotation> annotations;
    private final boolean isDeprecatedInJavaDoc;

    @NotNull
    private final WildcardType reflectType;

    public ReflectJavaWildcardType(@NotNull WildcardType reflectType) {
        Intrinsics.checkNotNullParameter(reflectType, "reflectType");
        this.reflectType = reflectType;
        this.annotations = CollectionsKt__CollectionsKt.emptyList();
    }

    @Override // kotlin.reflect.jvm.internal.impl.load.java.structure.JavaAnnotationOwner
    @NotNull
    public Collection<JavaAnnotation> getAnnotations() {
        return this.annotations;
    }

    @Override // kotlin.reflect.jvm.internal.impl.load.java.structure.JavaAnnotationOwner
    public boolean isDeprecatedInJavaDoc() {
        return this.isDeprecatedInJavaDoc;
    }

    @Override // kotlin.reflect.jvm.internal.impl.load.java.structure.JavaWildcardType
    public boolean isExtends() {
        Intrinsics.checkNotNullExpressionValue(getReflectType().getUpperBounds(), "reflectType.upperBounds");
        return !Intrinsics.areEqual(ArraysKt___ArraysKt.firstOrNull(r0), Object.class);
    }

    @Override // kotlin.reflect.jvm.internal.impl.load.java.structure.JavaWildcardType
    @Nullable
    public ReflectJavaType getBound() {
        Type[] upperBounds = getReflectType().getUpperBounds();
        Type[] lowerBounds = getReflectType().getLowerBounds();
        if (upperBounds.length > 1 || lowerBounds.length > 1) {
            throw new UnsupportedOperationException(Intrinsics.stringPlus("Wildcard types with many bounds are not yet supported: ", getReflectType()));
        }
        if (lowerBounds.length == 1) {
            ReflectJavaType.Factory factory = ReflectJavaType.Factory;
            Intrinsics.checkNotNullExpressionValue(lowerBounds, "lowerBounds");
            Object single = ArraysKt___ArraysKt.single(lowerBounds);
            Intrinsics.checkNotNullExpressionValue(single, "lowerBounds.single()");
            return factory.create((Type) single);
        }
        if (upperBounds.length != 1) {
            return null;
        }
        Intrinsics.checkNotNullExpressionValue(upperBounds, "upperBounds");
        Type ub = (Type) ArraysKt___ArraysKt.single(upperBounds);
        if (Intrinsics.areEqual(ub, Object.class)) {
            return null;
        }
        ReflectJavaType.Factory factory2 = ReflectJavaType.Factory;
        Intrinsics.checkNotNullExpressionValue(ub, "ub");
        return factory2.create(ub);
    }

    @Override // kotlin.reflect.jvm.internal.impl.descriptors.runtime.structure.ReflectJavaType
    @NotNull
    public WildcardType getReflectType() {
        return this.reflectType;
    }
}
