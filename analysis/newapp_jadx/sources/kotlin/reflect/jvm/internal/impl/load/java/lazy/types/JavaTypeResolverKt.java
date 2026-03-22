package kotlin.reflect.jvm.internal.impl.load.java.lazy.types;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import kotlin.Pair;
import kotlin.TuplesKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.collections.MapsKt__MapsJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassifierDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.load.java.components.TypeUsage;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.types.ErrorUtils;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.StarProjectionImpl;
import kotlin.reflect.jvm.internal.impl.types.StarProjectionImplKt;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructorSubstitution;
import kotlin.reflect.jvm.internal.impl.types.TypeProjection;
import kotlin.reflect.jvm.internal.impl.types.TypeProjectionImpl;
import kotlin.reflect.jvm.internal.impl.types.TypeSubstitutor;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import kotlin.reflect.jvm.internal.impl.types.typeUtil.TypeUtilsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class JavaTypeResolverKt {

    @NotNull
    private static final FqName JAVA_LANG_CLASS_FQ_NAME = new FqName("java.lang.Class");

    @NotNull
    public static final KotlinType getErasedUpperBound(@NotNull TypeParameterDescriptor typeParameterDescriptor, boolean z, @NotNull JavaTypeAttributes typeAttr, @NotNull Function0<? extends KotlinType> defaultValue) {
        Intrinsics.checkNotNullParameter(typeParameterDescriptor, "<this>");
        Intrinsics.checkNotNullParameter(typeAttr, "typeAttr");
        Intrinsics.checkNotNullParameter(defaultValue, "defaultValue");
        if (typeParameterDescriptor == typeAttr.getUpperBoundOfTypeParameter()) {
            return defaultValue.invoke();
        }
        JavaTypeAttributes withTypeParameter = typeAttr.getUpperBoundOfTypeParameter() == null ? typeAttr.withTypeParameter(typeParameterDescriptor) : typeAttr;
        SimpleType defaultType = typeParameterDescriptor.getDefaultType();
        Intrinsics.checkNotNullExpressionValue(defaultType, "defaultType");
        Set<TypeParameterDescriptor> extractTypeParametersFromUpperBounds = TypeUtilsKt.extractTypeParametersFromUpperBounds(defaultType, typeAttr.getUpperBoundOfTypeParameter());
        LinkedHashMap linkedHashMap = new LinkedHashMap(RangesKt___RangesKt.coerceAtLeast(MapsKt__MapsJVMKt.mapCapacity(CollectionsKt__IterablesKt.collectionSizeOrDefault(extractTypeParametersFromUpperBounds, 10)), 16));
        for (TypeParameterDescriptor typeParameterDescriptor2 : extractTypeParametersFromUpperBounds) {
            Pair m5318to = TuplesKt.m5318to(typeParameterDescriptor2.getTypeConstructor(), typeParameterDescriptor2 != typeAttr.getUpperBoundOfTypeParameter() ? RawSubstitution.INSTANCE.computeProjection(typeParameterDescriptor2, z ? typeAttr : typeAttr.withFlexibility(JavaTypeFlexibility.INFLEXIBLE), typeParameterDescriptor2 != typeAttr.getUpperBoundOfTypeParameter() ? getErasedUpperBound$default(typeParameterDescriptor2, z, withTypeParameter, null, 4, null) : StarProjectionImplKt.starProjectionType(typeParameterDescriptor2)) : makeStarProjection(typeParameterDescriptor2, typeAttr));
            linkedHashMap.put(m5318to.getFirst(), m5318to.getSecond());
        }
        TypeSubstitutor create = TypeSubstitutor.create(TypeConstructorSubstitution.Companion.createByConstructorsMap$default(TypeConstructorSubstitution.Companion, linkedHashMap, false, 2, null));
        Intrinsics.checkNotNullExpressionValue(create, "create(TypeConstructorSubstitution.createByConstructorsMap(erasedUpperBounds))");
        List<KotlinType> upperBounds = typeParameterDescriptor.getUpperBounds();
        Intrinsics.checkNotNullExpressionValue(upperBounds, "upperBounds");
        KotlinType firstUpperBound = (KotlinType) CollectionsKt___CollectionsKt.first((List) upperBounds);
        if (firstUpperBound.getConstructor().mo7311getDeclarationDescriptor() instanceof ClassDescriptor) {
            Intrinsics.checkNotNullExpressionValue(firstUpperBound, "firstUpperBound");
            return TypeUtilsKt.replaceArgumentsWithStarProjectionOrMapped(firstUpperBound, create, linkedHashMap, Variance.OUT_VARIANCE, typeAttr.getUpperBoundOfTypeParameter());
        }
        TypeParameterDescriptor upperBoundOfTypeParameter = typeAttr.getUpperBoundOfTypeParameter();
        if (upperBoundOfTypeParameter != null) {
            typeParameterDescriptor = upperBoundOfTypeParameter;
        }
        ClassifierDescriptor mo7311getDeclarationDescriptor = firstUpperBound.getConstructor().mo7311getDeclarationDescriptor();
        Objects.requireNonNull(mo7311getDeclarationDescriptor, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.TypeParameterDescriptor");
        while (true) {
            TypeParameterDescriptor typeParameterDescriptor3 = (TypeParameterDescriptor) mo7311getDeclarationDescriptor;
            if (Intrinsics.areEqual(typeParameterDescriptor3, typeParameterDescriptor)) {
                return defaultValue.invoke();
            }
            List<KotlinType> upperBounds2 = typeParameterDescriptor3.getUpperBounds();
            Intrinsics.checkNotNullExpressionValue(upperBounds2, "current.upperBounds");
            KotlinType nextUpperBound = (KotlinType) CollectionsKt___CollectionsKt.first((List) upperBounds2);
            if (nextUpperBound.getConstructor().mo7311getDeclarationDescriptor() instanceof ClassDescriptor) {
                Intrinsics.checkNotNullExpressionValue(nextUpperBound, "nextUpperBound");
                return TypeUtilsKt.replaceArgumentsWithStarProjectionOrMapped(nextUpperBound, create, linkedHashMap, Variance.OUT_VARIANCE, typeAttr.getUpperBoundOfTypeParameter());
            }
            mo7311getDeclarationDescriptor = nextUpperBound.getConstructor().mo7311getDeclarationDescriptor();
            Objects.requireNonNull(mo7311getDeclarationDescriptor, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.TypeParameterDescriptor");
        }
    }

    public static /* synthetic */ KotlinType getErasedUpperBound$default(final TypeParameterDescriptor typeParameterDescriptor, boolean z, JavaTypeAttributes javaTypeAttributes, Function0 function0, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function0 = new Function0<SimpleType>() { // from class: kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeResolverKt$getErasedUpperBound$1
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final SimpleType invoke() {
                    StringBuilder m586H = C1499a.m586H("Can't compute erased upper bound of type parameter `");
                    m586H.append(TypeParameterDescriptor.this);
                    m586H.append('`');
                    SimpleType createErrorType = ErrorUtils.createErrorType(m586H.toString());
                    Intrinsics.checkNotNullExpressionValue(createErrorType, "createErrorType(\"Can't compute erased upper bound of type parameter `$this`\")");
                    return createErrorType;
                }
            };
        }
        return getErasedUpperBound(typeParameterDescriptor, z, javaTypeAttributes, function0);
    }

    @NotNull
    public static final TypeProjection makeStarProjection(@NotNull TypeParameterDescriptor typeParameter, @NotNull JavaTypeAttributes attr) {
        Intrinsics.checkNotNullParameter(typeParameter, "typeParameter");
        Intrinsics.checkNotNullParameter(attr, "attr");
        return attr.getHowThisTypeIsUsed() == TypeUsage.SUPERTYPE ? new TypeProjectionImpl(StarProjectionImplKt.starProjectionType(typeParameter)) : new StarProjectionImpl(typeParameter);
    }

    @NotNull
    public static final JavaTypeAttributes toAttributes(@NotNull TypeUsage typeUsage, boolean z, @Nullable TypeParameterDescriptor typeParameterDescriptor) {
        Intrinsics.checkNotNullParameter(typeUsage, "<this>");
        return new JavaTypeAttributes(typeUsage, null, z, typeParameterDescriptor, 2, null);
    }

    public static /* synthetic */ JavaTypeAttributes toAttributes$default(TypeUsage typeUsage, boolean z, TypeParameterDescriptor typeParameterDescriptor, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        if ((i2 & 2) != 0) {
            typeParameterDescriptor = null;
        }
        return toAttributes(typeUsage, z, typeParameterDescriptor);
    }
}
