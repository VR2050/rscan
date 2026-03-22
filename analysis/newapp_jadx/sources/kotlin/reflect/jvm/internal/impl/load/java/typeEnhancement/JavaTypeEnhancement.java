package kotlin.reflect.jvm.internal.impl.load.java.typeEnhancement;

import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassifierDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import kotlin.reflect.jvm.internal.impl.load.java.lazy.JavaResolverSettings;
import kotlin.reflect.jvm.internal.impl.load.java.lazy.types.RawTypeImpl;
import kotlin.reflect.jvm.internal.impl.types.FlexibleType;
import kotlin.reflect.jvm.internal.impl.types.FlexibleTypesKt;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.KotlinTypeFactory;
import kotlin.reflect.jvm.internal.impl.types.KotlinTypeKt;
import kotlin.reflect.jvm.internal.impl.types.RawType;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.SpecialTypesKt;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructor;
import kotlin.reflect.jvm.internal.impl.types.TypeProjection;
import kotlin.reflect.jvm.internal.impl.types.TypeUtils;
import kotlin.reflect.jvm.internal.impl.types.TypeWithEnhancementKt;
import kotlin.reflect.jvm.internal.impl.types.UnwrappedType;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import kotlin.reflect.jvm.internal.impl.types.typeUtil.TypeUtilsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class JavaTypeEnhancement {

    @NotNull
    private final JavaResolverSettings javaResolverSettings;

    public static class Result {
        private final int subtreeSize;

        @NotNull
        private final KotlinType type;
        private final boolean wereChanges;

        public Result(@NotNull KotlinType type, int i2, boolean z) {
            Intrinsics.checkNotNullParameter(type, "type");
            this.type = type;
            this.subtreeSize = i2;
            this.wereChanges = z;
        }

        public final int getSubtreeSize() {
            return this.subtreeSize;
        }

        @NotNull
        public KotlinType getType() {
            return this.type;
        }

        @Nullable
        public final KotlinType getTypeIfChanged() {
            KotlinType type = getType();
            if (getWereChanges()) {
                return type;
            }
            return null;
        }

        public final boolean getWereChanges() {
            return this.wereChanges;
        }
    }

    public static final class SimpleResult extends Result {

        @NotNull
        private final SimpleType type;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public SimpleResult(@NotNull SimpleType type, int i2, boolean z) {
            super(type, i2, z);
            Intrinsics.checkNotNullParameter(type, "type");
            this.type = type;
        }

        @Override // kotlin.reflect.jvm.internal.impl.load.java.typeEnhancement.JavaTypeEnhancement.Result
        @NotNull
        public SimpleType getType() {
            return this.type;
        }
    }

    public JavaTypeEnhancement(@NotNull JavaResolverSettings javaResolverSettings) {
        Intrinsics.checkNotNullParameter(javaResolverSettings, "javaResolverSettings");
        this.javaResolverSettings = javaResolverSettings;
    }

    private final KotlinType buildEnhancementByFlexibleTypeBounds(KotlinType kotlinType, KotlinType kotlinType2) {
        KotlinType enhancement = TypeWithEnhancementKt.getEnhancement(kotlinType2);
        KotlinType enhancement2 = TypeWithEnhancementKt.getEnhancement(kotlinType);
        if (enhancement2 == null) {
            if (enhancement == null) {
                return null;
            }
            enhancement2 = enhancement;
        }
        if (enhancement == null) {
            return enhancement2;
        }
        KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
        return KotlinTypeFactory.flexibleType(FlexibleTypesKt.lowerIfFlexible(enhancement2), FlexibleTypesKt.upperIfFlexible(enhancement));
    }

    private final SimpleResult enhanceInflexible(SimpleType simpleType, Function1<? super Integer, JavaTypeQualifiers> function1, int i2, TypeComponentPosition typeComponentPosition, boolean z) {
        EnhancementResult enhanceMutability;
        EnhancementResult enhancedNullability;
        Annotations compositeAnnotationsOrSingle;
        int subtreeSize;
        TypeProjection createProjection;
        if (!TypeComponentPositionKt.shouldEnhance(typeComponentPosition) && simpleType.getArguments().isEmpty()) {
            return new SimpleResult(simpleType, 1, false);
        }
        ClassifierDescriptor mo7311getDeclarationDescriptor = simpleType.getConstructor().mo7311getDeclarationDescriptor();
        if (mo7311getDeclarationDescriptor == null) {
            return new SimpleResult(simpleType, 1, false);
        }
        JavaTypeQualifiers invoke = function1.invoke(Integer.valueOf(i2));
        enhanceMutability = TypeEnhancementKt.enhanceMutability(mo7311getDeclarationDescriptor, invoke, typeComponentPosition);
        ClassifierDescriptor classifierDescriptor = (ClassifierDescriptor) enhanceMutability.component1();
        Annotations component2 = enhanceMutability.component2();
        TypeConstructor typeConstructor = classifierDescriptor.getTypeConstructor();
        Intrinsics.checkNotNullExpressionValue(typeConstructor, "enhancedClassifier.typeConstructor");
        int i3 = i2 + 1;
        boolean z2 = component2 != null;
        List<TypeProjection> arguments = simpleType.getArguments();
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arguments, 10));
        int i4 = 0;
        for (Object obj : arguments) {
            int i5 = i4 + 1;
            if (i4 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            TypeProjection typeProjection = (TypeProjection) obj;
            if (typeProjection.isStarProjection()) {
                subtreeSize = i3 + 1;
                if (function1.invoke(Integer.valueOf(i3)).getNullability() != NullabilityQualifier.NOT_NULL || z) {
                    createProjection = TypeUtils.makeStarProjection(classifierDescriptor.getTypeConstructor().getParameters().get(i4));
                    Intrinsics.checkNotNullExpressionValue(createProjection, "{\n                    TypeUtils.makeStarProjection(enhancedClassifier.typeConstructor.parameters[localArgIndex])\n                }");
                } else {
                    KotlinType makeNotNullable = TypeUtilsKt.makeNotNullable(typeProjection.getType().unwrap());
                    Variance projectionKind = typeProjection.getProjectionKind();
                    Intrinsics.checkNotNullExpressionValue(projectionKind, "arg.projectionKind");
                    createProjection = TypeUtilsKt.createProjection(makeNotNullable, projectionKind, typeConstructor.getParameters().get(i4));
                }
            } else {
                Result enhancePossiblyFlexible = enhancePossiblyFlexible(typeProjection.getType().unwrap(), function1, i3);
                z2 = z2 || enhancePossiblyFlexible.getWereChanges();
                subtreeSize = enhancePossiblyFlexible.getSubtreeSize() + i3;
                KotlinType type = enhancePossiblyFlexible.getType();
                Variance projectionKind2 = typeProjection.getProjectionKind();
                Intrinsics.checkNotNullExpressionValue(projectionKind2, "arg.projectionKind");
                createProjection = TypeUtilsKt.createProjection(type, projectionKind2, typeConstructor.getParameters().get(i4));
            }
            i3 = subtreeSize;
            arrayList.add(createProjection);
            i4 = i5;
        }
        enhancedNullability = TypeEnhancementKt.getEnhancedNullability(simpleType, invoke, typeComponentPosition);
        boolean booleanValue = ((Boolean) enhancedNullability.component1()).booleanValue();
        Annotations component22 = enhancedNullability.component2();
        int i6 = i3 - i2;
        if (!(z2 || component22 != null)) {
            return new SimpleResult(simpleType, i6, false);
        }
        boolean z3 = false;
        compositeAnnotationsOrSingle = TypeEnhancementKt.compositeAnnotationsOrSingle(CollectionsKt__CollectionsKt.listOfNotNull((Object[]) new Annotations[]{simpleType.getAnnotations(), component2, component22}));
        KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
        SimpleType simpleType$default = KotlinTypeFactory.simpleType$default(compositeAnnotationsOrSingle, typeConstructor, arrayList, booleanValue, null, 16, null);
        UnwrappedType unwrappedType = simpleType$default;
        if (invoke.isNotNullTypeParameter()) {
            unwrappedType = notNullTypeParameter(simpleType$default);
        }
        if (component22 != null && invoke.isNullabilityQualifierForWarning()) {
            z3 = true;
        }
        if (z3) {
            unwrappedType = TypeWithEnhancementKt.wrapEnhancement(simpleType, unwrappedType);
        }
        return new SimpleResult((SimpleType) unwrappedType, i6, true);
    }

    public static /* synthetic */ SimpleResult enhanceInflexible$default(JavaTypeEnhancement javaTypeEnhancement, SimpleType simpleType, Function1 function1, int i2, TypeComponentPosition typeComponentPosition, boolean z, int i3, Object obj) {
        return javaTypeEnhancement.enhanceInflexible(simpleType, function1, i2, typeComponentPosition, (i3 & 8) != 0 ? false : z);
    }

    private final Result enhancePossiblyFlexible(UnwrappedType unwrappedType, Function1<? super Integer, JavaTypeQualifiers> function1, int i2) {
        UnwrappedType flexibleType;
        if (KotlinTypeKt.isError(unwrappedType)) {
            return new Result(unwrappedType, 1, false);
        }
        if (!(unwrappedType instanceof FlexibleType)) {
            if (unwrappedType instanceof SimpleType) {
                return enhanceInflexible$default(this, (SimpleType) unwrappedType, function1, i2, TypeComponentPosition.INFLEXIBLE, false, 8, null);
            }
            throw new NoWhenBranchMatchedException();
        }
        boolean z = unwrappedType instanceof RawType;
        FlexibleType flexibleType2 = (FlexibleType) unwrappedType;
        SimpleResult enhanceInflexible = enhanceInflexible(flexibleType2.getLowerBound(), function1, i2, TypeComponentPosition.FLEXIBLE_LOWER, z);
        SimpleResult enhanceInflexible2 = enhanceInflexible(flexibleType2.getUpperBound(), function1, i2, TypeComponentPosition.FLEXIBLE_UPPER, z);
        enhanceInflexible.getSubtreeSize();
        enhanceInflexible2.getSubtreeSize();
        boolean z2 = enhanceInflexible.getWereChanges() || enhanceInflexible2.getWereChanges();
        KotlinType buildEnhancementByFlexibleTypeBounds = buildEnhancementByFlexibleTypeBounds(enhanceInflexible.getType(), enhanceInflexible2.getType());
        if (z2) {
            if (unwrappedType instanceof RawTypeImpl) {
                flexibleType = new RawTypeImpl(enhanceInflexible.getType(), enhanceInflexible2.getType());
            } else {
                KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
                flexibleType = KotlinTypeFactory.flexibleType(enhanceInflexible.getType(), enhanceInflexible2.getType());
            }
            unwrappedType = TypeWithEnhancementKt.wrapEnhancement(flexibleType, buildEnhancementByFlexibleTypeBounds);
        }
        return new Result(unwrappedType, enhanceInflexible.getSubtreeSize(), z2);
    }

    private final SimpleType notNullTypeParameter(SimpleType simpleType) {
        return this.javaResolverSettings.getCorrectNullabilityForNotNullTypeParameter() ? SpecialTypesKt.makeSimpleTypeDefinitelyNotNullOrNotNull(simpleType, true) : new NotNullTypeParameter(simpleType);
    }

    @Nullable
    public final KotlinType enhance(@NotNull KotlinType kotlinType, @NotNull Function1<? super Integer, JavaTypeQualifiers> qualifiers) {
        Intrinsics.checkNotNullParameter(kotlinType, "<this>");
        Intrinsics.checkNotNullParameter(qualifiers, "qualifiers");
        return enhancePossiblyFlexible(kotlinType.unwrap(), qualifiers, 0).getTypeIfChanged();
    }
}
