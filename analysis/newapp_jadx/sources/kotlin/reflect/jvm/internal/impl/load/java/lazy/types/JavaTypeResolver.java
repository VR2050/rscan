package kotlin.reflect.jvm.internal.impl.load.java.lazy.types;

import java.util.List;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.jvm.internal.impl.builtins.PrimitiveType;
import kotlin.reflect.jvm.internal.impl.builtins.jvm.JavaToKotlinClassMapper;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import kotlin.reflect.jvm.internal.impl.load.java.components.TypeUsage;
import kotlin.reflect.jvm.internal.impl.load.java.lazy.LazyJavaAnnotations;
import kotlin.reflect.jvm.internal.impl.load.java.lazy.LazyJavaResolverContext;
import kotlin.reflect.jvm.internal.impl.load.java.lazy.TypeParameterResolver;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaArrayType;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaClass;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaClassifier;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaClassifierType;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaPrimitiveType;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaType;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaTypeParameter;
import kotlin.reflect.jvm.internal.impl.load.java.structure.JavaWildcardType;
import kotlin.reflect.jvm.internal.impl.name.ClassId;
import kotlin.reflect.jvm.internal.impl.name.FqName;
import kotlin.reflect.jvm.internal.impl.types.ErrorUtils;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.KotlinTypeFactory;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructor;
import kotlin.reflect.jvm.internal.impl.types.TypeProjection;
import kotlin.reflect.jvm.internal.impl.types.TypeProjectionImpl;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import kotlin.reflect.jvm.internal.impl.types.typeUtil.TypeUtilsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* loaded from: classes.dex */
public final class JavaTypeResolver {

    /* renamed from: c */
    @NotNull
    private final LazyJavaResolverContext f12089c;

    @NotNull
    private final TypeParameterResolver typeParameterResolver;

    public JavaTypeResolver(@NotNull LazyJavaResolverContext c2, @NotNull TypeParameterResolver typeParameterResolver) {
        Intrinsics.checkNotNullParameter(c2, "c");
        Intrinsics.checkNotNullParameter(typeParameterResolver, "typeParameterResolver");
        this.f12089c = c2;
        this.typeParameterResolver = typeParameterResolver;
    }

    private final boolean argumentsMakeSenseOnlyForMutableContainer(JavaClassifierType javaClassifierType, ClassDescriptor classDescriptor) {
        if (!argumentsMakeSenseOnlyForMutableContainer$isSuperWildcard((JavaType) CollectionsKt___CollectionsKt.lastOrNull((List) javaClassifierType.getTypeArguments()))) {
            return false;
        }
        List<TypeParameterDescriptor> parameters = JavaToKotlinClassMapper.INSTANCE.convertReadOnlyToMutable(classDescriptor).getTypeConstructor().getParameters();
        Intrinsics.checkNotNullExpressionValue(parameters, "JavaToKotlinClassMapper.convertReadOnlyToMutable(readOnlyContainer)\n            .typeConstructor.parameters");
        TypeParameterDescriptor typeParameterDescriptor = (TypeParameterDescriptor) CollectionsKt___CollectionsKt.lastOrNull((List) parameters);
        Variance variance = typeParameterDescriptor == null ? null : typeParameterDescriptor.getVariance();
        return (variance == null || variance == Variance.OUT_VARIANCE) ? false : true;
    }

    private static final boolean argumentsMakeSenseOnlyForMutableContainer$isSuperWildcard(JavaType javaType) {
        JavaWildcardType javaWildcardType = javaType instanceof JavaWildcardType ? (JavaWildcardType) javaType : null;
        return (javaWildcardType == null || javaWildcardType.getBound() == null || javaWildcardType.isExtends()) ? false : true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:6:0x0020, code lost:
    
        if ((!r4.isEmpty()) != false) goto L10;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.util.List<kotlin.reflect.jvm.internal.impl.types.TypeProjection> computeArguments(kotlin.reflect.jvm.internal.impl.load.java.structure.JavaClassifierType r9, final kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeAttributes r10, final kotlin.reflect.jvm.internal.impl.types.TypeConstructor r11) {
        /*
            r8 = this;
            boolean r0 = r9.isRaw()
            r1 = 0
            java.lang.String r2 = "constructor.parameters"
            r3 = 1
            if (r0 != 0) goto L24
            java.util.List r4 = r9.getTypeArguments()
            boolean r4 = r4.isEmpty()
            if (r4 == 0) goto L23
            java.util.List r4 = r11.getParameters()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r2)
            boolean r4 = r4.isEmpty()
            r4 = r4 ^ r3
            if (r4 == 0) goto L23
            goto L24
        L23:
            r3 = 0
        L24:
            java.util.List r4 = r11.getParameters()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r2)
            java.lang.String r2 = "parameter"
            r5 = 0
            r6 = 10
            if (r3 == 0) goto L87
            java.util.ArrayList r9 = new java.util.ArrayList
            int r1 = kotlin.collections.CollectionsKt__IterablesKt.collectionSizeOrDefault(r4, r6)
            r9.<init>(r1)
            java.util.Iterator r1 = r4.iterator()
        L3f:
            boolean r3 = r1.hasNext()
            if (r3 == 0) goto L82
            java.lang.Object r3 = r1.next()
            kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor r3 = (kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor) r3
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r2)
            kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor r4 = r10.getUpperBoundOfTypeParameter()
            boolean r4 = kotlin.reflect.jvm.internal.impl.types.typeUtil.TypeUtilsKt.hasTypeParameterRecursiveBounds(r3, r5, r4)
            if (r4 == 0) goto L5e
            kotlin.reflect.jvm.internal.impl.types.StarProjectionImpl r4 = new kotlin.reflect.jvm.internal.impl.types.StarProjectionImpl
            r4.<init>(r3)
            goto L7e
        L5e:
            kotlin.reflect.jvm.internal.impl.types.LazyWrappedType r4 = new kotlin.reflect.jvm.internal.impl.types.LazyWrappedType
            kotlin.reflect.jvm.internal.impl.load.java.lazy.LazyJavaResolverContext r6 = r8.f12089c
            kotlin.reflect.jvm.internal.impl.storage.StorageManager r6 = r6.getStorageManager()
            kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeResolver$computeArguments$1$erasedUpperBound$1 r7 = new kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeResolver$computeArguments$1$erasedUpperBound$1
            r7.<init>()
            r4.<init>(r6, r7)
            kotlin.reflect.jvm.internal.impl.load.java.lazy.types.RawSubstitution r6 = kotlin.reflect.jvm.internal.impl.load.java.lazy.types.RawSubstitution.INSTANCE
            if (r0 == 0) goto L74
            r7 = r10
            goto L7a
        L74:
            kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeFlexibility r7 = kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeFlexibility.INFLEXIBLE
            kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeAttributes r7 = r10.withFlexibility(r7)
        L7a:
            kotlin.reflect.jvm.internal.impl.types.TypeProjection r4 = r6.computeProjection(r3, r7, r4)
        L7e:
            r9.add(r4)
            goto L3f
        L82:
            java.util.List r9 = kotlin.collections.CollectionsKt___CollectionsKt.toList(r9)
            return r9
        L87:
            int r10 = r4.size()
            java.util.List r11 = r9.getTypeArguments()
            int r11 = r11.size()
            if (r10 == r11) goto Lc8
            java.util.ArrayList r9 = new java.util.ArrayList
            int r10 = kotlin.collections.CollectionsKt__IterablesKt.collectionSizeOrDefault(r4, r6)
            r9.<init>(r10)
            java.util.Iterator r10 = r4.iterator()
        La2:
            boolean r11 = r10.hasNext()
            if (r11 == 0) goto Lc3
            java.lang.Object r11 = r10.next()
            kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor r11 = (kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor) r11
            kotlin.reflect.jvm.internal.impl.types.TypeProjectionImpl r0 = new kotlin.reflect.jvm.internal.impl.types.TypeProjectionImpl
            kotlin.reflect.jvm.internal.impl.name.Name r11 = r11.getName()
            java.lang.String r11 = r11.asString()
            kotlin.reflect.jvm.internal.impl.types.SimpleType r11 = kotlin.reflect.jvm.internal.impl.types.ErrorUtils.createErrorType(r11)
            r0.<init>(r11)
            r9.add(r0)
            goto La2
        Lc3:
            java.util.List r9 = kotlin.collections.CollectionsKt___CollectionsKt.toList(r9)
            return r9
        Lc8:
            java.util.List r9 = r9.getTypeArguments()
            java.lang.Iterable r9 = kotlin.collections.CollectionsKt___CollectionsKt.withIndex(r9)
            java.util.ArrayList r10 = new java.util.ArrayList
            int r11 = kotlin.collections.CollectionsKt__IterablesKt.collectionSizeOrDefault(r9, r6)
            r10.<init>(r11)
            java.util.Iterator r9 = r9.iterator()
        Ldd:
            boolean r11 = r9.hasNext()
            if (r11 == 0) goto L10f
            java.lang.Object r11 = r9.next()
            kotlin.collections.IndexedValue r11 = (kotlin.collections.IndexedValue) r11
            int r0 = r11.getIndex()
            java.lang.Object r11 = r11.component2()
            kotlin.reflect.jvm.internal.impl.load.java.structure.JavaType r11 = (kotlin.reflect.jvm.internal.impl.load.java.structure.JavaType) r11
            int r3 = r4.size()
            java.lang.Object r0 = r4.get(r0)
            kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor r0 = (kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor) r0
            kotlin.reflect.jvm.internal.impl.load.java.components.TypeUsage r3 = kotlin.reflect.jvm.internal.impl.load.java.components.TypeUsage.COMMON
            r6 = 3
            kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeAttributes r3 = kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeResolverKt.toAttributes$default(r3, r1, r5, r6, r5)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            kotlin.reflect.jvm.internal.impl.types.TypeProjection r11 = r8.transformToTypeProjection(r11, r3, r0)
            r10.add(r11)
            goto Ldd
        L10f:
            java.util.List r9 = kotlin.collections.CollectionsKt___CollectionsKt.toList(r10)
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeResolver.computeArguments(kotlin.reflect.jvm.internal.impl.load.java.structure.JavaClassifierType, kotlin.reflect.jvm.internal.impl.load.java.lazy.types.JavaTypeAttributes, kotlin.reflect.jvm.internal.impl.types.TypeConstructor):java.util.List");
    }

    private final SimpleType computeSimpleJavaClassifierType(JavaClassifierType javaClassifierType, JavaTypeAttributes javaTypeAttributes, SimpleType simpleType) {
        Annotations annotations = simpleType == null ? null : simpleType.getAnnotations();
        if (annotations == null) {
            annotations = new LazyJavaAnnotations(this.f12089c, javaClassifierType, false, 4, null);
        }
        Annotations annotations2 = annotations;
        TypeConstructor computeTypeConstructor = computeTypeConstructor(javaClassifierType, javaTypeAttributes);
        if (computeTypeConstructor == null) {
            return null;
        }
        boolean isNullable = isNullable(javaTypeAttributes);
        if (Intrinsics.areEqual(simpleType != null ? simpleType.getConstructor() : null, computeTypeConstructor) && !javaClassifierType.isRaw() && isNullable) {
            return simpleType.makeNullableAsSpecified(true);
        }
        List<TypeProjection> computeArguments = computeArguments(javaClassifierType, javaTypeAttributes, computeTypeConstructor);
        KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
        return KotlinTypeFactory.simpleType$default(annotations2, computeTypeConstructor, computeArguments, isNullable, null, 16, null);
    }

    private final TypeConstructor computeTypeConstructor(JavaClassifierType javaClassifierType, JavaTypeAttributes javaTypeAttributes) {
        JavaClassifier classifier = javaClassifierType.getClassifier();
        if (classifier == null) {
            return createNotFoundClass(javaClassifierType);
        }
        if (!(classifier instanceof JavaClass)) {
            if (!(classifier instanceof JavaTypeParameter)) {
                throw new IllegalStateException(Intrinsics.stringPlus("Unknown classifier kind: ", classifier));
            }
            TypeParameterDescriptor resolveTypeParameter = this.typeParameterResolver.resolveTypeParameter((JavaTypeParameter) classifier);
            if (resolveTypeParameter == null) {
                return null;
            }
            return resolveTypeParameter.getTypeConstructor();
        }
        JavaClass javaClass = (JavaClass) classifier;
        FqName fqName = javaClass.getFqName();
        if (fqName == null) {
            throw new AssertionError(Intrinsics.stringPlus("Class type should have a FQ name: ", classifier));
        }
        ClassDescriptor mapKotlinClass = mapKotlinClass(javaClassifierType, javaTypeAttributes, fqName);
        if (mapKotlinClass == null) {
            mapKotlinClass = this.f12089c.getComponents().getModuleClassResolver().resolveClass(javaClass);
        }
        TypeConstructor typeConstructor = mapKotlinClass != null ? mapKotlinClass.getTypeConstructor() : null;
        return typeConstructor == null ? createNotFoundClass(javaClassifierType) : typeConstructor;
    }

    private final TypeConstructor createNotFoundClass(JavaClassifierType javaClassifierType) {
        ClassId classId = ClassId.topLevel(new FqName(javaClassifierType.getClassifierQualifiedName()));
        Intrinsics.checkNotNullExpressionValue(classId, "topLevel(FqName(javaType.classifierQualifiedName))");
        TypeConstructor typeConstructor = this.f12089c.getComponents().getDeserializedDescriptorResolver().getComponents().getNotFoundClasses().getClass(classId, CollectionsKt__CollectionsJVMKt.listOf(0)).getTypeConstructor();
        Intrinsics.checkNotNullExpressionValue(typeConstructor, "c.components.deserializedDescriptorResolver.components.notFoundClasses.getClass(classId, listOf(0)).typeConstructor");
        return typeConstructor;
    }

    private final boolean isConflictingArgumentFor(Variance variance, TypeParameterDescriptor typeParameterDescriptor) {
        return (typeParameterDescriptor.getVariance() == Variance.INVARIANT || variance == typeParameterDescriptor.getVariance()) ? false : true;
    }

    private final boolean isNullable(JavaTypeAttributes javaTypeAttributes) {
        return (javaTypeAttributes.getFlexibility() == JavaTypeFlexibility.FLEXIBLE_LOWER_BOUND || javaTypeAttributes.isForAnnotationParameter() || javaTypeAttributes.getHowThisTypeIsUsed() == TypeUsage.SUPERTYPE) ? false : true;
    }

    private final ClassDescriptor mapKotlinClass(JavaClassifierType javaClassifierType, JavaTypeAttributes javaTypeAttributes, FqName fqName) {
        FqName fqName2;
        if (javaTypeAttributes.isForAnnotationParameter()) {
            fqName2 = JavaTypeResolverKt.JAVA_LANG_CLASS_FQ_NAME;
            if (Intrinsics.areEqual(fqName, fqName2)) {
                return this.f12089c.getComponents().getReflectionTypes().getKClass();
            }
        }
        JavaToKotlinClassMapper javaToKotlinClassMapper = JavaToKotlinClassMapper.INSTANCE;
        ClassDescriptor mapJavaToKotlin$default = JavaToKotlinClassMapper.mapJavaToKotlin$default(javaToKotlinClassMapper, fqName, this.f12089c.getModule().getBuiltIns(), null, 4, null);
        if (mapJavaToKotlin$default == null) {
            return null;
        }
        return (javaToKotlinClassMapper.isReadOnly(mapJavaToKotlin$default) && (javaTypeAttributes.getFlexibility() == JavaTypeFlexibility.FLEXIBLE_LOWER_BOUND || javaTypeAttributes.getHowThisTypeIsUsed() == TypeUsage.SUPERTYPE || argumentsMakeSenseOnlyForMutableContainer(javaClassifierType, mapJavaToKotlin$default))) ? javaToKotlinClassMapper.convertReadOnlyToMutable(mapJavaToKotlin$default) : mapJavaToKotlin$default;
    }

    public static /* synthetic */ KotlinType transformArrayType$default(JavaTypeResolver javaTypeResolver, JavaArrayType javaArrayType, JavaTypeAttributes javaTypeAttributes, boolean z, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            z = false;
        }
        return javaTypeResolver.transformArrayType(javaArrayType, javaTypeAttributes, z);
    }

    private final KotlinType transformJavaClassifierType(JavaClassifierType javaClassifierType, JavaTypeAttributes javaTypeAttributes) {
        boolean z = (javaTypeAttributes.isForAnnotationParameter() || javaTypeAttributes.getHowThisTypeIsUsed() == TypeUsage.SUPERTYPE) ? false : true;
        boolean isRaw = javaClassifierType.isRaw();
        if (!isRaw && !z) {
            SimpleType computeSimpleJavaClassifierType = computeSimpleJavaClassifierType(javaClassifierType, javaTypeAttributes, null);
            return computeSimpleJavaClassifierType == null ? transformJavaClassifierType$errorType(javaClassifierType) : computeSimpleJavaClassifierType;
        }
        SimpleType computeSimpleJavaClassifierType2 = computeSimpleJavaClassifierType(javaClassifierType, javaTypeAttributes.withFlexibility(JavaTypeFlexibility.FLEXIBLE_LOWER_BOUND), null);
        if (computeSimpleJavaClassifierType2 == null) {
            return transformJavaClassifierType$errorType(javaClassifierType);
        }
        SimpleType computeSimpleJavaClassifierType3 = computeSimpleJavaClassifierType(javaClassifierType, javaTypeAttributes.withFlexibility(JavaTypeFlexibility.FLEXIBLE_UPPER_BOUND), computeSimpleJavaClassifierType2);
        if (computeSimpleJavaClassifierType3 == null) {
            return transformJavaClassifierType$errorType(javaClassifierType);
        }
        if (isRaw) {
            return new RawTypeImpl(computeSimpleJavaClassifierType2, computeSimpleJavaClassifierType3);
        }
        KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
        return KotlinTypeFactory.flexibleType(computeSimpleJavaClassifierType2, computeSimpleJavaClassifierType3);
    }

    private static final SimpleType transformJavaClassifierType$errorType(JavaClassifierType javaClassifierType) {
        SimpleType createErrorType = ErrorUtils.createErrorType(Intrinsics.stringPlus("Unresolved java class ", javaClassifierType.getPresentableText()));
        Intrinsics.checkNotNullExpressionValue(createErrorType, "createErrorType(\"Unresolved java class ${javaType.presentableText}\")");
        return createErrorType;
    }

    private final TypeProjection transformToTypeProjection(JavaType javaType, JavaTypeAttributes javaTypeAttributes, TypeParameterDescriptor typeParameterDescriptor) {
        if (!(javaType instanceof JavaWildcardType)) {
            return new TypeProjectionImpl(Variance.INVARIANT, transformJavaType(javaType, javaTypeAttributes));
        }
        JavaWildcardType javaWildcardType = (JavaWildcardType) javaType;
        JavaType bound = javaWildcardType.getBound();
        Variance variance = javaWildcardType.isExtends() ? Variance.OUT_VARIANCE : Variance.IN_VARIANCE;
        return (bound == null || isConflictingArgumentFor(variance, typeParameterDescriptor)) ? JavaTypeResolverKt.makeStarProjection(typeParameterDescriptor, javaTypeAttributes) : TypeUtilsKt.createProjection(transformJavaType(bound, JavaTypeResolverKt.toAttributes$default(TypeUsage.COMMON, false, null, 3, null)), variance, typeParameterDescriptor);
    }

    @NotNull
    public final KotlinType transformArrayType(@NotNull JavaArrayType arrayType, @NotNull JavaTypeAttributes attr, boolean z) {
        Intrinsics.checkNotNullParameter(arrayType, "arrayType");
        Intrinsics.checkNotNullParameter(attr, "attr");
        JavaType componentType = arrayType.getComponentType();
        JavaPrimitiveType javaPrimitiveType = componentType instanceof JavaPrimitiveType ? (JavaPrimitiveType) componentType : null;
        PrimitiveType type = javaPrimitiveType == null ? null : javaPrimitiveType.getType();
        LazyJavaAnnotations lazyJavaAnnotations = new LazyJavaAnnotations(this.f12089c, arrayType, true);
        if (type != null) {
            SimpleType primitiveArrayKotlinType = this.f12089c.getModule().getBuiltIns().getPrimitiveArrayKotlinType(type);
            Intrinsics.checkNotNullExpressionValue(primitiveArrayKotlinType, "c.module.builtIns.getPrimitiveArrayKotlinType(primitiveType)");
            primitiveArrayKotlinType.replaceAnnotations(Annotations.Companion.create(CollectionsKt___CollectionsKt.plus((Iterable) lazyJavaAnnotations, (Iterable) primitiveArrayKotlinType.getAnnotations())));
            if (attr.isForAnnotationParameter()) {
                return primitiveArrayKotlinType;
            }
            KotlinTypeFactory kotlinTypeFactory = KotlinTypeFactory.INSTANCE;
            return KotlinTypeFactory.flexibleType(primitiveArrayKotlinType, primitiveArrayKotlinType.makeNullableAsSpecified(true));
        }
        KotlinType transformJavaType = transformJavaType(componentType, JavaTypeResolverKt.toAttributes$default(TypeUsage.COMMON, attr.isForAnnotationParameter(), null, 2, null));
        if (attr.isForAnnotationParameter()) {
            SimpleType arrayType2 = this.f12089c.getModule().getBuiltIns().getArrayType(z ? Variance.OUT_VARIANCE : Variance.INVARIANT, transformJavaType, lazyJavaAnnotations);
            Intrinsics.checkNotNullExpressionValue(arrayType2, "c.module.builtIns.getArrayType(projectionKind, componentType, annotations)");
            return arrayType2;
        }
        KotlinTypeFactory kotlinTypeFactory2 = KotlinTypeFactory.INSTANCE;
        SimpleType arrayType3 = this.f12089c.getModule().getBuiltIns().getArrayType(Variance.INVARIANT, transformJavaType, lazyJavaAnnotations);
        Intrinsics.checkNotNullExpressionValue(arrayType3, "c.module.builtIns.getArrayType(INVARIANT, componentType, annotations)");
        return KotlinTypeFactory.flexibleType(arrayType3, this.f12089c.getModule().getBuiltIns().getArrayType(Variance.OUT_VARIANCE, transformJavaType, lazyJavaAnnotations).makeNullableAsSpecified(true));
    }

    @NotNull
    public final KotlinType transformJavaType(@Nullable JavaType javaType, @NotNull JavaTypeAttributes attr) {
        Intrinsics.checkNotNullParameter(attr, "attr");
        if (javaType instanceof JavaPrimitiveType) {
            PrimitiveType type = ((JavaPrimitiveType) javaType).getType();
            SimpleType primitiveKotlinType = type != null ? this.f12089c.getModule().getBuiltIns().getPrimitiveKotlinType(type) : this.f12089c.getModule().getBuiltIns().getUnitType();
            Intrinsics.checkNotNullExpressionValue(primitiveKotlinType, "{\n                val primitiveType = javaType.type\n                if (primitiveType != null) c.module.builtIns.getPrimitiveKotlinType(primitiveType)\n                else c.module.builtIns.unitType\n            }");
            return primitiveKotlinType;
        }
        if (javaType instanceof JavaClassifierType) {
            return transformJavaClassifierType((JavaClassifierType) javaType, attr);
        }
        if (javaType instanceof JavaArrayType) {
            return transformArrayType$default(this, (JavaArrayType) javaType, attr, false, 4, null);
        }
        if (!(javaType instanceof JavaWildcardType)) {
            if (javaType != null) {
                throw new UnsupportedOperationException(Intrinsics.stringPlus("Unsupported type: ", javaType));
            }
            SimpleType defaultBound = this.f12089c.getModule().getBuiltIns().getDefaultBound();
            Intrinsics.checkNotNullExpressionValue(defaultBound, "c.module.builtIns.defaultBound");
            return defaultBound;
        }
        JavaType bound = ((JavaWildcardType) javaType).getBound();
        KotlinType transformJavaType = bound == null ? null : transformJavaType(bound, attr);
        if (transformJavaType != null) {
            return transformJavaType;
        }
        SimpleType defaultBound2 = this.f12089c.getModule().getBuiltIns().getDefaultBound();
        Intrinsics.checkNotNullExpressionValue(defaultBound2, "c.module.builtIns.defaultBound");
        return defaultBound2;
    }
}
