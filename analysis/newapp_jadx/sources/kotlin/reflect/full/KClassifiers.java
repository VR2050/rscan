package kotlin.reflect.full;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.SinceKotlin;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KClassifier;
import kotlin.reflect.KType;
import kotlin.reflect.KTypeProjection;
import kotlin.reflect.KVariance;
import kotlin.reflect.jvm.internal.KClassifierImpl;
import kotlin.reflect.jvm.internal.KTypeImpl;
import kotlin.reflect.jvm.internal.KotlinReflectionInternalError;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassifierDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.TypeParameterDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.annotations.Annotations;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.KotlinTypeFactory;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.StarProjectionImpl;
import kotlin.reflect.jvm.internal.impl.types.TypeConstructor;
import kotlin.reflect.jvm.internal.impl.types.TypeProjectionBase;
import kotlin.reflect.jvm.internal.impl.types.TypeProjectionImpl;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u001b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\u001a=\u0010\t\u001a\u00020\b*\u00020\u00002\u000e\b\u0002\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00020\u00012\b\b\u0002\u0010\u0005\u001a\u00020\u00042\u000e\b\u0002\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00060\u0001H\u0007¢\u0006\u0004\b\t\u0010\n\u001a5\u0010\u0010\u001a\u00020\u000f2\u0006\u0010\f\u001a\u00020\u000b2\u0006\u0010\u000e\u001a\u00020\r2\f\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0010\u0010\u0011\" \u0010\u0016\u001a\u00020\b*\u00020\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0012\u0010\u0013¨\u0006\u0017"}, m5311d2 = {"Lkotlin/reflect/KClassifier;", "", "Lkotlin/reflect/KTypeProjection;", "arguments", "", "nullable", "", "annotations", "Lkotlin/reflect/KType;", "createType", "(Lkotlin/reflect/KClassifier;Ljava/util/List;ZLjava/util/List;)Lkotlin/reflect/KType;", "Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/Annotations;", "typeAnnotations", "Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;", "typeConstructor", "Lkotlin/reflect/jvm/internal/impl/types/SimpleType;", "createKotlinType", "(Lkotlin/reflect/jvm/internal/impl/descriptors/annotations/Annotations;Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;Ljava/util/List;Z)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;", "getStarProjectedType", "(Lkotlin/reflect/KClassifier;)Lkotlin/reflect/KType;", "getStarProjectedType$annotations", "(Lkotlin/reflect/KClassifier;)V", "starProjectedType", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KClassifiers")
/* loaded from: classes2.dex */
public final class KClassifiers {

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {}, m5311d2 = {}, m5312k = 3, m5313mv = {1, 5, 1})
    public final /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            KVariance.values();
            int[] iArr = new int[3];
            $EnumSwitchMapping$0 = iArr;
            iArr[KVariance.INVARIANT.ordinal()] = 1;
            iArr[KVariance.IN.ordinal()] = 2;
            iArr[KVariance.OUT.ordinal()] = 3;
        }
    }

    private static final SimpleType createKotlinType(Annotations annotations, TypeConstructor typeConstructor, List<KTypeProjection> list, boolean z) {
        TypeProjectionBase typeProjectionImpl;
        List<TypeParameterDescriptor> parameters = typeConstructor.getParameters();
        Intrinsics.checkNotNullExpressionValue(parameters, "typeConstructor.parameters");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
        int i2 = 0;
        for (Object obj : list) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            KTypeProjection kTypeProjection = (KTypeProjection) obj;
            KTypeImpl kTypeImpl = (KTypeImpl) kTypeProjection.getType();
            KotlinType type = kTypeImpl != null ? kTypeImpl.getType() : null;
            KVariance variance = kTypeProjection.getVariance();
            if (variance == null) {
                TypeParameterDescriptor typeParameterDescriptor = parameters.get(i2);
                Intrinsics.checkNotNullExpressionValue(typeParameterDescriptor, "parameters[index]");
                typeProjectionImpl = new StarProjectionImpl(typeParameterDescriptor);
            } else {
                int ordinal = variance.ordinal();
                if (ordinal == 0) {
                    Variance variance2 = Variance.INVARIANT;
                    Intrinsics.checkNotNull(type);
                    typeProjectionImpl = new TypeProjectionImpl(variance2, type);
                } else if (ordinal == 1) {
                    Variance variance3 = Variance.IN_VARIANCE;
                    Intrinsics.checkNotNull(type);
                    typeProjectionImpl = new TypeProjectionImpl(variance3, type);
                } else {
                    if (ordinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    Variance variance4 = Variance.OUT_VARIANCE;
                    Intrinsics.checkNotNull(type);
                    typeProjectionImpl = new TypeProjectionImpl(variance4, type);
                }
            }
            arrayList.add(typeProjectionImpl);
            i2 = i3;
        }
        return KotlinTypeFactory.simpleType$default(annotations, typeConstructor, arrayList, z, null, 16, null);
    }

    @SinceKotlin(version = "1.1")
    @NotNull
    public static final KType createType(@NotNull KClassifier createType, @NotNull List<KTypeProjection> arguments, boolean z, @NotNull List<? extends Annotation> annotations) {
        ClassifierDescriptor descriptor;
        Intrinsics.checkNotNullParameter(createType, "$this$createType");
        Intrinsics.checkNotNullParameter(arguments, "arguments");
        Intrinsics.checkNotNullParameter(annotations, "annotations");
        KClassifierImpl kClassifierImpl = (KClassifierImpl) (!(createType instanceof KClassifierImpl) ? null : createType);
        if (kClassifierImpl == null || (descriptor = kClassifierImpl.getDescriptor()) == null) {
            throw new KotlinReflectionInternalError("Cannot create type for an unsupported classifier: " + createType + " (" + createType.getClass() + ')');
        }
        TypeConstructor typeConstructor = descriptor.getTypeConstructor();
        Intrinsics.checkNotNullExpressionValue(typeConstructor, "descriptor.typeConstructor");
        List<TypeParameterDescriptor> parameters = typeConstructor.getParameters();
        Intrinsics.checkNotNullExpressionValue(parameters, "typeConstructor.parameters");
        if (parameters.size() == arguments.size()) {
            return new KTypeImpl(createKotlinType(annotations.isEmpty() ? Annotations.Companion.getEMPTY() : Annotations.Companion.getEMPTY(), typeConstructor, arguments, z), null, 2, null);
        }
        StringBuilder m586H = C1499a.m586H("Class declares ");
        m586H.append(parameters.size());
        m586H.append(" type parameters, but ");
        m586H.append(arguments.size());
        m586H.append(" were provided.");
        throw new IllegalArgumentException(m586H.toString());
    }

    public static /* synthetic */ KType createType$default(KClassifier kClassifier, List list, boolean z, List list2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            list = CollectionsKt__CollectionsKt.emptyList();
        }
        if ((i2 & 2) != 0) {
            z = false;
        }
        if ((i2 & 4) != 0) {
            list2 = CollectionsKt__CollectionsKt.emptyList();
        }
        return createType(kClassifier, list, z, list2);
    }

    @NotNull
    public static final KType getStarProjectedType(@NotNull KClassifier starProjectedType) {
        ClassifierDescriptor descriptor;
        Intrinsics.checkNotNullParameter(starProjectedType, "$this$starProjectedType");
        KClassifierImpl kClassifierImpl = (KClassifierImpl) (!(starProjectedType instanceof KClassifierImpl) ? null : starProjectedType);
        if (kClassifierImpl == null || (descriptor = kClassifierImpl.getDescriptor()) == null) {
            return createType$default(starProjectedType, null, false, null, 7, null);
        }
        TypeConstructor typeConstructor = descriptor.getTypeConstructor();
        Intrinsics.checkNotNullExpressionValue(typeConstructor, "descriptor.typeConstructor");
        List<TypeParameterDescriptor> parameters = typeConstructor.getParameters();
        Intrinsics.checkNotNullExpressionValue(parameters, "descriptor.typeConstructor.parameters");
        if (parameters.isEmpty()) {
            return createType$default(starProjectedType, null, false, null, 7, null);
        }
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(parameters, 10));
        for (TypeParameterDescriptor typeParameterDescriptor : parameters) {
            arrayList.add(KTypeProjection.INSTANCE.getSTAR());
        }
        return createType$default(starProjectedType, arrayList, false, null, 6, null);
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getStarProjectedType$annotations(KClassifier kClassifier) {
    }
}
