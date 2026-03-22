package kotlin.reflect.jvm.internal;

import java.lang.reflect.GenericArrayType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.util.ArrayList;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.LazyThreadSafetyMode;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.reflect.KTypeProjection;
import kotlin.reflect.jvm.internal.impl.descriptors.runtime.structure.ReflectClassUtilKt;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.TypeProjection;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\u0010\u0005\u001a\u0016\u0012\u0004\u0012\u00020\u0001 \u0002*\n\u0012\u0004\u0012\u00020\u0001\u0018\u00010\u00000\u0000H\n¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {"", "Lkotlin/reflect/KTypeProjection;", "kotlin.jvm.PlatformType", "invoke", "()Ljava/util/List;", "<anonymous>"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class KTypeImpl$arguments$2 extends Lambda implements Function0<List<? extends KTypeProjection>> {
    public final /* synthetic */ Function0 $computeJavaType;
    public final /* synthetic */ KTypeImpl this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public KTypeImpl$arguments$2(KTypeImpl kTypeImpl, Function0 function0) {
        super(0);
        this.this$0 = kTypeImpl;
        this.$computeJavaType = function0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.jvm.functions.Function0
    public final List<? extends KTypeProjection> invoke() {
        KTypeProjection invariant;
        List<TypeProjection> arguments = this.this$0.getType().getArguments();
        if (arguments.isEmpty()) {
            return CollectionsKt__CollectionsKt.emptyList();
        }
        final Lazy lazy = LazyKt__LazyJVMKt.lazy(LazyThreadSafetyMode.PUBLICATION, (Function0) new Function0<List<? extends Type>>() { // from class: kotlin.reflect.jvm.internal.KTypeImpl$arguments$2$parameterizedTypeArguments$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final List<? extends Type> invoke() {
                Type javaType = KTypeImpl$arguments$2.this.this$0.getJavaType();
                Intrinsics.checkNotNull(javaType);
                return ReflectClassUtilKt.getParameterizedTypeArguments(javaType);
            }
        });
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arguments, 10));
        final int i2 = 0;
        for (Object obj : arguments) {
            int i3 = i2 + 1;
            if (i2 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            TypeProjection typeProjection = (TypeProjection) obj;
            if (typeProjection.isStarProjection()) {
                invariant = KTypeProjection.INSTANCE.getSTAR();
            } else {
                KotlinType type = typeProjection.getType();
                Intrinsics.checkNotNullExpressionValue(type, "typeProjection.type");
                Function0<Type> function0 = null;
                Object[] objArr = 0;
                if (this.$computeJavaType != null) {
                    final Object[] objArr2 = objArr == true ? 1 : 0;
                    function0 = new Function0<Type>() { // from class: kotlin.reflect.jvm.internal.KTypeImpl$arguments$2$$special$$inlined$mapIndexed$lambda$1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(0);
                        }

                        @Override // kotlin.jvm.functions.Function0
                        @NotNull
                        public final Type invoke() {
                            Type javaType = this.this$0.getJavaType();
                            if (javaType instanceof Class) {
                                Class cls = (Class) javaType;
                                Class componentType = cls.isArray() ? cls.getComponentType() : Object.class;
                                Intrinsics.checkNotNullExpressionValue(componentType, "if (javaType.isArray) ja…Type else Any::class.java");
                                return componentType;
                            }
                            if (javaType instanceof GenericArrayType) {
                                if (i2 == 0) {
                                    Type genericComponentType = ((GenericArrayType) javaType).getGenericComponentType();
                                    Intrinsics.checkNotNullExpressionValue(genericComponentType, "javaType.genericComponentType");
                                    return genericComponentType;
                                }
                                StringBuilder m586H = C1499a.m586H("Array type has been queried for a non-0th argument: ");
                                m586H.append(this.this$0);
                                throw new KotlinReflectionInternalError(m586H.toString());
                            }
                            if (!(javaType instanceof ParameterizedType)) {
                                StringBuilder m586H2 = C1499a.m586H("Non-generic type has been queried for arguments: ");
                                m586H2.append(this.this$0);
                                throw new KotlinReflectionInternalError(m586H2.toString());
                            }
                            Type type2 = (Type) ((List) lazy.getValue()).get(i2);
                            if (type2 instanceof WildcardType) {
                                WildcardType wildcardType = (WildcardType) type2;
                                Type[] lowerBounds = wildcardType.getLowerBounds();
                                Intrinsics.checkNotNullExpressionValue(lowerBounds, "argument.lowerBounds");
                                Type type3 = (Type) ArraysKt___ArraysKt.firstOrNull(lowerBounds);
                                if (type3 != null) {
                                    type2 = type3;
                                } else {
                                    Type[] upperBounds = wildcardType.getUpperBounds();
                                    Intrinsics.checkNotNullExpressionValue(upperBounds, "argument.upperBounds");
                                    type2 = (Type) ArraysKt___ArraysKt.first(upperBounds);
                                }
                            }
                            Intrinsics.checkNotNullExpressionValue(type2, "if (argument !is Wildcar…ument.upperBounds.first()");
                            return type2;
                        }
                    };
                }
                KTypeImpl kTypeImpl = new KTypeImpl(type, function0);
                int ordinal = typeProjection.getProjectionKind().ordinal();
                if (ordinal == 0) {
                    invariant = KTypeProjection.INSTANCE.invariant(kTypeImpl);
                } else if (ordinal == 1) {
                    invariant = KTypeProjection.INSTANCE.contravariant(kTypeImpl);
                } else {
                    if (ordinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    invariant = KTypeProjection.INSTANCE.covariant(kTypeImpl);
                }
            }
            arrayList.add(invariant);
            i2 = i3;
        }
        return arrayList;
    }
}
