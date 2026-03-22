package kotlin.reflect.full;

import androidx.exifinterface.media.ExifInterface;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import kotlin.Deprecated;
import kotlin.Metadata;
import kotlin.SinceKotlin;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.MapsKt__MapsKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KCallable;
import kotlin.reflect.KClass;
import kotlin.reflect.KClassifier;
import kotlin.reflect.KFunction;
import kotlin.reflect.KParameter;
import kotlin.reflect.KProperty0;
import kotlin.reflect.KProperty1;
import kotlin.reflect.KProperty2;
import kotlin.reflect.KType;
import kotlin.reflect.jvm.internal.KCallableImpl;
import kotlin.reflect.jvm.internal.KClassImpl;
import kotlin.reflect.jvm.internal.KFunctionImpl;
import kotlin.reflect.jvm.internal.KTypeImpl;
import kotlin.reflect.jvm.internal.KotlinReflectionInternalError;
import kotlin.reflect.jvm.internal.impl.descriptors.ConstructorDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.FunctionDescriptor;
import kotlin.reflect.jvm.internal.impl.types.KotlinType;
import kotlin.reflect.jvm.internal.impl.types.SimpleType;
import kotlin.reflect.jvm.internal.impl.types.TypeSubstitutor;
import kotlin.reflect.jvm.internal.impl.types.Variance;
import kotlin.reflect.jvm.internal.impl.utils.DFS;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0010\u0000\n\u0002\b\u0007\n\u0002\u0010\u001e\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0010 \n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\u0007\u001a#\u0010\u0003\u001a\u00020\u0002*\u0006\u0012\u0002\b\u00030\u00002\n\u0010\u0001\u001a\u0006\u0012\u0002\b\u00030\u0000H\u0007¢\u0006\u0004\b\u0003\u0010\u0004\u001a#\u0010\u0006\u001a\u00020\u0002*\u0006\u0012\u0002\b\u00030\u00002\n\u0010\u0005\u001a\u0006\u0012\u0002\b\u00030\u0000H\u0007¢\u0006\u0004\b\u0006\u0010\u0004\u001a-\u0010\n\u001a\u00028\u0000\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00002\b\u0010\t\u001a\u0004\u0018\u00010\u0007H\u0007¢\u0006\u0004\b\n\u0010\u000b\u001a/\u0010\f\u001a\u0004\u0018\u00018\u0000\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00002\b\u0010\t\u001a\u0004\u0018\u00010\u0007H\u0007¢\u0006\u0004\b\f\u0010\u000b\u001a#\u0010\r\u001a\u00028\u0000\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u0000H\u0007¢\u0006\u0004\b\r\u0010\u000e\".\u0010\u0015\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0011\u0010\u0012\".\u0010\u0018\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b\u0017\u0010\u0014\u001a\u0004\b\u0016\u0010\u0012\"*\u0010\u001c\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u0000*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b\u001b\u0010\u0014\u001a\u0004\b\u0019\u0010\u001a\"\u001e\u0010\u001e\u001a\u00020\u0002*\u0006\u0012\u0002\b\u00030\u001d8B@\u0002X\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u001e\u0010\u001f\"$\u0010$\u001a\u00020 *\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b#\u0010\u0014\u001a\u0004\b!\u0010\"\"8\u0010(\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u0010\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b'\u0010\u0014\u001a\u0004\b%\u0010&\".\u0010+\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00000\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b*\u0010\u0014\u001a\u0004\b)\u0010\u0012\".\u00100\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00000,*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b/\u0010\u0014\u001a\u0004\b-\u0010.\".\u00103\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b2\u0010\u0014\u001a\u0004\b1\u0010\u0012\".\u00107\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u0003040\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b6\u0010\u0014\u001a\u0004\b5\u0010\u0012\".\u0010:\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b9\u0010\u0014\u001a\u0004\b8\u0010\u0012\"D\u0010>\u001a\u0016\u0012\u0012\u0012\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0002\b\u0003\u0012\u0002\b\u00030;0\u000f\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b=\u0010\u0014\u001a\u0004\b<\u0010\u0012\"\u001e\u0010?\u001a\u00020\u0002*\u0006\u0012\u0002\b\u00030\u001d8B@\u0002X\u0082\u0004¢\u0006\u0006\u001a\u0004\b?\u0010\u001f\"D\u0010B\u001a\u0016\u0012\u0012\u0012\u0010\u0012\u0004\u0012\u00028\u0000\u0012\u0002\b\u0003\u0012\u0002\b\u00030;0\u000f\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bA\u0010\u0014\u001a\u0004\b@\u0010\u0012\"@\u0010F\u001a\u0012\u0012\u000e\u0012\f\u0012\u0004\u0012\u00028\u0000\u0012\u0002\b\u00030C0\u000f\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bE\u0010\u0014\u001a\u0004\bD\u0010\u0012\"&\u0010I\u001a\u0004\u0018\u00010\u0007*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bH\u0010\u0014\u001a\u0004\bG\u0010\u000e\"*\u0010L\u001a\b\u0012\u0004\u0012\u00020 0\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bK\u0010\u0014\u001a\u0004\bJ\u0010\u0012\".\u0010O\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bN\u0010\u0014\u001a\u0004\bM\u0010\u0012\".\u0010R\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bQ\u0010\u0014\u001a\u0004\bP\u0010\u0012\"@\u0010U\u001a\u0012\u0012\u000e\u0012\f\u0012\u0004\u0012\u00028\u0000\u0012\u0002\b\u00030C0\u000f\"\b\b\u0000\u0010\b*\u00020\u0007*\b\u0012\u0004\u0012\u00028\u00000\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bT\u0010\u0014\u001a\u0004\bS\u0010\u0012\".\u0010Y\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030V0\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\bX\u0010\u0014\u001a\u0004\bW\u0010\u0012\".\u0010\\\u001a\f\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u00100\u000f*\u0006\u0012\u0002\b\u00030\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b[\u0010\u0014\u001a\u0004\bZ\u0010\u0012¨\u0006]"}, m5311d2 = {"Lkotlin/reflect/KClass;", "base", "", "isSubclassOf", "(Lkotlin/reflect/KClass;Lkotlin/reflect/KClass;)Z", "derived", "isSuperclassOf", "", ExifInterface.GPS_DIRECTION_TRUE, "value", "cast", "(Lkotlin/reflect/KClass;Ljava/lang/Object;)Ljava/lang/Object;", "safeCast", "createInstance", "(Lkotlin/reflect/KClass;)Ljava/lang/Object;", "", "Lkotlin/reflect/KFunction;", "getFunctions", "(Lkotlin/reflect/KClass;)Ljava/util/Collection;", "getFunctions$annotations", "(Lkotlin/reflect/KClass;)V", "functions", "getDeclaredMemberFunctions", "getDeclaredMemberFunctions$annotations", "declaredMemberFunctions", "getCompanionObject", "(Lkotlin/reflect/KClass;)Lkotlin/reflect/KClass;", "getCompanionObject$annotations", "companionObject", "Lkotlin/reflect/jvm/internal/KCallableImpl;", "isExtension", "(Lkotlin/reflect/jvm/internal/KCallableImpl;)Z", "Lkotlin/reflect/KType;", "getDefaultType", "(Lkotlin/reflect/KClass;)Lkotlin/reflect/KType;", "getDefaultType$annotations", "defaultType", "getPrimaryConstructor", "(Lkotlin/reflect/KClass;)Lkotlin/reflect/KFunction;", "getPrimaryConstructor$annotations", "primaryConstructor", "getAllSuperclasses", "getAllSuperclasses$annotations", "allSuperclasses", "", "getSuperclasses", "(Lkotlin/reflect/KClass;)Ljava/util/List;", "getSuperclasses$annotations", "superclasses", "getMemberFunctions", "getMemberFunctions$annotations", "memberFunctions", "Lkotlin/reflect/KCallable;", "getDeclaredMembers", "getDeclaredMembers$annotations", "declaredMembers", "getStaticFunctions", "getStaticFunctions$annotations", "staticFunctions", "Lkotlin/reflect/KProperty2;", "getMemberExtensionProperties", "getMemberExtensionProperties$annotations", "memberExtensionProperties", "isNotExtension", "getDeclaredMemberExtensionProperties", "getDeclaredMemberExtensionProperties$annotations", "declaredMemberExtensionProperties", "Lkotlin/reflect/KProperty1;", "getMemberProperties", "getMemberProperties$annotations", "memberProperties", "getCompanionObjectInstance", "getCompanionObjectInstance$annotations", "companionObjectInstance", "getAllSupertypes", "getAllSupertypes$annotations", "allSupertypes", "getMemberExtensionFunctions", "getMemberExtensionFunctions$annotations", "memberExtensionFunctions", "getDeclaredMemberExtensionFunctions", "getDeclaredMemberExtensionFunctions$annotations", "declaredMemberExtensionFunctions", "getDeclaredMemberProperties", "getDeclaredMemberProperties$annotations", "declaredMemberProperties", "Lkotlin/reflect/KProperty0;", "getStaticProperties", "getStaticProperties$annotations", "staticProperties", "getDeclaredFunctions", "getDeclaredFunctions$annotations", "declaredFunctions", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KClasses")
/* loaded from: classes2.dex */
public final class KClasses {
    /* JADX WARN: Multi-variable type inference failed */
    @SinceKotlin(version = "1.1")
    @NotNull
    public static final <T> T cast(@NotNull KClass<T> cast, @Nullable Object obj) {
        Intrinsics.checkNotNullParameter(cast, "$this$cast");
        if (cast.isInstance(obj)) {
            Objects.requireNonNull(obj, "null cannot be cast to non-null type T");
            return obj;
        }
        StringBuilder m586H = C1499a.m586H("Value cannot be cast to ");
        m586H.append(cast.getQualifiedName());
        throw new TypeCastException(m586H.toString());
    }

    @SinceKotlin(version = "1.1")
    @NotNull
    public static final <T> T createInstance(@NotNull KClass<T> createInstance) {
        boolean z;
        Intrinsics.checkNotNullParameter(createInstance, "$this$createInstance");
        Iterator<T> it = createInstance.getConstructors().iterator();
        T t = null;
        T t2 = null;
        boolean z2 = false;
        while (true) {
            if (it.hasNext()) {
                T next = it.next();
                List<KParameter> parameters = ((KFunction) next).getParameters();
                if (!(parameters instanceof Collection) || !parameters.isEmpty()) {
                    Iterator<T> it2 = parameters.iterator();
                    while (it2.hasNext()) {
                        if (!((KParameter) it2.next()).isOptional()) {
                            z = false;
                            break;
                        }
                    }
                }
                z = true;
                if (z) {
                    if (z2) {
                        break;
                    }
                    t2 = next;
                    z2 = true;
                }
            } else if (z2) {
                t = t2;
            }
        }
        KFunction kFunction = (KFunction) t;
        if (kFunction != null) {
            return (T) kFunction.callBy(MapsKt__MapsKt.emptyMap());
        }
        throw new IllegalArgumentException("Class should have a single no-arg constructor: " + createInstance);
    }

    @NotNull
    public static final Collection<KClass<?>> getAllSuperclasses(@NotNull KClass<?> allSuperclasses) {
        Intrinsics.checkNotNullParameter(allSuperclasses, "$this$allSuperclasses");
        Collection<KType> allSupertypes = getAllSupertypes(allSuperclasses);
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(allSupertypes, 10));
        for (KType kType : allSupertypes) {
            KClassifier classifier = kType.getClassifier();
            if (!(classifier instanceof KClass)) {
                classifier = null;
            }
            KClass kClass = (KClass) classifier;
            if (kClass == null) {
                throw new KotlinReflectionInternalError("Supertype not a class: " + kType);
            }
            arrayList.add(kClass);
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getAllSuperclasses$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KType> getAllSupertypes(@NotNull KClass<?> allSupertypes) {
        Intrinsics.checkNotNullParameter(allSupertypes, "$this$allSupertypes");
        Object dfs = DFS.dfs(allSupertypes.getSupertypes(), new DFS.Neighbors<KType>() { // from class: kotlin.reflect.full.KClasses$allSupertypes$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // kotlin.reflect.jvm.internal.impl.utils.DFS.Neighbors
            @NotNull
            public final Iterable<KType> getNeighbors(KType kType) {
                KClassifier classifier = kType.getClassifier();
                Function0 function0 = null;
                Object[] objArr = 0;
                if (!(classifier instanceof KClass)) {
                    classifier = null;
                }
                KClass kClass = (KClass) classifier;
                if (kClass == null) {
                    throw new KotlinReflectionInternalError("Supertype not a class: " + kType);
                }
                List<KType> supertypes = kClass.getSupertypes();
                if (kType.getArguments().isEmpty()) {
                    return supertypes;
                }
                TypeSubstitutor create = TypeSubstitutor.create(((KTypeImpl) kType).getType());
                ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(supertypes, 10));
                for (KType kType2 : supertypes) {
                    Objects.requireNonNull(kType2, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KTypeImpl");
                    KotlinType substitute = create.substitute(((KTypeImpl) kType2).getType(), Variance.INVARIANT);
                    if (substitute == null) {
                        throw new KotlinReflectionInternalError("Type substitution failed: " + kType2 + " (" + kType + ')');
                    }
                    Intrinsics.checkNotNullExpressionValue(substitute, "substitutor.substitute((…: $supertype ($current)\")");
                    arrayList.add(new KTypeImpl(substitute, function0, 2, objArr == true ? 1 : 0));
                }
                return arrayList;
            }
        }, new DFS.VisitedWithSet(), new DFS.NodeHandlerWithListResult<KType, KType>() { // from class: kotlin.reflect.full.KClasses$allSupertypes$2
            @Override // kotlin.reflect.jvm.internal.impl.utils.DFS.AbstractNodeHandler, kotlin.reflect.jvm.internal.impl.utils.DFS.NodeHandler
            public boolean beforeChildren(@NotNull KType current) {
                Intrinsics.checkNotNullParameter(current, "current");
                ((LinkedList) this.result).add(current);
                return true;
            }
        });
        Intrinsics.checkNotNullExpressionValue(dfs, "DFS.dfs(\n            sup…    }\n            }\n    )");
        return (Collection) dfs;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getAllSupertypes$annotations(KClass kClass) {
    }

    @Nullable
    public static final KClass<?> getCompanionObject(@NotNull KClass<?> companionObject) {
        Object obj;
        Intrinsics.checkNotNullParameter(companionObject, "$this$companionObject");
        Iterator<T> it = companionObject.getNestedClasses().iterator();
        while (true) {
            if (!it.hasNext()) {
                obj = null;
                break;
            }
            obj = it.next();
            KClass kClass = (KClass) obj;
            Objects.requireNonNull(kClass, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KClassImpl<*>");
            if (((KClassImpl) kClass).getDescriptor().isCompanionObject()) {
                break;
            }
        }
        return (KClass) obj;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getCompanionObject$annotations(KClass kClass) {
    }

    @Nullable
    public static final Object getCompanionObjectInstance(@NotNull KClass<?> companionObjectInstance) {
        Intrinsics.checkNotNullParameter(companionObjectInstance, "$this$companionObjectInstance");
        KClass<?> companionObject = getCompanionObject(companionObjectInstance);
        if (companionObject != null) {
            return companionObject.getObjectInstance();
        }
        return null;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getCompanionObjectInstance$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getDeclaredFunctions(@NotNull KClass<?> declaredFunctions) {
        Intrinsics.checkNotNullParameter(declaredFunctions, "$this$declaredFunctions");
        Collection<KCallableImpl<?>> declaredMembers = ((KClassImpl.Data) ((KClassImpl) declaredFunctions).getData().invoke()).getDeclaredMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : declaredMembers) {
            if (obj instanceof KFunction) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDeclaredFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getDeclaredMemberExtensionFunctions(@NotNull KClass<?> declaredMemberExtensionFunctions) {
        Intrinsics.checkNotNullParameter(declaredMemberExtensionFunctions, "$this$declaredMemberExtensionFunctions");
        Collection<KCallableImpl<?>> declaredNonStaticMembers = ((KClassImpl.Data) ((KClassImpl) declaredMemberExtensionFunctions).getData().invoke()).getDeclaredNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : declaredNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) obj;
            if (isExtension(kCallableImpl) && (kCallableImpl instanceof KFunction)) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDeclaredMemberExtensionFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final <T> Collection<KProperty2<T, ?, ?>> getDeclaredMemberExtensionProperties(@NotNull KClass<T> declaredMemberExtensionProperties) {
        Intrinsics.checkNotNullParameter(declaredMemberExtensionProperties, "$this$declaredMemberExtensionProperties");
        Collection<KCallableImpl<?>> declaredNonStaticMembers = ((KClassImpl) declaredMemberExtensionProperties).getData().invoke().getDeclaredNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (T t : declaredNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) t;
            if (isExtension(kCallableImpl) && (kCallableImpl instanceof KProperty2)) {
                arrayList.add(t);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDeclaredMemberExtensionProperties$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getDeclaredMemberFunctions(@NotNull KClass<?> declaredMemberFunctions) {
        Intrinsics.checkNotNullParameter(declaredMemberFunctions, "$this$declaredMemberFunctions");
        Collection<KCallableImpl<?>> declaredNonStaticMembers = ((KClassImpl.Data) ((KClassImpl) declaredMemberFunctions).getData().invoke()).getDeclaredNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : declaredNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) obj;
            if (isNotExtension(kCallableImpl) && (kCallableImpl instanceof KFunction)) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDeclaredMemberFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final <T> Collection<KProperty1<T, ?>> getDeclaredMemberProperties(@NotNull KClass<T> declaredMemberProperties) {
        Intrinsics.checkNotNullParameter(declaredMemberProperties, "$this$declaredMemberProperties");
        Collection<KCallableImpl<?>> declaredNonStaticMembers = ((KClassImpl) declaredMemberProperties).getData().invoke().getDeclaredNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (T t : declaredNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) t;
            if (isNotExtension(kCallableImpl) && (kCallableImpl instanceof KProperty1)) {
                arrayList.add(t);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDeclaredMemberProperties$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KCallable<?>> getDeclaredMembers(@NotNull KClass<?> declaredMembers) {
        Intrinsics.checkNotNullParameter(declaredMembers, "$this$declaredMembers");
        return ((KClassImpl.Data) ((KClassImpl) declaredMembers).getData().invoke()).getDeclaredMembers();
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDeclaredMembers$annotations(KClass kClass) {
    }

    @NotNull
    public static final KType getDefaultType(@NotNull final KClass<?> defaultType) {
        Intrinsics.checkNotNullParameter(defaultType, "$this$defaultType");
        SimpleType defaultType2 = ((KClassImpl) defaultType).getDescriptor().getDefaultType();
        Intrinsics.checkNotNullExpressionValue(defaultType2, "(this as KClassImpl<*>).descriptor.defaultType");
        return new KTypeImpl(defaultType2, new Function0<Type>() { // from class: kotlin.reflect.full.KClasses$defaultType$1
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Type invoke() {
                return ((KClassImpl) KClass.this).getJClass();
            }
        });
    }

    @Deprecated(message = "This function creates a type which rarely makes sense for generic classes. For example, such type can only be used in signatures of members of that class. Use starProjectedType or createType() for clearer semantics.")
    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getDefaultType$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getFunctions(@NotNull KClass<?> functions) {
        Intrinsics.checkNotNullParameter(functions, "$this$functions");
        Collection<KCallable<?>> members = functions.getMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : members) {
            if (obj instanceof KFunction) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getMemberExtensionFunctions(@NotNull KClass<?> memberExtensionFunctions) {
        Intrinsics.checkNotNullParameter(memberExtensionFunctions, "$this$memberExtensionFunctions");
        Collection<KCallableImpl<?>> allNonStaticMembers = ((KClassImpl.Data) ((KClassImpl) memberExtensionFunctions).getData().invoke()).getAllNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : allNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) obj;
            if (isExtension(kCallableImpl) && (kCallableImpl instanceof KFunction)) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getMemberExtensionFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final <T> Collection<KProperty2<T, ?, ?>> getMemberExtensionProperties(@NotNull KClass<T> memberExtensionProperties) {
        Intrinsics.checkNotNullParameter(memberExtensionProperties, "$this$memberExtensionProperties");
        Collection<KCallableImpl<?>> allNonStaticMembers = ((KClassImpl) memberExtensionProperties).getData().invoke().getAllNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (T t : allNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) t;
            if (isExtension(kCallableImpl) && (kCallableImpl instanceof KProperty2)) {
                arrayList.add(t);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getMemberExtensionProperties$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getMemberFunctions(@NotNull KClass<?> memberFunctions) {
        Intrinsics.checkNotNullParameter(memberFunctions, "$this$memberFunctions");
        Collection<KCallableImpl<?>> allNonStaticMembers = ((KClassImpl.Data) ((KClassImpl) memberFunctions).getData().invoke()).getAllNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : allNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) obj;
            if (isNotExtension(kCallableImpl) && (kCallableImpl instanceof KFunction)) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getMemberFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final <T> Collection<KProperty1<T, ?>> getMemberProperties(@NotNull KClass<T> memberProperties) {
        Intrinsics.checkNotNullParameter(memberProperties, "$this$memberProperties");
        Collection<KCallableImpl<?>> allNonStaticMembers = ((KClassImpl) memberProperties).getData().invoke().getAllNonStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (T t : allNonStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) t;
            if (isNotExtension(kCallableImpl) && (kCallableImpl instanceof KProperty1)) {
                arrayList.add(t);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getMemberProperties$annotations(KClass kClass) {
    }

    @Nullable
    public static final <T> KFunction<T> getPrimaryConstructor(@NotNull KClass<T> primaryConstructor) {
        T t;
        Intrinsics.checkNotNullParameter(primaryConstructor, "$this$primaryConstructor");
        Iterator<T> it = ((KClassImpl) primaryConstructor).getConstructors().iterator();
        while (true) {
            if (!it.hasNext()) {
                t = null;
                break;
            }
            t = it.next();
            KFunction kFunction = (KFunction) t;
            Objects.requireNonNull(kFunction, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KFunctionImpl");
            FunctionDescriptor descriptor = ((KFunctionImpl) kFunction).getDescriptor();
            Objects.requireNonNull(descriptor, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ConstructorDescriptor");
            if (((ConstructorDescriptor) descriptor).isPrimary()) {
                break;
            }
        }
        return (KFunction) t;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getPrimaryConstructor$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KFunction<?>> getStaticFunctions(@NotNull KClass<?> staticFunctions) {
        Intrinsics.checkNotNullParameter(staticFunctions, "$this$staticFunctions");
        Collection<KCallableImpl<?>> allStaticMembers = ((KClassImpl.Data) ((KClassImpl) staticFunctions).getData().invoke()).getAllStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : allStaticMembers) {
            if (obj instanceof KFunction) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getStaticFunctions$annotations(KClass kClass) {
    }

    @NotNull
    public static final Collection<KProperty0<?>> getStaticProperties(@NotNull KClass<?> staticProperties) {
        Intrinsics.checkNotNullParameter(staticProperties, "$this$staticProperties");
        Collection<KCallableImpl<?>> allStaticMembers = ((KClassImpl.Data) ((KClassImpl) staticProperties).getData().invoke()).getAllStaticMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj : allStaticMembers) {
            KCallableImpl kCallableImpl = (KCallableImpl) obj;
            if (isNotExtension(kCallableImpl) && (kCallableImpl instanceof KProperty0)) {
                arrayList.add(obj);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getStaticProperties$annotations(KClass kClass) {
    }

    @NotNull
    public static final List<KClass<?>> getSuperclasses(@NotNull KClass<?> superclasses) {
        Intrinsics.checkNotNullParameter(superclasses, "$this$superclasses");
        List<KType> supertypes = superclasses.getSupertypes();
        ArrayList arrayList = new ArrayList();
        Iterator<T> it = supertypes.iterator();
        while (it.hasNext()) {
            KClassifier classifier = ((KType) it.next()).getClassifier();
            if (!(classifier instanceof KClass)) {
                classifier = null;
            }
            KClass kClass = (KClass) classifier;
            if (kClass != null) {
                arrayList.add(kClass);
            }
        }
        return arrayList;
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getSuperclasses$annotations(KClass kClass) {
    }

    private static final boolean isExtension(KCallableImpl<?> kCallableImpl) {
        return kCallableImpl.getDescriptor().getExtensionReceiverParameter() != null;
    }

    private static final boolean isNotExtension(KCallableImpl<?> kCallableImpl) {
        return !isExtension(kCallableImpl);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.reflect.full.KClasses$sam$org_jetbrains_kotlin_utils_DFS_Neighbors$0] */
    @SinceKotlin(version = "1.1")
    public static final boolean isSubclassOf(@NotNull KClass<?> isSubclassOf, @NotNull final KClass<?> base) {
        Intrinsics.checkNotNullParameter(isSubclassOf, "$this$isSubclassOf");
        Intrinsics.checkNotNullParameter(base, "base");
        if (!Intrinsics.areEqual(isSubclassOf, base)) {
            List listOf = CollectionsKt__CollectionsJVMKt.listOf(isSubclassOf);
            final KProperty1 kProperty1 = KClasses$isSubclassOf$1.INSTANCE;
            if (kProperty1 != null) {
                kProperty1 = new DFS.Neighbors() { // from class: kotlin.reflect.full.KClasses$sam$org_jetbrains_kotlin_utils_DFS_Neighbors$0
                    @Override // kotlin.reflect.jvm.internal.impl.utils.DFS.Neighbors
                    @NotNull
                    public final /* synthetic */ Iterable getNeighbors(Object obj) {
                        return (Iterable) Function1.this.invoke(obj);
                    }
                };
            }
            Boolean ifAny = DFS.ifAny(listOf, (DFS.Neighbors) kProperty1, new Function1<KClass<?>, Boolean>() { // from class: kotlin.reflect.full.KClasses$isSubclassOf$2
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public final Boolean invoke(KClass<?> kClass) {
                    return Boolean.valueOf(Intrinsics.areEqual(kClass, KClass.this));
                }
            });
            Intrinsics.checkNotNullExpressionValue(ifAny, "DFS.ifAny(listOf(this), …erclasses) { it == base }");
            if (!ifAny.booleanValue()) {
                return false;
            }
        }
        return true;
    }

    @SinceKotlin(version = "1.1")
    public static final boolean isSuperclassOf(@NotNull KClass<?> isSuperclassOf, @NotNull KClass<?> derived) {
        Intrinsics.checkNotNullParameter(isSuperclassOf, "$this$isSuperclassOf");
        Intrinsics.checkNotNullParameter(derived, "derived");
        return isSubclassOf(derived, isSuperclassOf);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @SinceKotlin(version = "1.1")
    @Nullable
    public static final <T> T safeCast(@NotNull KClass<T> safeCast, @Nullable Object obj) {
        Intrinsics.checkNotNullParameter(safeCast, "$this$safeCast");
        if (!safeCast.isInstance(obj)) {
            return null;
        }
        Objects.requireNonNull(obj, "null cannot be cast to non-null type T");
        return obj;
    }
}
