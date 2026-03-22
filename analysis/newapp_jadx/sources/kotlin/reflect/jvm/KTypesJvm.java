package kotlin.reflect.jvm;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.SinceKotlin;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.reflect.KClass;
import kotlin.reflect.KClassifier;
import kotlin.reflect.KType;
import kotlin.reflect.KTypeParameter;
import kotlin.reflect.jvm.internal.KTypeImpl;
import kotlin.reflect.jvm.internal.KotlinReflectionInternalError;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassDescriptor;
import kotlin.reflect.jvm.internal.impl.descriptors.ClassKind;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\"$\u0010\u0006\u001a\u0006\u0012\u0002\b\u00030\u0001*\u00020\u00008F@\u0007X\u0087\u0004¢\u0006\f\u0012\u0004\b\u0004\u0010\u0005\u001a\u0004\b\u0002\u0010\u0003\"\u001e\u0010\u0006\u001a\u0006\u0012\u0002\b\u00030\u0001*\u00020\u00078@@\u0000X\u0080\u0004¢\u0006\u0006\u001a\u0004\b\u0002\u0010\b¨\u0006\t"}, m5311d2 = {"Lkotlin/reflect/KType;", "Lkotlin/reflect/KClass;", "getJvmErasure", "(Lkotlin/reflect/KType;)Lkotlin/reflect/KClass;", "getJvmErasure$annotations", "(Lkotlin/reflect/KType;)V", "jvmErasure", "Lkotlin/reflect/KClassifier;", "(Lkotlin/reflect/KClassifier;)Lkotlin/reflect/KClass;", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "KTypesJvm")
/* loaded from: classes.dex */
public final class KTypesJvm {
    @NotNull
    public static final KClass<?> getJvmErasure(@NotNull KType jvmErasure) {
        KClass<?> jvmErasure2;
        Intrinsics.checkNotNullParameter(jvmErasure, "$this$jvmErasure");
        KClassifier classifier = jvmErasure.getClassifier();
        if (classifier != null && (jvmErasure2 = getJvmErasure(classifier)) != null) {
            return jvmErasure2;
        }
        throw new KotlinReflectionInternalError("Cannot calculate JVM erasure for type: " + jvmErasure);
    }

    @SinceKotlin(version = "1.1")
    public static /* synthetic */ void getJvmErasure$annotations(KType kType) {
    }

    @NotNull
    public static final KClass<?> getJvmErasure(@NotNull KClassifier jvmErasure) {
        Object obj;
        KClass<?> jvmErasure2;
        Intrinsics.checkNotNullParameter(jvmErasure, "$this$jvmErasure");
        if (jvmErasure instanceof KClass) {
            return (KClass) jvmErasure;
        }
        if (!(jvmErasure instanceof KTypeParameter)) {
            throw new KotlinReflectionInternalError("Cannot calculate JVM erasure for type: " + jvmErasure);
        }
        List<KType> upperBounds = ((KTypeParameter) jvmErasure).getUpperBounds();
        Iterator<T> it = upperBounds.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            KType kType = (KType) next;
            Objects.requireNonNull(kType, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KTypeImpl");
            Object mo7311getDeclarationDescriptor = ((KTypeImpl) kType).getType().getConstructor().mo7311getDeclarationDescriptor();
            ClassDescriptor classDescriptor = (ClassDescriptor) (mo7311getDeclarationDescriptor instanceof ClassDescriptor ? mo7311getDeclarationDescriptor : null);
            if ((classDescriptor == null || classDescriptor.getKind() == ClassKind.INTERFACE || classDescriptor.getKind() == ClassKind.ANNOTATION_CLASS) ? false : true) {
                obj = next;
                break;
            }
        }
        KType kType2 = (KType) obj;
        if (kType2 == null) {
            kType2 = (KType) CollectionsKt___CollectionsKt.firstOrNull((List) upperBounds);
        }
        return (kType2 == null || (jvmErasure2 = getJvmErasure(kType2)) == null) ? Reflection.getOrCreateKotlinClass(Object.class) : jvmErasure2;
    }
}
