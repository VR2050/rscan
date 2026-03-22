package kotlin.reflect.jvm;

import androidx.exifinterface.media.ExifInterface;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.Intrinsics;
import kotlin.reflect.KCallable;
import kotlin.reflect.KDeclarationContainer;
import kotlin.reflect.KFunction;
import kotlin.reflect.KMutableProperty;
import kotlin.reflect.KProperty;
import kotlin.reflect.KProperty1;
import kotlin.reflect.KType;
import kotlin.reflect.TypesJVMKt;
import kotlin.reflect.full.KClasses;
import kotlin.reflect.jvm.internal.KCallableImpl;
import kotlin.reflect.jvm.internal.KPackageImpl;
import kotlin.reflect.jvm.internal.KPropertyImpl;
import kotlin.reflect.jvm.internal.KTypeImpl;
import kotlin.reflect.jvm.internal.UtilKt;
import kotlin.reflect.jvm.internal.calls.Caller;
import kotlin.reflect.jvm.internal.impl.descriptors.runtime.components.ReflectKotlinClass;
import kotlin.reflect.jvm.internal.impl.load.kotlin.header.KotlinClassHeader;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\f\u001a\u0015\u0010\u0002\u001a\u0004\u0018\u00010\u0001*\u00020\u0000H\u0002¢\u0006\u0004\b\u0002\u0010\u0003\"/\u0010\n\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u0007\"\b\b\u0000\u0010\u0005*\u00020\u0004*\b\u0012\u0004\u0012\u00028\u00000\u00068F@\u0006¢\u0006\u0006\u001a\u0004\b\b\u0010\t\"\u0017\u0010\u000f\u001a\u00020\f*\u00020\u000b8F@\u0006¢\u0006\u0006\u001a\u0004\b\r\u0010\u000e\"\u001d\u0010\n\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u0007*\u00020\u00108F@\u0006¢\u0006\u0006\u001a\u0004\b\b\u0010\u0011\"\u001d\u0010\u0016\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u0013*\u00020\u00128F@\u0006¢\u0006\u0006\u001a\u0004\b\u0014\u0010\u0015\"\u001d\u0010\u0019\u001a\u0004\u0018\u00010\u0010*\u0006\u0012\u0002\b\u00030\u00078F@\u0006¢\u0006\u0006\u001a\u0004\b\u0017\u0010\u0018\"\u001d\u0010\u001c\u001a\u0004\u0018\u00010\u0012*\u0006\u0012\u0002\b\u00030\u00138F@\u0006¢\u0006\u0006\u001a\u0004\b\u001a\u0010\u001b\"\u001d\u0010 \u001a\u0004\u0018\u00010\u0010*\u0006\u0012\u0002\b\u00030\u001d8F@\u0006¢\u0006\u0006\u001a\u0004\b\u001e\u0010\u001f\"1\u0010%\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u0006\"\u0004\b\u0000\u0010\u0005*\b\u0012\u0004\u0012\u00028\u00000\u00078F@\u0006¢\u0006\f\u0012\u0004\b#\u0010$\u001a\u0004\b!\u0010\"\"\u001d\u0010(\u001a\u0004\u0018\u00010\u0010*\u0006\u0012\u0002\b\u00030\u00138F@\u0006¢\u0006\u0006\u001a\u0004\b&\u0010'¨\u0006)"}, m5311d2 = {"Ljava/lang/reflect/Member;", "Lkotlin/reflect/KDeclarationContainer;", "getKPackage", "(Ljava/lang/reflect/Member;)Lkotlin/reflect/KDeclarationContainer;", "", ExifInterface.GPS_DIRECTION_TRUE, "Ljava/lang/reflect/Constructor;", "Lkotlin/reflect/KFunction;", "getKotlinFunction", "(Ljava/lang/reflect/Constructor;)Lkotlin/reflect/KFunction;", "kotlinFunction", "Lkotlin/reflect/KType;", "Ljava/lang/reflect/Type;", "getJavaType", "(Lkotlin/reflect/KType;)Ljava/lang/reflect/Type;", "javaType", "Ljava/lang/reflect/Method;", "(Ljava/lang/reflect/Method;)Lkotlin/reflect/KFunction;", "Ljava/lang/reflect/Field;", "Lkotlin/reflect/KProperty;", "getKotlinProperty", "(Ljava/lang/reflect/Field;)Lkotlin/reflect/KProperty;", "kotlinProperty", "getJavaMethod", "(Lkotlin/reflect/KFunction;)Ljava/lang/reflect/Method;", "javaMethod", "getJavaField", "(Lkotlin/reflect/KProperty;)Ljava/lang/reflect/Field;", "javaField", "Lkotlin/reflect/KMutableProperty;", "getJavaSetter", "(Lkotlin/reflect/KMutableProperty;)Ljava/lang/reflect/Method;", "javaSetter", "getJavaConstructor", "(Lkotlin/reflect/KFunction;)Ljava/lang/reflect/Constructor;", "getJavaConstructor$annotations", "(Lkotlin/reflect/KFunction;)V", "javaConstructor", "getJavaGetter", "(Lkotlin/reflect/KProperty;)Ljava/lang/reflect/Method;", "javaGetter", "kotlin-reflection"}, m5312k = 2, m5313mv = {1, 5, 1})
@JvmName(name = "ReflectJvmMapping")
/* loaded from: classes.dex */
public final class ReflectJvmMapping {

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {}, m5311d2 = {}, m5312k = 3, m5313mv = {1, 5, 1})
    public final /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            KotlinClassHeader.Kind.values();
            int[] iArr = new int[6];
            $EnumSwitchMapping$0 = iArr;
            iArr[KotlinClassHeader.Kind.FILE_FACADE.ordinal()] = 1;
            iArr[KotlinClassHeader.Kind.MULTIFILE_CLASS.ordinal()] = 2;
            iArr[KotlinClassHeader.Kind.MULTIFILE_CLASS_PART.ordinal()] = 3;
        }
    }

    @Nullable
    public static final <T> Constructor<T> getJavaConstructor(@NotNull KFunction<? extends T> javaConstructor) {
        Caller<?> caller;
        Intrinsics.checkNotNullParameter(javaConstructor, "$this$javaConstructor");
        KCallableImpl<?> asKCallableImpl = UtilKt.asKCallableImpl(javaConstructor);
        Object mo7302getMember = (asKCallableImpl == null || (caller = asKCallableImpl.getCaller()) == null) ? null : caller.mo7302getMember();
        return (Constructor) (mo7302getMember instanceof Constructor ? mo7302getMember : null);
    }

    public static /* synthetic */ void getJavaConstructor$annotations(KFunction kFunction) {
    }

    @Nullable
    public static final Field getJavaField(@NotNull KProperty<?> javaField) {
        Intrinsics.checkNotNullParameter(javaField, "$this$javaField");
        KPropertyImpl<?> asKPropertyImpl = UtilKt.asKPropertyImpl(javaField);
        if (asKPropertyImpl != null) {
            return asKPropertyImpl.getJavaField();
        }
        return null;
    }

    @Nullable
    public static final Method getJavaGetter(@NotNull KProperty<?> javaGetter) {
        Intrinsics.checkNotNullParameter(javaGetter, "$this$javaGetter");
        return getJavaMethod(javaGetter.getGetter());
    }

    @Nullable
    public static final Method getJavaMethod(@NotNull KFunction<?> javaMethod) {
        Caller<?> caller;
        Intrinsics.checkNotNullParameter(javaMethod, "$this$javaMethod");
        KCallableImpl<?> asKCallableImpl = UtilKt.asKCallableImpl(javaMethod);
        Object mo7302getMember = (asKCallableImpl == null || (caller = asKCallableImpl.getCaller()) == null) ? null : caller.mo7302getMember();
        return (Method) (mo7302getMember instanceof Method ? mo7302getMember : null);
    }

    @Nullable
    public static final Method getJavaSetter(@NotNull KMutableProperty<?> javaSetter) {
        Intrinsics.checkNotNullParameter(javaSetter, "$this$javaSetter");
        return getJavaMethod(javaSetter.getSetter());
    }

    @NotNull
    public static final Type getJavaType(@NotNull KType javaType) {
        Intrinsics.checkNotNullParameter(javaType, "$this$javaType");
        Type javaType2 = ((KTypeImpl) javaType).getJavaType();
        return javaType2 != null ? javaType2 : TypesJVMKt.getJavaType(javaType);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static final KDeclarationContainer getKPackage(Member member) {
        KotlinClassHeader classHeader;
        ReflectKotlinClass.Factory factory = ReflectKotlinClass.Factory;
        Class<?> declaringClass = member.getDeclaringClass();
        Intrinsics.checkNotNullExpressionValue(declaringClass, "declaringClass");
        ReflectKotlinClass create = factory.create(declaringClass);
        String str = null;
        Object[] objArr = 0;
        KotlinClassHeader.Kind kind = (create == null || (classHeader = create.getClassHeader()) == null) ? null : classHeader.getKind();
        if (kind == null) {
            return null;
        }
        int ordinal = kind.ordinal();
        int i2 = 2;
        if (ordinal != 2 && ordinal != 4 && ordinal != 5) {
            return null;
        }
        Class<?> declaringClass2 = member.getDeclaringClass();
        Intrinsics.checkNotNullExpressionValue(declaringClass2, "declaringClass");
        return new KPackageImpl(declaringClass2, str, i2, objArr == true ? 1 : 0);
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00b6 A[EDGE_INSN: B:44:0x00b6->B:45:0x00b6 BREAK  A[LOOP:2: B:31:0x006f->B:48:?], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:48:? A[LOOP:2: B:31:0x006f->B:48:?, LOOP_END, SYNTHETIC] */
    @org.jetbrains.annotations.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final kotlin.reflect.KFunction<?> getKotlinFunction(@org.jetbrains.annotations.NotNull java.lang.reflect.Method r7) {
        /*
            java.lang.String r0 = "$this$kotlinFunction"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            int r0 = r7.getModifiers()
            boolean r0 = java.lang.reflect.Modifier.isStatic(r0)
            java.lang.String r1 = "declaringClass"
            r2 = 0
            if (r0 == 0) goto Lbb
            kotlin.reflect.KDeclarationContainer r0 = getKPackage(r7)
            if (r0 == 0) goto L56
            java.util.Collection r0 = r0.getMembers()
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            java.util.Iterator r0 = r0.iterator()
        L25:
            boolean r3 = r0.hasNext()
            if (r3 == 0) goto L37
            java.lang.Object r3 = r0.next()
            boolean r4 = r3 instanceof kotlin.reflect.KFunction
            if (r4 == 0) goto L25
            r1.add(r3)
            goto L25
        L37:
            java.util.Iterator r0 = r1.iterator()
        L3b:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L53
            java.lang.Object r1 = r0.next()
            r3 = r1
            kotlin.reflect.KFunction r3 = (kotlin.reflect.KFunction) r3
            java.lang.reflect.Method r3 = getJavaMethod(r3)
            boolean r3 = kotlin.jvm.internal.Intrinsics.areEqual(r3, r7)
            if (r3 == 0) goto L3b
            r2 = r1
        L53:
            kotlin.reflect.KFunction r2 = (kotlin.reflect.KFunction) r2
            return r2
        L56:
            java.lang.Class r0 = r7.getDeclaringClass()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            kotlin.reflect.KClass r0 = kotlin.jvm.JvmClassMappingKt.getKotlinClass(r0)
            kotlin.reflect.KClass r0 = kotlin.reflect.full.KClasses.getCompanionObject(r0)
            if (r0 == 0) goto Lbb
            java.util.Collection r0 = kotlin.reflect.full.KClasses.getFunctions(r0)
            java.util.Iterator r0 = r0.iterator()
        L6f:
            boolean r3 = r0.hasNext()
            if (r3 == 0) goto Lb5
            java.lang.Object r3 = r0.next()
            r4 = r3
            kotlin.reflect.KFunction r4 = (kotlin.reflect.KFunction) r4
            java.lang.reflect.Method r4 = getJavaMethod(r4)
            if (r4 == 0) goto Lb1
            java.lang.String r5 = r4.getName()
            java.lang.String r6 = r7.getName()
            boolean r5 = kotlin.jvm.internal.Intrinsics.areEqual(r5, r6)
            if (r5 == 0) goto Lb1
            java.lang.Class[] r5 = r4.getParameterTypes()
            kotlin.jvm.internal.Intrinsics.checkNotNull(r5)
            java.lang.Class[] r6 = r7.getParameterTypes()
            boolean r5 = java.util.Arrays.equals(r5, r6)
            if (r5 == 0) goto Lb1
            java.lang.Class r4 = r4.getReturnType()
            java.lang.Class r5 = r7.getReturnType()
            boolean r4 = kotlin.jvm.internal.Intrinsics.areEqual(r4, r5)
            if (r4 == 0) goto Lb1
            r4 = 1
            goto Lb2
        Lb1:
            r4 = 0
        Lb2:
            if (r4 == 0) goto L6f
            goto Lb6
        Lb5:
            r3 = r2
        Lb6:
            kotlin.reflect.KFunction r3 = (kotlin.reflect.KFunction) r3
            if (r3 == 0) goto Lbb
            return r3
        Lbb:
            java.lang.Class r0 = r7.getDeclaringClass()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            kotlin.reflect.KClass r0 = kotlin.jvm.JvmClassMappingKt.getKotlinClass(r0)
            java.util.Collection r0 = kotlin.reflect.full.KClasses.getFunctions(r0)
            java.util.Iterator r0 = r0.iterator()
        Lce:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto Le6
            java.lang.Object r1 = r0.next()
            r3 = r1
            kotlin.reflect.KFunction r3 = (kotlin.reflect.KFunction) r3
            java.lang.reflect.Method r3 = getJavaMethod(r3)
            boolean r3 = kotlin.jvm.internal.Intrinsics.areEqual(r3, r7)
            if (r3 == 0) goto Lce
            r2 = r1
        Le6:
            kotlin.reflect.KFunction r2 = (kotlin.reflect.KFunction) r2
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.reflect.jvm.ReflectJvmMapping.getKotlinFunction(java.lang.reflect.Method):kotlin.reflect.KFunction");
    }

    @Nullable
    public static final KProperty<?> getKotlinProperty(@NotNull Field kotlinProperty) {
        Intrinsics.checkNotNullParameter(kotlinProperty, "$this$kotlinProperty");
        Object obj = null;
        if (kotlinProperty.isSynthetic()) {
            return null;
        }
        KDeclarationContainer kPackage = getKPackage(kotlinProperty);
        if (kPackage == null) {
            Class<?> declaringClass = kotlinProperty.getDeclaringClass();
            Intrinsics.checkNotNullExpressionValue(declaringClass, "declaringClass");
            Iterator it = KClasses.getMemberProperties(JvmClassMappingKt.getKotlinClass(declaringClass)).iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                Object next = it.next();
                if (Intrinsics.areEqual(getJavaField((KProperty1) next), kotlinProperty)) {
                    obj = next;
                    break;
                }
            }
            return (KProperty) obj;
        }
        Collection<KCallable<?>> members = kPackage.getMembers();
        ArrayList arrayList = new ArrayList();
        for (Object obj2 : members) {
            if (obj2 instanceof KProperty) {
                arrayList.add(obj2);
            }
        }
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            Object next2 = it2.next();
            if (Intrinsics.areEqual(getJavaField((KProperty) next2), kotlinProperty)) {
                obj = next2;
                break;
            }
        }
        return (KProperty) obj;
    }

    @Nullable
    public static final <T> KFunction<T> getKotlinFunction(@NotNull Constructor<T> kotlinFunction) {
        T t;
        Intrinsics.checkNotNullParameter(kotlinFunction, "$this$kotlinFunction");
        Class<T> declaringClass = kotlinFunction.getDeclaringClass();
        Intrinsics.checkNotNullExpressionValue(declaringClass, "declaringClass");
        Iterator<T> it = JvmClassMappingKt.getKotlinClass(declaringClass).getConstructors().iterator();
        while (true) {
            if (!it.hasNext()) {
                t = null;
                break;
            }
            t = it.next();
            if (Intrinsics.areEqual(getJavaConstructor((KFunction) t), kotlinFunction)) {
                break;
            }
        }
        return (KFunction) t;
    }
}
