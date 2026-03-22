package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.Arrays;
import java.util.Objects;
import javax.annotation.Nullable;
import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p458k.C4391l0;
import p474l.C4744f;

/* renamed from: n.d0 */
/* loaded from: classes3.dex */
public final class C4984d0 {

    /* renamed from: a */
    public static final Type[] f12807a = new Type[0];

    /* renamed from: n.d0$a */
    public static final class a implements GenericArrayType {

        /* renamed from: c */
        public final Type f12808c;

        public a(Type type) {
            this.f12808c = type;
        }

        public boolean equals(Object obj) {
            return (obj instanceof GenericArrayType) && C4984d0.m5656c(this, (GenericArrayType) obj);
        }

        @Override // java.lang.reflect.GenericArrayType
        public Type getGenericComponentType() {
            return this.f12808c;
        }

        public int hashCode() {
            return this.f12808c.hashCode();
        }

        public String toString() {
            return C4984d0.m5669p(this.f12808c) + "[]";
        }
    }

    /* renamed from: n.d0$b */
    public static final class b implements ParameterizedType {

        /* renamed from: c */
        @Nullable
        public final Type f12809c;

        /* renamed from: e */
        public final Type f12810e;

        /* renamed from: f */
        public final Type[] f12811f;

        public b(@Nullable Type type, Type type2, Type... typeArr) {
            if (type2 instanceof Class) {
                if ((type == null) != (((Class) type2).getEnclosingClass() == null)) {
                    throw new IllegalArgumentException();
                }
            }
            for (Type type3 : typeArr) {
                Objects.requireNonNull(type3, "typeArgument == null");
                C4984d0.m5655b(type3);
            }
            this.f12809c = type;
            this.f12810e = type2;
            this.f12811f = (Type[]) typeArr.clone();
        }

        public boolean equals(Object obj) {
            return (obj instanceof ParameterizedType) && C4984d0.m5656c(this, (ParameterizedType) obj);
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type[] getActualTypeArguments() {
            return (Type[]) this.f12811f.clone();
        }

        @Override // java.lang.reflect.ParameterizedType
        @Nullable
        public Type getOwnerType() {
            return this.f12809c;
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type getRawType() {
            return this.f12810e;
        }

        public int hashCode() {
            int hashCode = Arrays.hashCode(this.f12811f) ^ this.f12810e.hashCode();
            Type type = this.f12809c;
            return hashCode ^ (type != null ? type.hashCode() : 0);
        }

        public String toString() {
            Type[] typeArr = this.f12811f;
            if (typeArr.length == 0) {
                return C4984d0.m5669p(this.f12810e);
            }
            StringBuilder sb = new StringBuilder((typeArr.length + 1) * 30);
            sb.append(C4984d0.m5669p(this.f12810e));
            sb.append("<");
            sb.append(C4984d0.m5669p(this.f12811f[0]));
            for (int i2 = 1; i2 < this.f12811f.length; i2++) {
                sb.append(", ");
                sb.append(C4984d0.m5669p(this.f12811f[i2]));
            }
            sb.append(">");
            return sb.toString();
        }
    }

    /* renamed from: n.d0$c */
    public static final class c implements WildcardType {

        /* renamed from: c */
        public final Type f12812c;

        /* renamed from: e */
        @Nullable
        public final Type f12813e;

        public c(Type[] typeArr, Type[] typeArr2) {
            if (typeArr2.length > 1) {
                throw new IllegalArgumentException();
            }
            if (typeArr.length != 1) {
                throw new IllegalArgumentException();
            }
            if (typeArr2.length != 1) {
                Objects.requireNonNull(typeArr[0]);
                C4984d0.m5655b(typeArr[0]);
                this.f12813e = null;
                this.f12812c = typeArr[0];
                return;
            }
            Objects.requireNonNull(typeArr2[0]);
            C4984d0.m5655b(typeArr2[0]);
            if (typeArr[0] != Object.class) {
                throw new IllegalArgumentException();
            }
            this.f12813e = typeArr2[0];
            this.f12812c = Object.class;
        }

        public boolean equals(Object obj) {
            return (obj instanceof WildcardType) && C4984d0.m5656c(this, (WildcardType) obj);
        }

        @Override // java.lang.reflect.WildcardType
        public Type[] getLowerBounds() {
            Type type = this.f12813e;
            return type != null ? new Type[]{type} : C4984d0.f12807a;
        }

        @Override // java.lang.reflect.WildcardType
        public Type[] getUpperBounds() {
            return new Type[]{this.f12812c};
        }

        public int hashCode() {
            Type type = this.f12813e;
            return (type != null ? type.hashCode() + 31 : 1) ^ (this.f12812c.hashCode() + 31);
        }

        public String toString() {
            if (this.f12813e != null) {
                StringBuilder m586H = C1499a.m586H("? super ");
                m586H.append(C4984d0.m5669p(this.f12813e));
                return m586H.toString();
            }
            if (this.f12812c == Object.class) {
                return "?";
            }
            StringBuilder m586H2 = C1499a.m586H("? extends ");
            m586H2.append(C4984d0.m5669p(this.f12812c));
            return m586H2.toString();
        }
    }

    /* renamed from: a */
    public static AbstractC4393m0 m5654a(AbstractC4393m0 abstractC4393m0) {
        C4744f asResponseBody = new C4744f();
        abstractC4393m0.mo4927k().mo5359K(asResponseBody);
        C4371b0 mo4926e = abstractC4393m0.mo4926e();
        long mo4925d = abstractC4393m0.mo4925d();
        Intrinsics.checkParameterIsNotNull(asResponseBody, "content");
        Intrinsics.checkParameterIsNotNull(asResponseBody, "$this$asResponseBody");
        return new C4391l0(asResponseBody, mo4926e, mo4925d);
    }

    /* renamed from: b */
    public static void m5655b(Type type) {
        if ((type instanceof Class) && ((Class) type).isPrimitive()) {
            throw new IllegalArgumentException();
        }
    }

    /* renamed from: c */
    public static boolean m5656c(Type type, Type type2) {
        if (type == type2) {
            return true;
        }
        if (type instanceof Class) {
            return type.equals(type2);
        }
        if (type instanceof ParameterizedType) {
            if (!(type2 instanceof ParameterizedType)) {
                return false;
            }
            ParameterizedType parameterizedType = (ParameterizedType) type;
            ParameterizedType parameterizedType2 = (ParameterizedType) type2;
            Type ownerType = parameterizedType.getOwnerType();
            Type ownerType2 = parameterizedType2.getOwnerType();
            return (ownerType == ownerType2 || (ownerType != null && ownerType.equals(ownerType2))) && parameterizedType.getRawType().equals(parameterizedType2.getRawType()) && Arrays.equals(parameterizedType.getActualTypeArguments(), parameterizedType2.getActualTypeArguments());
        }
        if (type instanceof GenericArrayType) {
            if (type2 instanceof GenericArrayType) {
                return m5656c(((GenericArrayType) type).getGenericComponentType(), ((GenericArrayType) type2).getGenericComponentType());
            }
            return false;
        }
        if (type instanceof WildcardType) {
            if (!(type2 instanceof WildcardType)) {
                return false;
            }
            WildcardType wildcardType = (WildcardType) type;
            WildcardType wildcardType2 = (WildcardType) type2;
            return Arrays.equals(wildcardType.getUpperBounds(), wildcardType2.getUpperBounds()) && Arrays.equals(wildcardType.getLowerBounds(), wildcardType2.getLowerBounds());
        }
        if (!(type instanceof TypeVariable) || !(type2 instanceof TypeVariable)) {
            return false;
        }
        TypeVariable typeVariable = (TypeVariable) type;
        TypeVariable typeVariable2 = (TypeVariable) type2;
        return typeVariable.getGenericDeclaration() == typeVariable2.getGenericDeclaration() && typeVariable.getName().equals(typeVariable2.getName());
    }

    /* renamed from: d */
    public static Type m5657d(Type type, Class<?> cls, Class<?> cls2) {
        if (cls2 == cls) {
            return type;
        }
        if (cls2.isInterface()) {
            Class<?>[] interfaces = cls.getInterfaces();
            int length = interfaces.length;
            for (int i2 = 0; i2 < length; i2++) {
                if (interfaces[i2] == cls2) {
                    return cls.getGenericInterfaces()[i2];
                }
                if (cls2.isAssignableFrom(interfaces[i2])) {
                    return m5657d(cls.getGenericInterfaces()[i2], interfaces[i2], cls2);
                }
            }
        }
        if (!cls.isInterface()) {
            while (cls != Object.class) {
                Class<? super Object> superclass = cls.getSuperclass();
                if (superclass == cls2) {
                    return cls.getGenericSuperclass();
                }
                if (cls2.isAssignableFrom(superclass)) {
                    return m5657d(cls.getGenericSuperclass(), superclass, cls2);
                }
                cls = superclass;
            }
        }
        return cls2;
    }

    /* renamed from: e */
    public static Type m5658e(int i2, ParameterizedType parameterizedType) {
        Type[] actualTypeArguments = parameterizedType.getActualTypeArguments();
        if (i2 >= 0 && i2 < actualTypeArguments.length) {
            Type type = actualTypeArguments[i2];
            return type instanceof WildcardType ? ((WildcardType) type).getUpperBounds()[0] : type;
        }
        StringBuilder m588J = C1499a.m588J("Index ", i2, " not in range [0,");
        m588J.append(actualTypeArguments.length);
        m588J.append(") for ");
        m588J.append(parameterizedType);
        throw new IllegalArgumentException(m588J.toString());
    }

    /* renamed from: f */
    public static Class<?> m5659f(Type type) {
        Objects.requireNonNull(type, "type == null");
        if (type instanceof Class) {
            return (Class) type;
        }
        if (type instanceof ParameterizedType) {
            Type rawType = ((ParameterizedType) type).getRawType();
            if (rawType instanceof Class) {
                return (Class) rawType;
            }
            throw new IllegalArgumentException();
        }
        if (type instanceof GenericArrayType) {
            return Array.newInstance(m5659f(((GenericArrayType) type).getGenericComponentType()), 0).getClass();
        }
        if (type instanceof TypeVariable) {
            return Object.class;
        }
        if (type instanceof WildcardType) {
            return m5659f(((WildcardType) type).getUpperBounds()[0]);
        }
        throw new IllegalArgumentException("Expected a Class, ParameterizedType, or GenericArrayType, but <" + type + "> is of type " + type.getClass().getName());
    }

    /* renamed from: g */
    public static Type m5660g(Type type, Class<?> cls, Class<?> cls2) {
        if (cls2.isAssignableFrom(cls)) {
            return m5667n(type, cls, m5657d(type, cls, cls2));
        }
        throw new IllegalArgumentException();
    }

    /* renamed from: h */
    public static boolean m5661h(@Nullable Type type) {
        if (type instanceof Class) {
            return false;
        }
        if (type instanceof ParameterizedType) {
            for (Type type2 : ((ParameterizedType) type).getActualTypeArguments()) {
                if (m5661h(type2)) {
                    return true;
                }
            }
            return false;
        }
        if (type instanceof GenericArrayType) {
            return m5661h(((GenericArrayType) type).getGenericComponentType());
        }
        if ((type instanceof TypeVariable) || (type instanceof WildcardType)) {
            return true;
        }
        throw new IllegalArgumentException("Expected a Class, ParameterizedType, or GenericArrayType, but <" + type + "> is of type " + (type == null ? "null" : type.getClass().getName()));
    }

    /* renamed from: i */
    public static boolean m5662i(Annotation[] annotationArr, Class<? extends Annotation> cls) {
        for (Annotation annotation : annotationArr) {
            if (cls.isInstance(annotation)) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: j */
    public static RuntimeException m5663j(Method method, String str, Object... objArr) {
        return m5664k(method, null, str, objArr);
    }

    /* renamed from: k */
    public static RuntimeException m5664k(Method method, @Nullable Throwable th, String str, Object... objArr) {
        StringBuilder m590L = C1499a.m590L(String.format(str, objArr), "\n    for method ");
        m590L.append(method.getDeclaringClass().getSimpleName());
        m590L.append(".");
        m590L.append(method.getName());
        return new IllegalArgumentException(m590L.toString(), th);
    }

    /* renamed from: l */
    public static RuntimeException m5665l(Method method, int i2, String str, Object... objArr) {
        StringBuilder m590L = C1499a.m590L(str, " (parameter #");
        m590L.append(i2 + 1);
        m590L.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m5663j(method, m590L.toString(), objArr);
    }

    /* renamed from: m */
    public static RuntimeException m5666m(Method method, Throwable th, int i2, String str, Object... objArr) {
        StringBuilder m590L = C1499a.m590L(str, " (parameter #");
        m590L.append(i2 + 1);
        m590L.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m5664k(method, th, m590L.toString(), objArr);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0043 A[LOOP:0: B:1:0x0000->B:18:0x0043, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0042 A[SYNTHETIC] */
    /* renamed from: n */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.reflect.Type m5667n(java.lang.reflect.Type r8, java.lang.Class<?> r9, java.lang.reflect.Type r10) {
        /*
            Method dump skipped, instructions count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p505n.C4984d0.m5667n(java.lang.reflect.Type, java.lang.Class, java.lang.reflect.Type):java.lang.reflect.Type");
    }

    /* renamed from: o */
    public static void m5668o(Throwable th) {
        if (th instanceof VirtualMachineError) {
            throw ((VirtualMachineError) th);
        }
        if (th instanceof ThreadDeath) {
            throw ((ThreadDeath) th);
        }
        if (th instanceof LinkageError) {
            throw ((LinkageError) th);
        }
    }

    /* renamed from: p */
    public static String m5669p(Type type) {
        return type instanceof Class ? ((Class) type).getName() : type.toString();
    }
}
