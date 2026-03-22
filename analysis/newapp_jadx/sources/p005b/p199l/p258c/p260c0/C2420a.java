package p005b.p199l.p258c.p260c0;

import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.GenericDeclaration;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.NoSuchElementException;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.l.c.c0.a */
/* loaded from: classes2.dex */
public final class C2420a {

    /* renamed from: a */
    public static final Type[] f6452a = new Type[0];

    /* renamed from: b.l.c.c0.a$a */
    public static final class a implements GenericArrayType, Serializable {
        private static final long serialVersionUID = 0;

        /* renamed from: c */
        public final Type f6453c;

        public a(Type type) {
            this.f6453c = C2420a.m2757a(type);
        }

        public boolean equals(Object obj) {
            return (obj instanceof GenericArrayType) && C2420a.m2759c(this, (GenericArrayType) obj);
        }

        @Override // java.lang.reflect.GenericArrayType
        public Type getGenericComponentType() {
            return this.f6453c;
        }

        public int hashCode() {
            return this.f6453c.hashCode();
        }

        public String toString() {
            return C2420a.m2765i(this.f6453c) + "[]";
        }
    }

    /* renamed from: b.l.c.c0.a$b */
    public static final class b implements ParameterizedType, Serializable {
        private static final long serialVersionUID = 0;

        /* renamed from: c */
        public final Type f6454c;

        /* renamed from: e */
        public final Type f6455e;

        /* renamed from: f */
        public final Type[] f6456f;

        public b(Type type, Type type2, Type... typeArr) {
            if (type2 instanceof Class) {
                Class cls = (Class) type2;
                boolean z = true;
                boolean z2 = Modifier.isStatic(cls.getModifiers()) || cls.getEnclosingClass() == null;
                if (type == null && !z2) {
                    z = false;
                }
                C2354n.m2524w(z);
            }
            this.f6454c = type == null ? null : C2420a.m2757a(type);
            this.f6455e = C2420a.m2757a(type2);
            Type[] typeArr2 = (Type[]) typeArr.clone();
            this.f6456f = typeArr2;
            int length = typeArr2.length;
            for (int i2 = 0; i2 < length; i2++) {
                Objects.requireNonNull(this.f6456f[i2]);
                C2420a.m2758b(this.f6456f[i2]);
                Type[] typeArr3 = this.f6456f;
                typeArr3[i2] = C2420a.m2757a(typeArr3[i2]);
            }
        }

        public boolean equals(Object obj) {
            return (obj instanceof ParameterizedType) && C2420a.m2759c(this, (ParameterizedType) obj);
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type[] getActualTypeArguments() {
            return (Type[]) this.f6456f.clone();
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type getOwnerType() {
            return this.f6454c;
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type getRawType() {
            return this.f6455e;
        }

        public int hashCode() {
            int hashCode = Arrays.hashCode(this.f6456f) ^ this.f6455e.hashCode();
            Type type = this.f6454c;
            return hashCode ^ (type != null ? type.hashCode() : 0);
        }

        public String toString() {
            int length = this.f6456f.length;
            if (length == 0) {
                return C2420a.m2765i(this.f6455e);
            }
            StringBuilder sb = new StringBuilder((length + 1) * 30);
            sb.append(C2420a.m2765i(this.f6455e));
            sb.append("<");
            sb.append(C2420a.m2765i(this.f6456f[0]));
            for (int i2 = 1; i2 < length; i2++) {
                sb.append(", ");
                sb.append(C2420a.m2765i(this.f6456f[i2]));
            }
            sb.append(">");
            return sb.toString();
        }
    }

    /* renamed from: b.l.c.c0.a$c */
    public static final class c implements WildcardType, Serializable {
        private static final long serialVersionUID = 0;

        /* renamed from: c */
        public final Type f6457c;

        /* renamed from: e */
        public final Type f6458e;

        public c(Type[] typeArr, Type[] typeArr2) {
            C2354n.m2524w(typeArr2.length <= 1);
            C2354n.m2524w(typeArr.length == 1);
            if (typeArr2.length != 1) {
                Objects.requireNonNull(typeArr[0]);
                C2420a.m2758b(typeArr[0]);
                this.f6458e = null;
                this.f6457c = C2420a.m2757a(typeArr[0]);
                return;
            }
            Objects.requireNonNull(typeArr2[0]);
            C2420a.m2758b(typeArr2[0]);
            C2354n.m2524w(typeArr[0] == Object.class);
            this.f6458e = C2420a.m2757a(typeArr2[0]);
            this.f6457c = Object.class;
        }

        public boolean equals(Object obj) {
            return (obj instanceof WildcardType) && C2420a.m2759c(this, (WildcardType) obj);
        }

        @Override // java.lang.reflect.WildcardType
        public Type[] getLowerBounds() {
            Type type = this.f6458e;
            return type != null ? new Type[]{type} : C2420a.f6452a;
        }

        @Override // java.lang.reflect.WildcardType
        public Type[] getUpperBounds() {
            return new Type[]{this.f6457c};
        }

        public int hashCode() {
            Type type = this.f6458e;
            return (type != null ? type.hashCode() + 31 : 1) ^ (this.f6457c.hashCode() + 31);
        }

        public String toString() {
            if (this.f6458e != null) {
                StringBuilder m586H = C1499a.m586H("? super ");
                m586H.append(C2420a.m2765i(this.f6458e));
                return m586H.toString();
            }
            if (this.f6457c == Object.class) {
                return "?";
            }
            StringBuilder m586H2 = C1499a.m586H("? extends ");
            m586H2.append(C2420a.m2765i(this.f6457c));
            return m586H2.toString();
        }
    }

    /* renamed from: a */
    public static Type m2757a(Type type) {
        if (type instanceof Class) {
            Class cls = (Class) type;
            return cls.isArray() ? new a(m2757a(cls.getComponentType())) : cls;
        }
        if (type instanceof ParameterizedType) {
            ParameterizedType parameterizedType = (ParameterizedType) type;
            return new b(parameterizedType.getOwnerType(), parameterizedType.getRawType(), parameterizedType.getActualTypeArguments());
        }
        if (type instanceof GenericArrayType) {
            return new a(((GenericArrayType) type).getGenericComponentType());
        }
        if (!(type instanceof WildcardType)) {
            return type;
        }
        WildcardType wildcardType = (WildcardType) type;
        return new c(wildcardType.getUpperBounds(), wildcardType.getLowerBounds());
    }

    /* renamed from: b */
    public static void m2758b(Type type) {
        C2354n.m2524w(((type instanceof Class) && ((Class) type).isPrimitive()) ? false : true);
    }

    /* renamed from: c */
    public static boolean m2759c(Type type, Type type2) {
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
                return m2759c(((GenericArrayType) type).getGenericComponentType(), ((GenericArrayType) type2).getGenericComponentType());
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
    public static Type m2760d(Type type, Class<?> cls, Class<?> cls2) {
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
                    return m2760d(cls.getGenericInterfaces()[i2], interfaces[i2], cls2);
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
                    return m2760d(cls.getGenericSuperclass(), superclass, cls2);
                }
                cls = superclass;
            }
        }
        return cls2;
    }

    /* renamed from: e */
    public static Class<?> m2761e(Type type) {
        if (type instanceof Class) {
            return (Class) type;
        }
        if (type instanceof ParameterizedType) {
            Type rawType = ((ParameterizedType) type).getRawType();
            C2354n.m2524w(rawType instanceof Class);
            return (Class) rawType;
        }
        if (type instanceof GenericArrayType) {
            return Array.newInstance(m2761e(((GenericArrayType) type).getGenericComponentType()), 0).getClass();
        }
        if (type instanceof TypeVariable) {
            return Object.class;
        }
        if (type instanceof WildcardType) {
            return m2761e(((WildcardType) type).getUpperBounds()[0]);
        }
        throw new IllegalArgumentException("Expected a Class, ParameterizedType, or GenericArrayType, but <" + type + "> is of type " + (type == null ? "null" : type.getClass().getName()));
    }

    /* renamed from: f */
    public static Type m2762f(Type type, Class<?> cls, Class<?> cls2) {
        if (type instanceof WildcardType) {
            type = ((WildcardType) type).getUpperBounds()[0];
        }
        C2354n.m2524w(cls2.isAssignableFrom(cls));
        return m2763g(type, cls, m2760d(type, cls, cls2));
    }

    /* renamed from: g */
    public static Type m2763g(Type type, Class<?> cls, Type type2) {
        return m2764h(type, cls, type2, new HashSet());
    }

    /* renamed from: h */
    public static Type m2764h(Type type, Class<?> cls, Type type2, Collection<TypeVariable> collection) {
        TypeVariable typeVariable;
        do {
            int i2 = 0;
            if (!(type2 instanceof TypeVariable)) {
                if (type2 instanceof Class) {
                    Class cls2 = (Class) type2;
                    if (cls2.isArray()) {
                        Class<?> componentType = cls2.getComponentType();
                        Type m2764h = m2764h(type, cls, componentType, collection);
                        return componentType == m2764h ? cls2 : new a(m2764h);
                    }
                }
                if (type2 instanceof GenericArrayType) {
                    GenericArrayType genericArrayType = (GenericArrayType) type2;
                    Type genericComponentType = genericArrayType.getGenericComponentType();
                    Type m2764h2 = m2764h(type, cls, genericComponentType, collection);
                    return genericComponentType == m2764h2 ? genericArrayType : new a(m2764h2);
                }
                if (type2 instanceof ParameterizedType) {
                    ParameterizedType parameterizedType = (ParameterizedType) type2;
                    Type ownerType = parameterizedType.getOwnerType();
                    Type m2764h3 = m2764h(type, cls, ownerType, collection);
                    boolean z = m2764h3 != ownerType;
                    Type[] actualTypeArguments = parameterizedType.getActualTypeArguments();
                    int length = actualTypeArguments.length;
                    while (i2 < length) {
                        Type m2764h4 = m2764h(type, cls, actualTypeArguments[i2], collection);
                        if (m2764h4 != actualTypeArguments[i2]) {
                            if (!z) {
                                actualTypeArguments = (Type[]) actualTypeArguments.clone();
                                z = true;
                            }
                            actualTypeArguments[i2] = m2764h4;
                        }
                        i2++;
                    }
                    return z ? new b(m2764h3, parameterizedType.getRawType(), actualTypeArguments) : parameterizedType;
                }
                boolean z2 = type2 instanceof WildcardType;
                Type type3 = type2;
                if (z2) {
                    WildcardType wildcardType = (WildcardType) type2;
                    Type[] lowerBounds = wildcardType.getLowerBounds();
                    Type[] upperBounds = wildcardType.getUpperBounds();
                    if (lowerBounds.length == 1) {
                        Type m2764h5 = m2764h(type, cls, lowerBounds[0], collection);
                        type3 = wildcardType;
                        if (m2764h5 != lowerBounds[0]) {
                            return new c(new Type[]{Object.class}, m2764h5 instanceof WildcardType ? ((WildcardType) m2764h5).getLowerBounds() : new Type[]{m2764h5});
                        }
                    } else {
                        type3 = wildcardType;
                        if (upperBounds.length == 1) {
                            Type m2764h6 = m2764h(type, cls, upperBounds[0], collection);
                            type3 = wildcardType;
                            if (m2764h6 != upperBounds[0]) {
                                return new c(m2764h6 instanceof WildcardType ? ((WildcardType) m2764h6).getUpperBounds() : new Type[]{m2764h6}, f6452a);
                            }
                        }
                    }
                }
                return type3;
            }
            typeVariable = (TypeVariable) type2;
            if (collection.contains(typeVariable)) {
                return type2;
            }
            collection.add(typeVariable);
            GenericDeclaration genericDeclaration = typeVariable.getGenericDeclaration();
            Class cls3 = genericDeclaration instanceof Class ? (Class) genericDeclaration : null;
            if (cls3 != null) {
                Type m2760d = m2760d(type, cls, cls3);
                if (m2760d instanceof ParameterizedType) {
                    TypeVariable[] typeParameters = cls3.getTypeParameters();
                    int length2 = typeParameters.length;
                    while (i2 < length2) {
                        if (typeVariable.equals(typeParameters[i2])) {
                            type2 = ((ParameterizedType) m2760d).getActualTypeArguments()[i2];
                        } else {
                            i2++;
                        }
                    }
                    throw new NoSuchElementException();
                }
            }
            type2 = typeVariable;
        } while (type2 != typeVariable);
        return type2;
    }

    /* renamed from: i */
    public static String m2765i(Type type) {
        return type instanceof Class ? ((Class) type).getName() : type.toString();
    }
}
