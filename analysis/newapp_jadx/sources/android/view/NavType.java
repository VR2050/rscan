package android.view;

import android.os.Bundle;
import android.os.Parcelable;
import androidx.annotation.AnyRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.Serializable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public abstract class NavType<T> {

    @NonNull
    public static final NavType<boolean[]> BoolArrayType;

    @NonNull
    public static final NavType<Boolean> BoolType;

    @NonNull
    public static final NavType<float[]> FloatArrayType;

    @NonNull
    public static final NavType<Float> FloatType;

    @NonNull
    public static final NavType<int[]> IntArrayType;

    @NonNull
    public static final NavType<Integer> IntType;

    @NonNull
    public static final NavType<long[]> LongArrayType;

    @NonNull
    public static final NavType<Long> LongType;

    @NonNull
    public static final NavType<Integer> ReferenceType;

    @NonNull
    public static final NavType<String[]> StringArrayType;

    @NonNull
    public static final NavType<String> StringType;
    private final boolean mNullableAllowed;

    public static final class ParcelableArrayType<D extends Parcelable> extends NavType<D[]> {

        @NonNull
        private final Class<D[]> mArrayType;

        public ParcelableArrayType(@NonNull Class<D> cls) {
            super(true);
            if (!Parcelable.class.isAssignableFrom(cls)) {
                throw new IllegalArgumentException(cls + " does not implement Parcelable.");
            }
            try {
                this.mArrayType = (Class<D[]>) Class.forName("[L" + cls.getName() + ";");
            } catch (ClassNotFoundException e2) {
                throw new RuntimeException(e2);
            }
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || ParcelableArrayType.class != obj.getClass()) {
                return false;
            }
            return this.mArrayType.equals(((ParcelableArrayType) obj).mArrayType);
        }

        @Override // android.view.NavType
        @NonNull
        public String getName() {
            return this.mArrayType.getName();
        }

        public int hashCode() {
            return this.mArrayType.hashCode();
        }

        @Override // android.view.NavType
        @Nullable
        public D[] get(@NonNull Bundle bundle, @NonNull String str) {
            return (D[]) ((Parcelable[]) bundle.get(str));
        }

        @Override // android.view.NavType
        @NonNull
        public D[] parseValue(@NonNull String str) {
            throw new UnsupportedOperationException("Arrays don't support default values.");
        }

        @Override // android.view.NavType
        public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable D[] dArr) {
            this.mArrayType.cast(dArr);
            bundle.putParcelableArray(str, dArr);
        }
    }

    public static final class ParcelableType<D> extends NavType<D> {

        @NonNull
        private final Class<D> mType;

        public ParcelableType(@NonNull Class<D> cls) {
            super(true);
            if (Parcelable.class.isAssignableFrom(cls) || Serializable.class.isAssignableFrom(cls)) {
                this.mType = cls;
                return;
            }
            throw new IllegalArgumentException(cls + " does not implement Parcelable or Serializable.");
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || ParcelableType.class != obj.getClass()) {
                return false;
            }
            return this.mType.equals(((ParcelableType) obj).mType);
        }

        @Override // android.view.NavType
        @Nullable
        public D get(@NonNull Bundle bundle, @NonNull String str) {
            return (D) bundle.get(str);
        }

        @Override // android.view.NavType
        @NonNull
        public String getName() {
            return this.mType.getName();
        }

        public int hashCode() {
            return this.mType.hashCode();
        }

        @Override // android.view.NavType
        @NonNull
        public D parseValue(@NonNull String str) {
            throw new UnsupportedOperationException("Parcelables don't support default values.");
        }

        @Override // android.view.NavType
        public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable D d2) {
            this.mType.cast(d2);
            if (d2 == null || (d2 instanceof Parcelable)) {
                bundle.putParcelable(str, (Parcelable) d2);
            } else if (d2 instanceof Serializable) {
                bundle.putSerializable(str, (Serializable) d2);
            }
        }
    }

    public static final class SerializableArrayType<D extends Serializable> extends NavType<D[]> {

        @NonNull
        private final Class<D[]> mArrayType;

        public SerializableArrayType(@NonNull Class<D> cls) {
            super(true);
            if (!Serializable.class.isAssignableFrom(cls)) {
                throw new IllegalArgumentException(cls + " does not implement Serializable.");
            }
            try {
                this.mArrayType = (Class<D[]>) Class.forName("[L" + cls.getName() + ";");
            } catch (ClassNotFoundException e2) {
                throw new RuntimeException(e2);
            }
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || SerializableArrayType.class != obj.getClass()) {
                return false;
            }
            return this.mArrayType.equals(((SerializableArrayType) obj).mArrayType);
        }

        @Override // android.view.NavType
        @NonNull
        public String getName() {
            return this.mArrayType.getName();
        }

        public int hashCode() {
            return this.mArrayType.hashCode();
        }

        @Override // android.view.NavType
        @Nullable
        public D[] get(@NonNull Bundle bundle, @NonNull String str) {
            return (D[]) ((Serializable[]) bundle.get(str));
        }

        @Override // android.view.NavType
        @NonNull
        public D[] parseValue(@NonNull String str) {
            throw new UnsupportedOperationException("Arrays don't support default values.");
        }

        /* JADX WARN: Multi-variable type inference failed */
        @Override // android.view.NavType
        public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable D[] dArr) {
            this.mArrayType.cast(dArr);
            bundle.putSerializable(str, dArr);
        }
    }

    public static class SerializableType<D extends Serializable> extends NavType<D> {

        @NonNull
        private final Class<D> mType;

        public SerializableType(@NonNull Class<D> cls) {
            super(true);
            if (!Serializable.class.isAssignableFrom(cls)) {
                throw new IllegalArgumentException(cls + " does not implement Serializable.");
            }
            if (!cls.isEnum()) {
                this.mType = cls;
                return;
            }
            throw new IllegalArgumentException(cls + " is an Enum. You should use EnumType instead.");
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof SerializableType) {
                return this.mType.equals(((SerializableType) obj).mType);
            }
            return false;
        }

        @Override // android.view.NavType
        @NonNull
        public String getName() {
            return this.mType.getName();
        }

        public int hashCode() {
            return this.mType.hashCode();
        }

        @Override // android.view.NavType
        @Nullable
        public D get(@NonNull Bundle bundle, @NonNull String str) {
            return (D) bundle.get(str);
        }

        @Override // android.view.NavType
        @NonNull
        public D parseValue(@NonNull String str) {
            throw new UnsupportedOperationException("Serializables don't support default values.");
        }

        @Override // android.view.NavType
        public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable D d2) {
            this.mType.cast(d2);
            bundle.putSerializable(str, d2);
        }

        public SerializableType(boolean z, @NonNull Class<D> cls) {
            super(z);
            if (Serializable.class.isAssignableFrom(cls)) {
                this.mType = cls;
                return;
            }
            throw new IllegalArgumentException(cls + " does not implement Serializable.");
        }
    }

    static {
        boolean z = false;
        IntType = new NavType<Integer>(z) { // from class: androidx.navigation.NavType.1
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "integer";
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            public Integer get(@NonNull Bundle bundle, @NonNull String str) {
                return (Integer) bundle.get(str);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            @NonNull
            public Integer parseValue(@NonNull String str) {
                return str.startsWith("0x") ? Integer.valueOf(Integer.parseInt(str.substring(2), 16)) : Integer.valueOf(Integer.parseInt(str));
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @NonNull Integer num) {
                bundle.putInt(str, num.intValue());
            }
        };
        ReferenceType = new NavType<Integer>(z) { // from class: androidx.navigation.NavType.2
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "reference";
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            @AnyRes
            public Integer get(@NonNull Bundle bundle, @NonNull String str) {
                return (Integer) bundle.get(str);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            @NonNull
            public Integer parseValue(@NonNull String str) {
                throw new UnsupportedOperationException("References don't support parsing string values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @NonNull @AnyRes Integer num) {
                bundle.putInt(str, num.intValue());
            }
        };
        boolean z2 = true;
        IntArrayType = new NavType<int[]>(z2) { // from class: androidx.navigation.NavType.3
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "integer[]";
            }

            @Override // android.view.NavType
            public int[] get(@NonNull Bundle bundle, @NonNull String str) {
                return (int[]) bundle.get(str);
            }

            @Override // android.view.NavType
            @NonNull
            public int[] parseValue(@NonNull String str) {
                throw new UnsupportedOperationException("Arrays don't support default values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable int[] iArr) {
                bundle.putIntArray(str, iArr);
            }
        };
        LongType = new NavType<Long>(z) { // from class: androidx.navigation.NavType.4
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "long";
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            public Long get(@NonNull Bundle bundle, @NonNull String str) {
                return (Long) bundle.get(str);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            @NonNull
            public Long parseValue(@NonNull String str) {
                if (str.endsWith("L")) {
                    str = str.substring(0, str.length() - 1);
                }
                return str.startsWith("0x") ? Long.valueOf(Long.parseLong(str.substring(2), 16)) : Long.valueOf(Long.parseLong(str));
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @NonNull Long l2) {
                bundle.putLong(str, l2.longValue());
            }
        };
        LongArrayType = new NavType<long[]>(z2) { // from class: androidx.navigation.NavType.5
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "long[]";
            }

            @Override // android.view.NavType
            public long[] get(@NonNull Bundle bundle, @NonNull String str) {
                return (long[]) bundle.get(str);
            }

            @Override // android.view.NavType
            @NonNull
            public long[] parseValue(@NonNull String str) {
                throw new UnsupportedOperationException("Arrays don't support default values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable long[] jArr) {
                bundle.putLongArray(str, jArr);
            }
        };
        FloatType = new NavType<Float>(z) { // from class: androidx.navigation.NavType.6
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "float";
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            public Float get(@NonNull Bundle bundle, @NonNull String str) {
                return (Float) bundle.get(str);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            @NonNull
            public Float parseValue(@NonNull String str) {
                return Float.valueOf(Float.parseFloat(str));
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @NonNull Float f2) {
                bundle.putFloat(str, f2.floatValue());
            }
        };
        FloatArrayType = new NavType<float[]>(z2) { // from class: androidx.navigation.NavType.7
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "float[]";
            }

            @Override // android.view.NavType
            public float[] get(@NonNull Bundle bundle, @NonNull String str) {
                return (float[]) bundle.get(str);
            }

            @Override // android.view.NavType
            @NonNull
            public float[] parseValue(@NonNull String str) {
                throw new UnsupportedOperationException("Arrays don't support default values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable float[] fArr) {
                bundle.putFloatArray(str, fArr);
            }
        };
        BoolType = new NavType<Boolean>(z) { // from class: androidx.navigation.NavType.8
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "boolean";
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            public Boolean get(@NonNull Bundle bundle, @NonNull String str) {
                return (Boolean) bundle.get(str);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.view.NavType
            @NonNull
            public Boolean parseValue(@NonNull String str) {
                if ("true".equals(str)) {
                    return Boolean.TRUE;
                }
                if ("false".equals(str)) {
                    return Boolean.FALSE;
                }
                throw new IllegalArgumentException("A boolean NavType only accepts \"true\" or \"false\" values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @NonNull Boolean bool) {
                bundle.putBoolean(str, bool.booleanValue());
            }
        };
        BoolArrayType = new NavType<boolean[]>(z2) { // from class: androidx.navigation.NavType.9
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "boolean[]";
            }

            @Override // android.view.NavType
            public boolean[] get(@NonNull Bundle bundle, @NonNull String str) {
                return (boolean[]) bundle.get(str);
            }

            @Override // android.view.NavType
            @NonNull
            public boolean[] parseValue(@NonNull String str) {
                throw new UnsupportedOperationException("Arrays don't support default values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable boolean[] zArr) {
                bundle.putBooleanArray(str, zArr);
            }
        };
        StringType = new NavType<String>(z2) { // from class: androidx.navigation.NavType.10
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "string";
            }

            @Override // android.view.NavType
            @NonNull
            public String parseValue(@NonNull String str) {
                return str;
            }

            @Override // android.view.NavType
            public String get(@NonNull Bundle bundle, @NonNull String str) {
                return (String) bundle.get(str);
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable String str2) {
                bundle.putString(str, str2);
            }
        };
        StringArrayType = new NavType<String[]>(z2) { // from class: androidx.navigation.NavType.11
            @Override // android.view.NavType
            @NonNull
            public String getName() {
                return "string[]";
            }

            @Override // android.view.NavType
            public String[] get(@NonNull Bundle bundle, @NonNull String str) {
                return (String[]) bundle.get(str);
            }

            @Override // android.view.NavType
            @NonNull
            public String[] parseValue(@NonNull String str) {
                throw new UnsupportedOperationException("Arrays don't support default values.");
            }

            @Override // android.view.NavType
            public void put(@NonNull Bundle bundle, @NonNull String str, @Nullable String[] strArr) {
                bundle.putStringArray(str, strArr);
            }
        };
    }

    public NavType(boolean z) {
        this.mNullableAllowed = z;
    }

    @NonNull
    public static NavType<?> fromArgType(@Nullable String str, @Nullable String str2) {
        String str3;
        NavType<Integer> navType = IntType;
        if (navType.getName().equals(str)) {
            return navType;
        }
        NavType navType2 = IntArrayType;
        if (navType2.getName().equals(str)) {
            return navType2;
        }
        NavType<Long> navType3 = LongType;
        if (navType3.getName().equals(str)) {
            return navType3;
        }
        NavType navType4 = LongArrayType;
        if (navType4.getName().equals(str)) {
            return navType4;
        }
        NavType<Boolean> navType5 = BoolType;
        if (navType5.getName().equals(str)) {
            return navType5;
        }
        NavType navType6 = BoolArrayType;
        if (navType6.getName().equals(str)) {
            return navType6;
        }
        NavType<String> navType7 = StringType;
        if (navType7.getName().equals(str)) {
            return navType7;
        }
        NavType navType8 = StringArrayType;
        if (navType8.getName().equals(str)) {
            return navType8;
        }
        NavType<Float> navType9 = FloatType;
        if (navType9.getName().equals(str)) {
            return navType9;
        }
        NavType navType10 = FloatArrayType;
        if (navType10.getName().equals(str)) {
            return navType10;
        }
        NavType<Integer> navType11 = ReferenceType;
        if (navType11.getName().equals(str)) {
            return navType11;
        }
        if (str == null || str.isEmpty()) {
            return navType7;
        }
        try {
            if (!str.startsWith(".") || str2 == null) {
                str3 = str;
            } else {
                str3 = str2 + str;
            }
            if (str.endsWith("[]")) {
                str3 = str3.substring(0, str3.length() - 2);
                Class<?> cls = Class.forName(str3);
                if (Parcelable.class.isAssignableFrom(cls)) {
                    return new ParcelableArrayType(cls);
                }
                if (Serializable.class.isAssignableFrom(cls)) {
                    return new SerializableArrayType(cls);
                }
            } else {
                Class<?> cls2 = Class.forName(str3);
                if (Parcelable.class.isAssignableFrom(cls2)) {
                    return new ParcelableType(cls2);
                }
                if (Enum.class.isAssignableFrom(cls2)) {
                    return new EnumType(cls2);
                }
                if (Serializable.class.isAssignableFrom(cls2)) {
                    return new SerializableType(cls2);
                }
            }
            throw new IllegalArgumentException(str3 + " is not Serializable or Parcelable.");
        } catch (ClassNotFoundException e2) {
            throw new RuntimeException(e2);
        }
    }

    @NonNull
    public static NavType inferFromValue(@NonNull String str) {
        try {
            try {
                try {
                    try {
                        NavType<Integer> navType = IntType;
                        navType.parseValue(str);
                        return navType;
                    } catch (IllegalArgumentException unused) {
                        NavType<Boolean> navType2 = BoolType;
                        navType2.parseValue(str);
                        return navType2;
                    }
                } catch (IllegalArgumentException unused2) {
                    NavType<Float> navType3 = FloatType;
                    navType3.parseValue(str);
                    return navType3;
                }
            } catch (IllegalArgumentException unused3) {
                NavType<Long> navType4 = LongType;
                navType4.parseValue(str);
                return navType4;
            }
        } catch (IllegalArgumentException unused4) {
            return StringType;
        }
    }

    @NonNull
    public static NavType inferFromValueType(@Nullable Object obj) {
        if (obj instanceof Integer) {
            return IntType;
        }
        if (obj instanceof int[]) {
            return IntArrayType;
        }
        if (obj instanceof Long) {
            return LongType;
        }
        if (obj instanceof long[]) {
            return LongArrayType;
        }
        if (obj instanceof Float) {
            return FloatType;
        }
        if (obj instanceof float[]) {
            return FloatArrayType;
        }
        if (obj instanceof Boolean) {
            return BoolType;
        }
        if (obj instanceof boolean[]) {
            return BoolArrayType;
        }
        if ((obj instanceof String) || obj == null) {
            return StringType;
        }
        if (obj instanceof String[]) {
            return StringArrayType;
        }
        if (obj.getClass().isArray() && Parcelable.class.isAssignableFrom(obj.getClass().getComponentType())) {
            return new ParcelableArrayType(obj.getClass().getComponentType());
        }
        if (obj.getClass().isArray() && Serializable.class.isAssignableFrom(obj.getClass().getComponentType())) {
            return new SerializableArrayType(obj.getClass().getComponentType());
        }
        if (obj instanceof Parcelable) {
            return new ParcelableType(obj.getClass());
        }
        if (obj instanceof Enum) {
            return new EnumType(obj.getClass());
        }
        if (obj instanceof Serializable) {
            return new SerializableType(obj.getClass());
        }
        StringBuilder m586H = C1499a.m586H("Object of type ");
        m586H.append(obj.getClass().getName());
        m586H.append(" is not supported for navigation arguments.");
        throw new IllegalArgumentException(m586H.toString());
    }

    @Nullable
    public abstract T get(@NonNull Bundle bundle, @NonNull String str);

    @NonNull
    public abstract String getName();

    public boolean isNullableAllowed() {
        return this.mNullableAllowed;
    }

    @NonNull
    public T parseAndPut(@NonNull Bundle bundle, @NonNull String str, @NonNull String str2) {
        T parseValue = parseValue(str2);
        put(bundle, str, parseValue);
        return parseValue;
    }

    @NonNull
    public abstract T parseValue(@NonNull String str);

    public abstract void put(@NonNull Bundle bundle, @NonNull String str, @Nullable T t);

    @NonNull
    public String toString() {
        return getName();
    }

    public static final class EnumType<D extends Enum> extends SerializableType<D> {

        @NonNull
        private final Class<D> mType;

        public EnumType(@NonNull Class<D> cls) {
            super(false, cls);
            if (cls.isEnum()) {
                this.mType = cls;
                return;
            }
            throw new IllegalArgumentException(cls + " is not an Enum type.");
        }

        @Override // androidx.navigation.NavType.SerializableType, android.view.NavType
        @NonNull
        public String getName() {
            return this.mType.getName();
        }

        @Override // androidx.navigation.NavType.SerializableType, android.view.NavType
        @NonNull
        public D parseValue(@NonNull String str) {
            for (D d2 : this.mType.getEnumConstants()) {
                if (d2.name().equals(str)) {
                    return d2;
                }
            }
            StringBuilder m591M = C1499a.m591M("Enum value ", str, " not found for type ");
            m591M.append(this.mType.getName());
            m591M.append(".");
            throw new IllegalArgumentException(m591M.toString());
        }
    }
}
