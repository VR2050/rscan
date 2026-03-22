package com.alibaba.fastjson.util;

import com.alibaba.fastjson.annotation.JSONField;
import java.lang.annotation.Annotation;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.util.Map;
import kotlin.text.Typography;

/* loaded from: classes.dex */
public class FieldInfo implements Comparable<FieldInfo> {
    public final String[] alternateNames;
    public final Class<?> declaringClass;
    public final Field field;
    public final boolean fieldAccess;
    private final JSONField fieldAnnotation;
    public final Class<?> fieldClass;
    public final boolean fieldTransient;
    public final Type fieldType;
    public final String format;
    public final boolean getOnly;
    public final boolean isEnum;
    public final boolean jsonDirect;
    public final String label;
    public final Method method;
    private final JSONField methodAnnotation;
    public final String name;
    public final char[] name_chars;
    private int ordinal;
    public final int parserFeatures;
    public final int serialzeFeatures;
    public final boolean unwrapped;

    public FieldInfo(String str, Class<?> cls, Class<?> cls2, Type type, Field field, int i2, int i3, int i4) {
        this.ordinal = 0;
        i2 = i2 < 0 ? 0 : i2;
        this.name = str;
        this.declaringClass = cls;
        this.fieldClass = cls2;
        this.fieldType = type;
        this.method = null;
        this.field = field;
        this.ordinal = i2;
        this.serialzeFeatures = i3;
        this.parserFeatures = i4;
        this.isEnum = cls2.isEnum();
        if (field != null) {
            int modifiers = field.getModifiers();
            int i5 = modifiers & 1;
            this.fieldAccess = true;
            this.fieldTransient = Modifier.isTransient(modifiers);
        } else {
            this.fieldTransient = false;
            this.fieldAccess = false;
        }
        this.name_chars = genFieldNameChars();
        if (field != null) {
            TypeUtils.setAccessible(field);
        }
        this.label = "";
        this.fieldAnnotation = field == null ? null : (JSONField) TypeUtils.getAnnotation(field, JSONField.class);
        this.methodAnnotation = null;
        this.getOnly = false;
        this.jsonDirect = false;
        this.unwrapped = false;
        this.format = null;
        this.alternateNames = new String[0];
    }

    private static boolean getArgument(Type[] typeArr, Map<TypeVariable, Type> map) {
        if (map == null || map.size() == 0) {
            return false;
        }
        boolean z = false;
        for (int i2 = 0; i2 < typeArr.length; i2++) {
            Type type = typeArr[i2];
            if (type instanceof ParameterizedType) {
                ParameterizedType parameterizedType = (ParameterizedType) type;
                Type[] actualTypeArguments = parameterizedType.getActualTypeArguments();
                if (getArgument(actualTypeArguments, map)) {
                    typeArr[i2] = new ParameterizedTypeImpl(actualTypeArguments, parameterizedType.getOwnerType(), parameterizedType.getRawType());
                    z = true;
                }
            } else {
                if ((type instanceof TypeVariable) && map.containsKey(type)) {
                    typeArr[i2] = map.get(type);
                    z = true;
                }
            }
        }
        return z;
    }

    public static Type getFieldType(Class<?> cls, Type type, Type type2) {
        return getFieldType(cls, type, type2, null);
    }

    private static Type getInheritGenericType(Class<?> cls, Type type, TypeVariable<?> typeVariable) {
        Type[] typeArr;
        Class<?> cls2 = typeVariable.getGenericDeclaration() instanceof Class ? (Class) typeVariable.getGenericDeclaration() : null;
        if (cls2 == cls) {
            typeArr = type instanceof ParameterizedType ? ((ParameterizedType) type).getActualTypeArguments() : null;
        } else {
            Type[] typeArr2 = null;
            while (cls != null && cls != Object.class && cls != cls2) {
                Type genericSuperclass = cls.getGenericSuperclass();
                if (genericSuperclass instanceof ParameterizedType) {
                    Type[] actualTypeArguments = ((ParameterizedType) genericSuperclass).getActualTypeArguments();
                    getArgument(actualTypeArguments, cls.getTypeParameters(), typeArr2);
                    typeArr2 = actualTypeArguments;
                }
                cls = cls.getSuperclass();
            }
            typeArr = typeArr2;
        }
        if (typeArr == null || cls2 == null) {
            return null;
        }
        TypeVariable<Class<?>>[] typeParameters = cls2.getTypeParameters();
        for (int i2 = 0; i2 < typeParameters.length; i2++) {
            if (typeVariable.equals(typeParameters[i2])) {
                return typeArr[i2];
            }
        }
        return null;
    }

    public char[] genFieldNameChars() {
        int length = this.name.length();
        char[] cArr = new char[length + 3];
        String str = this.name;
        str.getChars(0, str.length(), cArr, 1);
        cArr[0] = Typography.quote;
        cArr[length + 1] = Typography.quote;
        cArr[length + 2] = ':';
        return cArr;
    }

    public Object get(Object obj) {
        Method method = this.method;
        return method != null ? method.invoke(obj, new Object[0]) : this.field.get(obj);
    }

    public <T extends Annotation> T getAnnation(Class<T> cls) {
        Field field;
        if (cls == JSONField.class) {
            return getAnnotation();
        }
        T t = null;
        Method method = this.method;
        if (method != null) {
            t = (T) TypeUtils.getAnnotation(method, cls);
        }
        return (t != null || (field = this.field) == null) ? t : (T) TypeUtils.getAnnotation(field, cls);
    }

    public JSONField getAnnotation() {
        JSONField jSONField = this.fieldAnnotation;
        return jSONField != null ? jSONField : this.methodAnnotation;
    }

    public Class<?> getDeclaredClass() {
        Method method = this.method;
        if (method != null) {
            return method.getDeclaringClass();
        }
        Field field = this.field;
        if (field != null) {
            return field.getDeclaringClass();
        }
        return null;
    }

    public String getFormat() {
        return this.format;
    }

    public Member getMember() {
        Method method = this.method;
        return method != null ? method : this.field;
    }

    public void set(Object obj, Object obj2) {
        Method method = this.method;
        if (method != null) {
            method.invoke(obj, obj2);
        } else {
            this.field.set(obj, obj2);
        }
    }

    public void setAccessible() {
        Method method = this.method;
        if (method != null) {
            TypeUtils.setAccessible(method);
        } else {
            TypeUtils.setAccessible(this.field);
        }
    }

    public String toString() {
        return this.name;
    }

    public static Type getFieldType(Class<?> cls, Type type, Type type2, Map<TypeVariable, Type> map) {
        TypeVariable<Class<?>>[] typeParameters;
        ParameterizedType parameterizedType;
        if (cls != null && type != null) {
            if (type2 instanceof GenericArrayType) {
                Type genericComponentType = ((GenericArrayType) type2).getGenericComponentType();
                Type fieldType = getFieldType(cls, type, genericComponentType, map);
                return genericComponentType != fieldType ? Array.newInstance(TypeUtils.getClass(fieldType), 0).getClass() : type2;
            }
            if (!TypeUtils.isGenericParamType(type)) {
                return type2;
            }
            if (type2 instanceof TypeVariable) {
                ParameterizedType parameterizedType2 = (ParameterizedType) TypeUtils.getGenericParamType(type);
                TypeVariable typeVariable = (TypeVariable) type2;
                TypeVariable<Class<?>>[] typeParameters2 = TypeUtils.getClass(parameterizedType2).getTypeParameters();
                for (int i2 = 0; i2 < typeParameters2.length; i2++) {
                    if (typeParameters2[i2].getName().equals(typeVariable.getName())) {
                        return parameterizedType2.getActualTypeArguments()[i2];
                    }
                }
            }
            if (type2 instanceof ParameterizedType) {
                ParameterizedType parameterizedType3 = (ParameterizedType) type2;
                Type[] actualTypeArguments = parameterizedType3.getActualTypeArguments();
                boolean argument = getArgument(actualTypeArguments, map);
                if (!argument) {
                    if (type instanceof ParameterizedType) {
                        parameterizedType = (ParameterizedType) type;
                        typeParameters = cls.getTypeParameters();
                    } else if (cls.getGenericSuperclass() instanceof ParameterizedType) {
                        parameterizedType = (ParameterizedType) cls.getGenericSuperclass();
                        typeParameters = cls.getSuperclass().getTypeParameters();
                    } else {
                        typeParameters = type.getClass().getTypeParameters();
                        parameterizedType = parameterizedType3;
                    }
                    argument = getArgument(actualTypeArguments, typeParameters, parameterizedType.getActualTypeArguments());
                }
                if (argument) {
                    return new ParameterizedTypeImpl(actualTypeArguments, parameterizedType3.getOwnerType(), parameterizedType3.getRawType());
                }
            }
        }
        return type2;
    }

    @Override // java.lang.Comparable
    public int compareTo(FieldInfo fieldInfo) {
        int i2 = this.ordinal;
        int i3 = fieldInfo.ordinal;
        if (i2 < i3) {
            return -1;
        }
        if (i2 > i3) {
            return 1;
        }
        int compareTo = this.name.compareTo(fieldInfo.name);
        if (compareTo != 0) {
            return compareTo;
        }
        Class<?> declaredClass = getDeclaredClass();
        Class<?> declaredClass2 = fieldInfo.getDeclaredClass();
        if (declaredClass != null && declaredClass2 != null && declaredClass != declaredClass2) {
            if (declaredClass.isAssignableFrom(declaredClass2)) {
                return -1;
            }
            if (declaredClass2.isAssignableFrom(declaredClass)) {
                return 1;
            }
        }
        Field field = this.field;
        boolean z = false;
        boolean z2 = field != null && field.getType() == this.fieldClass;
        Field field2 = fieldInfo.field;
        if (field2 != null && field2.getType() == fieldInfo.fieldClass) {
            z = true;
        }
        if (z2 && !z) {
            return 1;
        }
        if (z && !z2) {
            return -1;
        }
        if (fieldInfo.fieldClass.isPrimitive() && !this.fieldClass.isPrimitive()) {
            return 1;
        }
        if (this.fieldClass.isPrimitive() && !fieldInfo.fieldClass.isPrimitive()) {
            return -1;
        }
        if (fieldInfo.fieldClass.getName().startsWith("java.") && !this.fieldClass.getName().startsWith("java.")) {
            return 1;
        }
        if (!this.fieldClass.getName().startsWith("java.") || fieldInfo.fieldClass.getName().startsWith("java.")) {
            return this.fieldClass.getName().compareTo(fieldInfo.fieldClass.getName());
        }
        return -1;
    }

    private static boolean getArgument(Type[] typeArr, TypeVariable[] typeVariableArr, Type[] typeArr2) {
        if (typeArr2 == null || typeVariableArr.length == 0) {
            return false;
        }
        boolean z = false;
        for (int i2 = 0; i2 < typeArr.length; i2++) {
            Type type = typeArr[i2];
            if (type instanceof ParameterizedType) {
                ParameterizedType parameterizedType = (ParameterizedType) type;
                Type[] actualTypeArguments = parameterizedType.getActualTypeArguments();
                if (getArgument(actualTypeArguments, typeVariableArr, typeArr2)) {
                    typeArr[i2] = new ParameterizedTypeImpl(actualTypeArguments, parameterizedType.getOwnerType(), parameterizedType.getRawType());
                    z = true;
                }
            } else if (type instanceof TypeVariable) {
                for (int i3 = 0; i3 < typeVariableArr.length; i3++) {
                    if (type.equals(typeVariableArr[i3])) {
                        typeArr[i2] = typeArr2[i3];
                        z = true;
                    }
                }
            }
        }
        return z;
    }

    public FieldInfo(String str, Method method, Field field, Class<?> cls, Type type, int i2, int i3, int i4, JSONField jSONField, JSONField jSONField2, String str2) {
        this(str, method, field, cls, type, i2, i3, i4, jSONField, jSONField2, str2, null);
    }

    /* JADX WARN: Code restructure failed: missing block: B:4:0x001f, code lost:
    
        if (r9.equals(r14) != false) goto L9;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public FieldInfo(java.lang.String r14, java.lang.reflect.Method r15, java.lang.reflect.Field r16, java.lang.Class<?> r17, java.lang.reflect.Type r18, int r19, int r20, int r21, com.alibaba.fastjson.annotation.JSONField r22, com.alibaba.fastjson.annotation.JSONField r23, java.lang.String r24, java.util.Map<java.lang.reflect.TypeVariable, java.lang.reflect.Type> r25) {
        /*
            Method dump skipped, instructions count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.util.FieldInfo.<init>(java.lang.String, java.lang.reflect.Method, java.lang.reflect.Field, java.lang.Class, java.lang.reflect.Type, int, int, int, com.alibaba.fastjson.annotation.JSONField, com.alibaba.fastjson.annotation.JSONField, java.lang.String, java.util.Map):void");
    }
}
