package com.alibaba.fastjson.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.JSONScanner;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.parser.deserializer.FieldDeserializer;
import com.alibaba.fastjson.serializer.SerializerFeature;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Proxy;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.AccessControlException;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/* JADX INFO: loaded from: classes.dex */
public class TypeUtils {
    public static boolean compatibleWithJavaBean = false;
    private static boolean setAccessibleEnable = true;
    private static ConcurrentMap<String, Class<?>> mappings = new ConcurrentHashMap();

    static {
        addBaseClassMappings();
    }

    public static final String castToString(Object value) {
        if (value == null) {
            return null;
        }
        return value.toString();
    }

    public static final Byte castToByte(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return Byte.valueOf(((Number) value).byteValue());
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0 || "null".equals(strVal)) {
                return null;
            }
            return Byte.valueOf(Byte.parseByte(strVal));
        }
        throw new JSONException("can not cast to byte, value : " + value);
    }

    public static final Character castToChar(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Character) {
            return (Character) value;
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0) {
                return null;
            }
            if (strVal.length() != 1) {
                throw new JSONException("can not cast to byte, value : " + value);
            }
            return Character.valueOf(strVal.charAt(0));
        }
        throw new JSONException("can not cast to byte, value : " + value);
    }

    public static final Short castToShort(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return Short.valueOf(((Number) value).shortValue());
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0 || "null".equals(strVal)) {
                return null;
            }
            return Short.valueOf(Short.parseShort(strVal));
        }
        throw new JSONException("can not cast to short, value : " + value);
    }

    public static final BigDecimal castToBigDecimal(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof BigDecimal) {
            return (BigDecimal) value;
        }
        if (value instanceof BigInteger) {
            return new BigDecimal((BigInteger) value);
        }
        String strVal = value.toString();
        if (strVal.length() == 0) {
            return null;
        }
        return new BigDecimal(strVal);
    }

    public static final BigInteger castToBigInteger(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof BigInteger) {
            return (BigInteger) value;
        }
        if ((value instanceof Float) || (value instanceof Double)) {
            return BigInteger.valueOf(((Number) value).longValue());
        }
        String strVal = value.toString();
        if (strVal.length() == 0) {
            return null;
        }
        return new BigInteger(strVal);
    }

    public static final Float castToFloat(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return Float.valueOf(((Number) value).floatValue());
        }
        if (value instanceof String) {
            String strVal = value.toString();
            if (strVal.length() == 0 || "null".equals(strVal)) {
                return null;
            }
            return Float.valueOf(Float.parseFloat(strVal));
        }
        throw new JSONException("can not cast to float, value : " + value);
    }

    public static final Double castToDouble(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return Double.valueOf(((Number) value).doubleValue());
        }
        if (value instanceof String) {
            String strVal = value.toString();
            if (strVal.length() == 0 || "null".equals(strVal)) {
                return null;
            }
            return Double.valueOf(Double.parseDouble(strVal));
        }
        throw new JSONException("can not cast to double, value : " + value);
    }

    public static final Date castToDate(Object value) {
        String format;
        if (value == null) {
            return null;
        }
        if (value instanceof Calendar) {
            return ((Calendar) value).getTime();
        }
        if (value instanceof Date) {
            return (Date) value;
        }
        long longValue = -1;
        if (value instanceof Number) {
            longValue = ((Number) value).longValue();
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.indexOf(45) != -1) {
                if (strVal.length() == JSON.DEFFAULT_DATE_FORMAT.length()) {
                    format = JSON.DEFFAULT_DATE_FORMAT;
                } else if (strVal.length() == 10) {
                    format = "yyyy-MM-dd";
                } else if (strVal.length() == "yyyy-MM-dd HH:mm:ss".length()) {
                    format = "yyyy-MM-dd HH:mm:ss";
                } else {
                    format = "yyyy-MM-dd HH:mm:ss.SSS";
                }
                SimpleDateFormat dateFormat = new SimpleDateFormat(format);
                try {
                    return dateFormat.parse(strVal);
                } catch (ParseException e) {
                    throw new JSONException("can not cast to Date, value : " + strVal);
                }
            }
            if (strVal.length() == 0) {
                return null;
            }
            longValue = Long.parseLong(strVal);
        }
        if (longValue < 0) {
            throw new JSONException("can not cast to Date, value : " + value);
        }
        return new Date(longValue);
    }

    public static final java.sql.Date castToSqlDate(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Calendar) {
            return new java.sql.Date(((Calendar) value).getTimeInMillis());
        }
        if (value instanceof java.sql.Date) {
            return (java.sql.Date) value;
        }
        if (value instanceof Date) {
            return new java.sql.Date(((Date) value).getTime());
        }
        long longValue = 0;
        if (value instanceof Number) {
            longValue = ((Number) value).longValue();
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0) {
                return null;
            }
            longValue = Long.parseLong(strVal);
        }
        if (longValue <= 0) {
            throw new JSONException("can not cast to Date, value : " + value);
        }
        return new java.sql.Date(longValue);
    }

    public static final Timestamp castToTimestamp(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Calendar) {
            return new Timestamp(((Calendar) value).getTimeInMillis());
        }
        if (value instanceof Timestamp) {
            return (Timestamp) value;
        }
        if (value instanceof Date) {
            return new Timestamp(((Date) value).getTime());
        }
        long longValue = 0;
        if (value instanceof Number) {
            longValue = ((Number) value).longValue();
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0) {
                return null;
            }
            longValue = Long.parseLong(strVal);
        }
        if (longValue <= 0) {
            throw new JSONException("can not cast to Date, value : " + value);
        }
        return new Timestamp(longValue);
    }

    public static final Long castToLong(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number) {
            return Long.valueOf(((Number) value).longValue());
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0 || "null".equals(strVal)) {
                return null;
            }
            try {
                return Long.valueOf(Long.parseLong(strVal));
            } catch (NumberFormatException e) {
                JSONScanner dateParser = new JSONScanner(strVal);
                Calendar calendar = null;
                if (dateParser.scanISO8601DateIfMatch(false)) {
                    calendar = dateParser.getCalendar();
                }
                dateParser.close();
                if (calendar != null) {
                    return Long.valueOf(calendar.getTimeInMillis());
                }
            }
        }
        throw new JSONException("can not cast to long, value : " + value);
    }

    public static final Integer castToInt(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof Number) {
            return Integer.valueOf(((Number) value).intValue());
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0 || "null".equals(strVal)) {
                return null;
            }
            return Integer.valueOf(Integer.parseInt(strVal));
        }
        throw new JSONException("can not cast to int, value : " + value);
    }

    public static final byte[] castToBytes(Object value) {
        if (value instanceof byte[]) {
            return (byte[]) value;
        }
        if (value instanceof String) {
            return Base64.decodeFast((String) value);
        }
        throw new JSONException("can not cast to int, value : " + value);
    }

    public static final Boolean castToBoolean(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof Number) {
            return Boolean.valueOf(((Number) value).intValue() == 1);
        }
        if (value instanceof String) {
            String strVal = (String) value;
            if (strVal.length() == 0) {
                return null;
            }
            if ("true".equalsIgnoreCase(strVal)) {
                return Boolean.TRUE;
            }
            if ("false".equalsIgnoreCase(strVal)) {
                return Boolean.FALSE;
            }
            if ("1".equals(strVal)) {
                return Boolean.TRUE;
            }
            if ("0".equals(strVal)) {
                return Boolean.FALSE;
            }
            if ("null".equals(strVal)) {
                return null;
            }
        }
        throw new JSONException("can not cast to int, value : " + value);
    }

    public static final <T> T castToJavaBean(Object obj, Class<T> cls) {
        return (T) cast(obj, (Class) cls, ParserConfig.getGlobalInstance());
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final <T> T cast(Object obj, Class<T> cls, ParserConfig parserConfig) {
        Object obj2;
        if (obj == 0) {
            return null;
        }
        if (cls == null) {
            throw new IllegalArgumentException("clazz is null");
        }
        if (cls == obj.getClass()) {
            return obj;
        }
        if (obj instanceof Map) {
            if (cls == Map.class) {
                return obj;
            }
            Map map = (Map) obj;
            if (cls == Object.class && !map.containsKey(JSON.DEFAULT_TYPE_KEY)) {
                return obj;
            }
            return (T) castToJavaBean((Map) obj, cls, parserConfig);
        }
        if (cls.isArray()) {
            if (obj instanceof Collection) {
                Collection collection = (Collection) obj;
                int i = 0;
                T t = (T) Array.newInstance(cls.getComponentType(), collection.size());
                Iterator it = collection.iterator();
                while (it.hasNext()) {
                    Array.set(t, i, cast(it.next(), (Class) cls.getComponentType(), parserConfig));
                    i++;
                }
                return t;
            }
            if (cls == byte[].class) {
                return (T) castToBytes(obj);
            }
        }
        if (cls.isAssignableFrom(obj.getClass())) {
            return obj;
        }
        if (cls == Boolean.TYPE || cls == Boolean.class) {
            return (T) castToBoolean(obj);
        }
        if (cls == Byte.TYPE || cls == Byte.class) {
            return (T) castToByte(obj);
        }
        if (cls == Short.TYPE || cls == Short.class) {
            return (T) castToShort(obj);
        }
        if (cls == Integer.TYPE || cls == Integer.class) {
            return (T) castToInt(obj);
        }
        if (cls == Long.TYPE || cls == Long.class) {
            return (T) castToLong(obj);
        }
        if (cls == Float.TYPE || cls == Float.class) {
            return (T) castToFloat(obj);
        }
        if (cls == Double.TYPE || cls == Double.class) {
            return (T) castToDouble(obj);
        }
        if (cls == String.class) {
            return (T) castToString(obj);
        }
        if (cls == BigDecimal.class) {
            return (T) castToBigDecimal(obj);
        }
        if (cls == BigInteger.class) {
            return (T) castToBigInteger(obj);
        }
        if (cls == Date.class) {
            return (T) castToDate(obj);
        }
        if (cls == java.sql.Date.class) {
            return (T) castToSqlDate(obj);
        }
        if (cls == Timestamp.class) {
            return (T) castToTimestamp(obj);
        }
        if (cls.isEnum()) {
            return (T) castToEnum(obj, cls, parserConfig);
        }
        if (Calendar.class.isAssignableFrom(cls)) {
            Date dateCastToDate = castToDate(obj);
            if (cls == Calendar.class) {
                obj2 = (T) Calendar.getInstance();
            } else {
                try {
                    obj2 = (T) ((Calendar) cls.newInstance());
                } catch (Exception e) {
                    throw new JSONException("can not cast to : " + cls.getName(), e);
                }
            }
            ((Calendar) obj2).setTime(dateCastToDate);
            return (T) obj2;
        }
        if ((obj instanceof String) && ((String) obj).length() == 0) {
            return null;
        }
        throw new JSONException("can not cast to : " + cls.getName());
    }

    /* JADX WARN: Type inference failed for: r8v1, types: [T, java.lang.Enum] */
    public static final <T> T castToEnum(Object obj, Class<T> cls, ParserConfig parserConfig) {
        try {
            if (obj instanceof String) {
                String str = (String) obj;
                if (str.length() == 0) {
                    return null;
                }
                return (T) Enum.valueOf(cls, str);
            }
            if (obj instanceof Number) {
                int iIntValue = ((Number) obj).intValue();
                for (Object obj2 : (Object[]) cls.getMethod("values", new Class[0]).invoke(null, new Object[0])) {
                    ?? r8 = (T) ((Enum) obj2);
                    if (r8.ordinal() == iIntValue) {
                        return r8;
                    }
                }
            }
            throw new JSONException("can not cast to : " + cls.getName());
        } catch (Exception e) {
            throw new JSONException("can not cast to : " + cls.getName(), e);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final <T> T cast(Object obj, Type type, ParserConfig parserConfig) {
        if (obj == 0) {
            return null;
        }
        if (type instanceof Class) {
            return (T) cast(obj, (Class) type, parserConfig);
        }
        if (type instanceof ParameterizedType) {
            return (T) cast(obj, (ParameterizedType) type, parserConfig);
        }
        if ((obj instanceof String) && ((String) obj).length() == 0) {
            return null;
        }
        if (type instanceof TypeVariable) {
            return obj;
        }
        throw new JSONException("can not cast to : " + type);
    }

    /* JADX WARN: Type inference failed for: r2v8, types: [T, java.util.HashMap, java.util.Map] */
    public static final <T> T cast(Object obj, ParameterizedType parameterizedType, ParserConfig parserConfig) {
        T t;
        Type rawType = parameterizedType.getRawType();
        if (rawType == Set.class || rawType == HashSet.class || rawType == TreeSet.class || rawType == List.class || rawType == ArrayList.class) {
            Type type = parameterizedType.getActualTypeArguments()[0];
            if (obj instanceof Iterable) {
                if (rawType == Set.class || rawType == HashSet.class) {
                    t = (T) new HashSet();
                } else if (rawType == TreeSet.class) {
                    t = (T) new TreeSet();
                } else {
                    t = (T) new ArrayList();
                }
                Iterator<T> it = ((Iterable) obj).iterator();
                while (it.hasNext()) {
                    ((Collection) t).add(cast(it.next(), type, parserConfig));
                }
                return t;
            }
        }
        if (rawType == Map.class || rawType == HashMap.class) {
            Type type2 = parameterizedType.getActualTypeArguments()[0];
            Type type3 = parameterizedType.getActualTypeArguments()[1];
            if (obj instanceof Map) {
                ?? r2 = (T) new HashMap();
                for (Map.Entry entry : ((Map) obj).entrySet()) {
                    r2.put(cast(entry.getKey(), type2, parserConfig), cast(entry.getValue(), type3, parserConfig));
                }
                return r2;
            }
        }
        if ((obj instanceof String) && ((String) obj).length() == 0) {
            return null;
        }
        if (parameterizedType.getActualTypeArguments().length == 1 && (parameterizedType.getActualTypeArguments()[0] instanceof WildcardType)) {
            return (T) cast(obj, rawType, parserConfig);
        }
        throw new JSONException("can not cast to : " + parameterizedType);
    }

    public static final <T> T castToJavaBean(Map<String, Object> map, Class<T> cls, ParserConfig parserConfig) {
        JSONObject jSONObject;
        int iIntValue;
        ParserConfig globalInstance = parserConfig;
        try {
            if (cls == StackTraceElement.class) {
                String str = (String) map.get("className");
                String str2 = (String) map.get("methodName");
                String str3 = (String) map.get("fileName");
                Number number = (Number) map.get("lineNumber");
                if (number == null) {
                    iIntValue = 0;
                } else {
                    iIntValue = number.intValue();
                }
                return (T) new StackTraceElement(str, str2, str3, iIntValue);
            }
            Object obj = map.get(JSON.DEFAULT_TYPE_KEY);
            if (obj instanceof String) {
                String str4 = (String) obj;
                Class<?> clsLoadClass = loadClass(str4);
                if (clsLoadClass == null) {
                    throw new ClassNotFoundException(str4 + " not found");
                }
                if (!clsLoadClass.equals(cls)) {
                    return (T) castToJavaBean(map, clsLoadClass, globalInstance);
                }
            }
            if (cls.isInterface()) {
                if (map instanceof JSONObject) {
                    jSONObject = (JSONObject) map;
                } else {
                    jSONObject = new JSONObject(map);
                }
                return (T) Proxy.newProxyInstance(Thread.currentThread().getContextClassLoader(), new Class[]{cls}, jSONObject);
            }
            if (globalInstance == null) {
                globalInstance = ParserConfig.getGlobalInstance();
            }
            try {
                Map<String, FieldDeserializer> fieldDeserializers = globalInstance.getFieldDeserializers(cls);
                Constructor<T> declaredConstructor = cls.getDeclaredConstructor(new Class[0]);
                if (!declaredConstructor.isAccessible()) {
                    declaredConstructor.setAccessible(true);
                }
                T tNewInstance = declaredConstructor.newInstance(new Object[0]);
                for (Map.Entry<String, FieldDeserializer> entry : fieldDeserializers.entrySet()) {
                    String key = entry.getKey();
                    FieldDeserializer value = entry.getValue();
                    if (map.containsKey(key)) {
                        Object obj2 = map.get(key);
                        Method method = value.getMethod();
                        if (method != null) {
                            method.invoke(tNewInstance, cast(obj2, method.getGenericParameterTypes()[0], globalInstance));
                        } else {
                            Field field = value.getField();
                            field.set(tNewInstance, cast(obj2, field.getGenericType(), globalInstance));
                        }
                    }
                }
                return tNewInstance;
            } catch (Exception e) {
                e = e;
                throw new JSONException(e.getMessage(), e);
            }
        } catch (Exception e2) {
            e = e2;
        }
    }

    public static void addClassMapping(String className, Class<?> clazz) {
        if (className == null) {
            className = clazz.getName();
        }
        mappings.put(className, clazz);
    }

    public static void addBaseClassMappings() {
        mappings.put("byte", Byte.TYPE);
        mappings.put("short", Short.TYPE);
        mappings.put("int", Integer.TYPE);
        mappings.put("long", Long.TYPE);
        mappings.put("float", Float.TYPE);
        mappings.put("double", Double.TYPE);
        mappings.put("boolean", Boolean.TYPE);
        mappings.put("char", Character.TYPE);
        mappings.put("[byte", byte[].class);
        mappings.put("[short", short[].class);
        mappings.put("[int", int[].class);
        mappings.put("[long", long[].class);
        mappings.put("[float", float[].class);
        mappings.put("[double", double[].class);
        mappings.put("[boolean", boolean[].class);
        mappings.put("[char", char[].class);
        mappings.put(HashMap.class.getName(), HashMap.class);
    }

    public static void clearClassMapping() {
        mappings.clear();
        addBaseClassMappings();
    }

    public static Class<?> loadClass(String className) {
        if (className == null || className.length() == 0) {
            return null;
        }
        Class<?> clazz = mappings.get(className);
        if (clazz != null) {
            return clazz;
        }
        if (className.charAt(0) == '[') {
            Class<?> componentType = loadClass(className.substring(1));
            return Array.newInstance(componentType, 0).getClass();
        }
        if (className.startsWith("L") && className.endsWith(";")) {
            String newClassName = className.substring(1, className.length() - 1);
            return loadClass(newClassName);
        }
        try {
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            if (classLoader != null) {
                clazz = classLoader.loadClass(className);
                addClassMapping(className, clazz);
                return clazz;
            }
        } catch (Throwable th) {
        }
        try {
            clazz = Class.forName(className);
            addClassMapping(className, clazz);
            return clazz;
        } catch (Throwable th2) {
            return clazz;
        }
    }

    public static List<FieldInfo> computeGetters(Class<?> clazz, Map<String, String> aliasMap) {
        return computeGetters(clazz, aliasMap, true);
    }

    public static List<FieldInfo> computeGetters(Class<?> clazz, Map<String, String> aliasMap, boolean sorted) {
        int ordinal;
        int serialzeFeatures;
        String propertyName;
        JSONField annotation;
        Method[] arr$;
        int len$;
        int len$2;
        String propertyName2;
        int ordinal2;
        int serialzeFeatures2;
        JSONField fieldAnnotation;
        String propertyName3;
        int ordinal3;
        int serialzeFeatures3;
        String propertyName4;
        JSONField fieldAnnotation2;
        String propertyName5;
        Map<String, String> map = aliasMap;
        Map<String, FieldInfo> fieldInfoMap = new LinkedHashMap<>();
        Method[] arr$2 = clazz.getMethods();
        int i$ = 0;
        for (int len$3 = arr$2.length; i$ < len$3; len$3 = len$) {
            Method method = arr$2[i$];
            String methodName = method.getName();
            int ordinal4 = 0;
            int serialzeFeatures4 = 0;
            if (Modifier.isStatic(method.getModifiers())) {
                arr$ = arr$2;
                len$ = len$3;
            } else if (method.getReturnType().equals(Void.TYPE)) {
                arr$ = arr$2;
                len$ = len$3;
            } else if (method.getParameterTypes().length != 0) {
                arr$ = arr$2;
                len$ = len$3;
            } else if (method.getReturnType() == ClassLoader.class) {
                arr$ = arr$2;
                len$ = len$3;
            } else if (method.getName().equals("getMetaClass") && method.getReturnType().getName().equals("groovy.lang.MetaClass")) {
                arr$ = arr$2;
                len$ = len$3;
            } else {
                JSONField annotation2 = (JSONField) method.getAnnotation(JSONField.class);
                if (annotation2 != null) {
                    annotation = annotation2;
                } else {
                    annotation = getSupperMethodAnnotation(clazz, method);
                }
                if (annotation == null) {
                    arr$ = arr$2;
                } else if (!annotation.serialize()) {
                    arr$ = arr$2;
                    len$ = len$3;
                } else {
                    int ordinal5 = annotation.ordinal();
                    int serialzeFeatures5 = SerializerFeature.of(annotation.serialzeFeatures());
                    if (annotation.name().length() == 0) {
                        arr$ = arr$2;
                        ordinal4 = ordinal5;
                        serialzeFeatures4 = serialzeFeatures5;
                    } else {
                        String propertyName6 = annotation.name();
                        if (map == null) {
                            propertyName5 = propertyName6;
                        } else {
                            String propertyName7 = map.get(propertyName6);
                            if (propertyName7 != null) {
                                propertyName5 = propertyName7;
                            } else {
                                arr$ = arr$2;
                                len$ = len$3;
                            }
                        }
                        arr$ = arr$2;
                        fieldInfoMap.put(propertyName5, new FieldInfo(propertyName5, method, (Field) null, ordinal5, serialzeFeatures5));
                        len$ = len$3;
                    }
                }
                if (!methodName.startsWith("get")) {
                    len$ = len$3;
                    len$2 = 3;
                } else if (methodName.length() < 4) {
                    len$ = len$3;
                } else if (methodName.equals("getClass")) {
                    len$ = len$3;
                } else {
                    char c3 = methodName.charAt(3);
                    if (Character.isUpperCase(c3)) {
                        propertyName3 = compatibleWithJavaBean ? decapitalize(methodName.substring(3)) : Character.toLowerCase(methodName.charAt(3)) + methodName.substring(4);
                    } else if (c3 == '_') {
                        propertyName3 = methodName.substring(4);
                    } else if (c3 == 'f') {
                        propertyName3 = methodName.substring(3);
                    } else if (methodName.length() < 5 || !Character.isUpperCase(methodName.charAt(4))) {
                        len$ = len$3;
                    } else {
                        propertyName3 = decapitalize(methodName.substring(3));
                    }
                    boolean ignore = isJSONTypeIgnore(clazz, propertyName3);
                    if (ignore) {
                        len$ = len$3;
                    } else {
                        Field field = ParserConfig.getField(clazz, propertyName3);
                        if (field != null && (fieldAnnotation2 = (JSONField) field.getAnnotation(JSONField.class)) != null) {
                            if (!fieldAnnotation2.serialize()) {
                                len$ = len$3;
                            } else {
                                int ordinal6 = fieldAnnotation2.ordinal();
                                int serialzeFeatures6 = SerializerFeature.of(fieldAnnotation2.serialzeFeatures());
                                if (fieldAnnotation2.name().length() == 0) {
                                    ordinal3 = ordinal6;
                                    serialzeFeatures3 = serialzeFeatures6;
                                } else {
                                    propertyName3 = fieldAnnotation2.name();
                                    if (map == null || (propertyName3 = map.get(propertyName3)) != null) {
                                        ordinal3 = ordinal6;
                                        serialzeFeatures3 = serialzeFeatures6;
                                    } else {
                                        len$ = len$3;
                                    }
                                }
                            }
                        } else {
                            ordinal3 = ordinal4;
                            serialzeFeatures3 = serialzeFeatures4;
                        }
                        if (map == null) {
                            propertyName4 = propertyName3;
                        } else {
                            String propertyName8 = map.get(propertyName3);
                            if (propertyName8 != null) {
                                propertyName4 = propertyName8;
                            } else {
                                len$ = len$3;
                            }
                        }
                        len$ = len$3;
                        len$2 = 3;
                        fieldInfoMap.put(propertyName4, new FieldInfo(propertyName4, method, field, ordinal3, serialzeFeatures3));
                        ordinal4 = ordinal3;
                        serialzeFeatures4 = serialzeFeatures3;
                    }
                }
                if (methodName.startsWith("is") && methodName.length() >= len$2) {
                    char c2 = methodName.charAt(2);
                    if (Character.isUpperCase(c2)) {
                        propertyName2 = compatibleWithJavaBean ? decapitalize(methodName.substring(2)) : Character.toLowerCase(methodName.charAt(2)) + methodName.substring(len$2);
                    } else if (c2 == '_') {
                        propertyName2 = methodName.substring(len$2);
                    } else if (c2 == 'f') {
                        propertyName2 = methodName.substring(2);
                    }
                    Field field2 = ParserConfig.getField(clazz, propertyName2);
                    if (field2 == null) {
                        field2 = ParserConfig.getField(clazz, methodName);
                    }
                    if (field2 != null && (fieldAnnotation = (JSONField) field2.getAnnotation(JSONField.class)) != null) {
                        if (fieldAnnotation.serialize()) {
                            int ordinal7 = fieldAnnotation.ordinal();
                            int serialzeFeatures7 = SerializerFeature.of(fieldAnnotation.serialzeFeatures());
                            if (fieldAnnotation.name().length() == 0) {
                                ordinal2 = ordinal7;
                                serialzeFeatures2 = serialzeFeatures7;
                            } else {
                                propertyName2 = fieldAnnotation.name();
                                if (map == null || (propertyName2 = map.get(propertyName2)) != null) {
                                    ordinal2 = ordinal7;
                                    serialzeFeatures2 = serialzeFeatures7;
                                }
                            }
                        }
                    } else {
                        ordinal2 = ordinal4;
                        serialzeFeatures2 = serialzeFeatures4;
                    }
                    if (map == null || (propertyName2 = map.get(propertyName2)) != null) {
                        fieldInfoMap.put(propertyName2, new FieldInfo(propertyName2, method, field2, ordinal2, serialzeFeatures2));
                    }
                }
            }
            i$++;
            arr$2 = arr$;
        }
        Field[] arr$3 = clazz.getFields();
        int len$4 = arr$3.length;
        int i$2 = 0;
        while (i$2 < len$4) {
            Field field3 = arr$3[i$2];
            if (!Modifier.isStatic(field3.getModifiers())) {
                JSONField fieldAnnotation3 = (JSONField) field3.getAnnotation(JSONField.class);
                String propertyName9 = field3.getName();
                if (fieldAnnotation3 == null) {
                    ordinal = 0;
                    serialzeFeatures = 0;
                } else if (fieldAnnotation3.serialize()) {
                    int ordinal8 = fieldAnnotation3.ordinal();
                    int serialzeFeatures8 = SerializerFeature.of(fieldAnnotation3.serialzeFeatures());
                    if (fieldAnnotation3.name().length() == 0) {
                        ordinal = ordinal8;
                        serialzeFeatures = serialzeFeatures8;
                    } else {
                        propertyName9 = fieldAnnotation3.name();
                        ordinal = ordinal8;
                        serialzeFeatures = serialzeFeatures8;
                    }
                }
                if (map == null) {
                    propertyName = propertyName9;
                } else {
                    String propertyName10 = map.get(propertyName9);
                    if (propertyName10 != null) {
                        propertyName = propertyName10;
                    }
                }
                if (!fieldInfoMap.containsKey(propertyName)) {
                    fieldInfoMap.put(propertyName, new FieldInfo(propertyName, (Method) null, field3, ordinal, serialzeFeatures));
                }
            }
            i$2++;
            map = aliasMap;
        }
        List<FieldInfo> fieldInfoList = new ArrayList<>();
        boolean containsAll = false;
        String[] orders = null;
        JSONType annotation3 = (JSONType) clazz.getAnnotation(JSONType.class);
        if (annotation3 != null) {
            orders = annotation3.orders();
            if (orders != null && orders.length == fieldInfoMap.size()) {
                containsAll = true;
                int len$5 = orders.length;
                int i$3 = 0;
                while (true) {
                    if (i$3 >= len$5) {
                        break;
                    }
                    String item = orders[i$3];
                    if (fieldInfoMap.containsKey(item)) {
                        i$3++;
                    } else {
                        containsAll = false;
                        break;
                    }
                }
            } else {
                containsAll = false;
            }
        }
        if (containsAll) {
            String[] arr$4 = orders;
            for (String item2 : arr$4) {
                FieldInfo fieldInfo = fieldInfoMap.get(item2);
                fieldInfoList.add(fieldInfo);
            }
        } else {
            for (FieldInfo fieldInfo2 : fieldInfoMap.values()) {
                fieldInfoList.add(fieldInfo2);
            }
            if (sorted) {
                Collections.sort(fieldInfoList);
            }
        }
        return fieldInfoList;
    }

    public static JSONField getSupperMethodAnnotation(Class<?> clazz, Method method) {
        JSONField annotation;
        for (Class<?> interfaceClass : clazz.getInterfaces()) {
            Method[] arr$ = interfaceClass.getMethods();
            for (Method interfaceMethod : arr$) {
                if (interfaceMethod.getName().equals(method.getName()) && interfaceMethod.getParameterTypes().length == method.getParameterTypes().length) {
                    boolean match = true;
                    int i = 0;
                    while (true) {
                        if (i >= interfaceMethod.getParameterTypes().length) {
                            break;
                        }
                        if (interfaceMethod.getParameterTypes()[i].equals(method.getParameterTypes()[i])) {
                            i++;
                        } else {
                            match = false;
                            break;
                        }
                    }
                    if (match && (annotation = (JSONField) interfaceMethod.getAnnotation(JSONField.class)) != null) {
                        return annotation;
                    }
                }
            }
        }
        return null;
    }

    private static boolean isJSONTypeIgnore(Class<?> clazz, String propertyName) {
        JSONType jsonType = (JSONType) clazz.getAnnotation(JSONType.class);
        if (jsonType != null && jsonType.ignores() != null) {
            String[] arr$ = jsonType.ignores();
            for (String item : arr$) {
                if (propertyName.equalsIgnoreCase(item)) {
                    return true;
                }
            }
        }
        if (clazz.getSuperclass() != Object.class && clazz.getSuperclass() != null && isJSONTypeIgnore(clazz.getSuperclass(), propertyName)) {
            return true;
        }
        return false;
    }

    public static boolean isGenericParamType(Type type) {
        if (type instanceof ParameterizedType) {
            return true;
        }
        if (type instanceof Class) {
            return isGenericParamType(((Class) type).getGenericSuperclass());
        }
        return false;
    }

    public static Type getGenericParamType(Type type) {
        if (!(type instanceof ParameterizedType) && (type instanceof Class)) {
            return getGenericParamType(((Class) type).getGenericSuperclass());
        }
        return type;
    }

    public static Type unwrap(Type type) {
        if (type instanceof GenericArrayType) {
            Type componentType = ((GenericArrayType) type).getGenericComponentType();
            if (componentType == Byte.TYPE) {
                return byte[].class;
            }
            if (componentType == Character.TYPE) {
                return char[].class;
            }
        }
        return type;
    }

    public static Class<?> getClass(Type type) {
        if (type.getClass() == Class.class) {
            return (Class) type;
        }
        if (type instanceof ParameterizedType) {
            return getClass(((ParameterizedType) type).getRawType());
        }
        return Object.class;
    }

    public static Field getField(Class<?> clazz, String fieldName) {
        Field[] arr$ = clazz.getDeclaredFields();
        for (Field field : arr$) {
            if (fieldName.equals(field.getName())) {
                return field;
            }
        }
        Class<?> superClass = clazz.getSuperclass();
        if (superClass != null && superClass != Object.class) {
            return getField(superClass, fieldName);
        }
        return null;
    }

    public static int getSerializeFeatures(Class<?> clazz) {
        JSONType annotation = (JSONType) clazz.getAnnotation(JSONType.class);
        if (annotation == null) {
            return 0;
        }
        return SerializerFeature.of(annotation.serialzeFeatures());
    }

    public static int getParserFeatures(Class<?> clazz) {
        JSONType annotation = (JSONType) clazz.getAnnotation(JSONType.class);
        if (annotation == null) {
            return 0;
        }
        return Feature.of(annotation.parseFeatures());
    }

    public static String decapitalize(String name) {
        if (name == null || name.length() == 0) {
            return name;
        }
        if (name.length() > 1 && Character.isUpperCase(name.charAt(1)) && Character.isUpperCase(name.charAt(0))) {
            return name;
        }
        char[] chars = name.toCharArray();
        chars[0] = Character.toLowerCase(chars[0]);
        return new String(chars);
    }

    static void setAccessible(AccessibleObject obj) {
        if (!setAccessibleEnable || obj.isAccessible()) {
            return;
        }
        try {
            obj.setAccessible(true);
        } catch (AccessControlException e) {
            setAccessibleEnable = false;
        }
    }
}
