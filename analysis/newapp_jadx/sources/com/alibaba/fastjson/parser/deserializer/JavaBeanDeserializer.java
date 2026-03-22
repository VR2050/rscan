package com.alibaba.fastjson.parser.deserializer;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.JSONLexer;
import com.alibaba.fastjson.parser.JSONLexerBase;
import com.alibaba.fastjson.parser.ParseContext;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.util.FieldInfo;
import com.alibaba.fastjson.util.JavaBeanInfo;
import com.alibaba.fastjson.util.TypeUtils;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class JavaBeanDeserializer implements ObjectDeserializer {
    private final Map<String, FieldDeserializer> alterNameFieldDeserializers;
    public final JavaBeanInfo beanInfo;
    public final Class<?> clazz;
    private ConcurrentMap<String, Object> extraFieldDeserializers;
    private Map<String, FieldDeserializer> fieldDeserializerMap;
    private final FieldDeserializer[] fieldDeserializers;
    private transient long[] hashArray;
    private transient short[] hashArrayMapping;
    private transient long[] smartMatchHashArray;
    private transient short[] smartMatchHashArrayMapping;
    public final FieldDeserializer[] sortedFieldDeserializers;

    public JavaBeanDeserializer(ParserConfig parserConfig, Class<?> cls) {
        this(parserConfig, cls, cls);
    }

    private Object createFactoryInstance(ParserConfig parserConfig, Object obj) {
        return this.beanInfo.factoryMethod.invoke(null, obj);
    }

    public static JavaBeanDeserializer getSeeAlso(ParserConfig parserConfig, JavaBeanInfo javaBeanInfo, String str) {
        JSONType jSONType = javaBeanInfo.jsonType;
        if (jSONType == null) {
            return null;
        }
        for (Class<?> cls : jSONType.seeAlso()) {
            ObjectDeserializer deserializer = parserConfig.getDeserializer(cls);
            if (deserializer instanceof JavaBeanDeserializer) {
                JavaBeanDeserializer javaBeanDeserializer = (JavaBeanDeserializer) deserializer;
                JavaBeanInfo javaBeanInfo2 = javaBeanDeserializer.beanInfo;
                if (javaBeanInfo2.typeName.equals(str)) {
                    return javaBeanDeserializer;
                }
                JavaBeanDeserializer seeAlso = getSeeAlso(parserConfig, javaBeanInfo2, str);
                if (seeAlso != null) {
                    return seeAlso;
                }
            }
        }
        return null;
    }

    public static boolean isSetFlag(int i2, int[] iArr) {
        if (iArr == null) {
            return false;
        }
        int i3 = i2 / 32;
        int i4 = i2 % 32;
        if (i3 < iArr.length) {
            if (((1 << i4) & iArr[i3]) != 0) {
                return true;
            }
        }
        return false;
    }

    public static void parseArray(Collection collection, ObjectDeserializer objectDeserializer, DefaultJSONParser defaultJSONParser, Type type, Object obj) {
        JSONLexerBase jSONLexerBase = (JSONLexerBase) defaultJSONParser.lexer;
        int i2 = jSONLexerBase.token();
        if (i2 == 8) {
            jSONLexerBase.nextToken(16);
            jSONLexerBase.token();
            return;
        }
        if (i2 != 14) {
            defaultJSONParser.throwException(i2);
        }
        if (jSONLexerBase.getCurrent() == '[') {
            jSONLexerBase.next();
            jSONLexerBase.setToken(14);
        } else {
            jSONLexerBase.nextToken(14);
        }
        if (jSONLexerBase.token() == 15) {
            jSONLexerBase.nextToken();
            return;
        }
        int i3 = 0;
        while (true) {
            collection.add(objectDeserializer.deserialze(defaultJSONParser, type, Integer.valueOf(i3)));
            i3++;
            if (jSONLexerBase.token() != 16) {
                break;
            }
            if (jSONLexerBase.getCurrent() == '[') {
                jSONLexerBase.next();
                jSONLexerBase.setToken(14);
            } else {
                jSONLexerBase.nextToken(14);
            }
        }
        int i4 = jSONLexerBase.token();
        if (i4 != 15) {
            defaultJSONParser.throwException(i4);
        }
        if (jSONLexerBase.getCurrent() != ',') {
            jSONLexerBase.nextToken(16);
        } else {
            jSONLexerBase.next();
            jSONLexerBase.setToken(16);
        }
    }

    public void check(JSONLexer jSONLexer, int i2) {
        if (jSONLexer.token() != i2) {
            throw new JSONException("syntax error");
        }
    }

    public Object createInstance(DefaultJSONParser defaultJSONParser, Type type) {
        Object newInstance;
        if ((type instanceof Class) && this.clazz.isInterface()) {
            return Proxy.newProxyInstance(Thread.currentThread().getContextClassLoader(), new Class[]{(Class) type}, new JSONObject());
        }
        JavaBeanInfo javaBeanInfo = this.beanInfo;
        Constructor<?> constructor = javaBeanInfo.defaultConstructor;
        Object obj = null;
        if (constructor == null && javaBeanInfo.factoryMethod == null) {
            return null;
        }
        Method method = javaBeanInfo.factoryMethod;
        if (method != null && javaBeanInfo.defaultConstructorParameterSize > 0) {
            return null;
        }
        try {
            if (javaBeanInfo.defaultConstructorParameterSize == 0) {
                newInstance = constructor != null ? constructor.newInstance(new Object[0]) : method.invoke(null, new Object[0]);
            } else {
                ParseContext context = defaultJSONParser.getContext();
                if (context == null || context.object == null) {
                    throw new JSONException("can't create non-static inner class instance.");
                }
                if (!(type instanceof Class)) {
                    throw new JSONException("can't create non-static inner class instance.");
                }
                String name = ((Class) type).getName();
                String substring = name.substring(0, name.lastIndexOf(36));
                Object obj2 = context.object;
                String name2 = obj2.getClass().getName();
                if (!name2.equals(substring)) {
                    ParseContext parseContext = context.parent;
                    if (parseContext == null || parseContext.object == null || !("java.util.ArrayList".equals(name2) || "java.util.List".equals(name2) || "java.util.Collection".equals(name2) || "java.util.Map".equals(name2) || "java.util.HashMap".equals(name2))) {
                        obj = obj2;
                    } else if (parseContext.object.getClass().getName().equals(substring)) {
                        obj = parseContext.object;
                    }
                    obj2 = obj;
                }
                if (obj2 == null || ((obj2 instanceof Collection) && ((Collection) obj2).isEmpty())) {
                    throw new JSONException("can't create non-static inner class instance.");
                }
                newInstance = constructor.newInstance(obj2);
            }
            if (defaultJSONParser != null && defaultJSONParser.lexer.isEnabled(Feature.InitStringFieldAsEmpty)) {
                for (FieldInfo fieldInfo : this.beanInfo.fields) {
                    if (fieldInfo.fieldClass == String.class) {
                        try {
                            fieldInfo.set(newInstance, "");
                        } catch (Exception e2) {
                            throw new JSONException(C1499a.m623j(this.clazz, C1499a.m586H("create instance error, class ")), e2);
                        }
                    }
                }
            }
            return newInstance;
        } catch (JSONException e3) {
            throw e3;
        } catch (Exception e4) {
            throw new JSONException(C1499a.m623j(this.clazz, C1499a.m586H("create instance error, class ")), e4);
        }
    }

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public <T> T deserialze(DefaultJSONParser defaultJSONParser, Type type, Object obj) {
        return (T) deserialze(defaultJSONParser, type, obj, 0);
    }

    public <T> T deserialzeArrayMapping(DefaultJSONParser defaultJSONParser, Type type, Object obj, Object obj2) {
        JSONLexer jSONLexer = defaultJSONParser.lexer;
        if (jSONLexer.token() != 14) {
            throw new JSONException("error");
        }
        String scanTypeName = jSONLexer.scanTypeName(defaultJSONParser.symbolTable);
        if (scanTypeName != null) {
            ObjectDeserializer seeAlso = getSeeAlso(defaultJSONParser.getConfig(), this.beanInfo, scanTypeName);
            if (seeAlso == null) {
                seeAlso = defaultJSONParser.getConfig().getDeserializer(defaultJSONParser.getConfig().checkAutoType(scanTypeName, TypeUtils.getClass(type), jSONLexer.getFeatures()));
            }
            if (seeAlso instanceof JavaBeanDeserializer) {
                return (T) ((JavaBeanDeserializer) seeAlso).deserialzeArrayMapping(defaultJSONParser, type, obj, obj2);
            }
        }
        T t = (T) createInstance(defaultJSONParser, type);
        int i2 = 0;
        int length = this.sortedFieldDeserializers.length;
        while (true) {
            if (i2 >= length) {
                break;
            }
            char c2 = i2 == length + (-1) ? ']' : ',';
            FieldDeserializer fieldDeserializer = this.sortedFieldDeserializers[i2];
            Class<?> cls = fieldDeserializer.fieldInfo.fieldClass;
            if (cls == Integer.TYPE) {
                fieldDeserializer.setValue((Object) t, jSONLexer.scanInt(c2));
            } else if (cls == String.class) {
                fieldDeserializer.setValue((Object) t, jSONLexer.scanString(c2));
            } else if (cls == Long.TYPE) {
                fieldDeserializer.setValue(t, jSONLexer.scanLong(c2));
            } else if (cls.isEnum()) {
                char current = jSONLexer.getCurrent();
                fieldDeserializer.setValue(t, (current == '\"' || current == 'n') ? jSONLexer.scanEnum(cls, defaultJSONParser.getSymbolTable(), c2) : (current < '0' || current > '9') ? scanEnum(jSONLexer, c2) : ((EnumDeserializer) ((DefaultFieldDeserializer) fieldDeserializer).getFieldValueDeserilizer(defaultJSONParser.getConfig())).valueOf(jSONLexer.scanInt(c2)));
            } else if (cls == Boolean.TYPE) {
                fieldDeserializer.setValue(t, jSONLexer.scanBoolean(c2));
            } else if (cls == Float.TYPE) {
                fieldDeserializer.setValue(t, Float.valueOf(jSONLexer.scanFloat(c2)));
            } else if (cls == Double.TYPE) {
                fieldDeserializer.setValue(t, Double.valueOf(jSONLexer.scanDouble(c2)));
            } else if (cls == Date.class && jSONLexer.getCurrent() == '1') {
                fieldDeserializer.setValue(t, new Date(jSONLexer.scanLong(c2)));
            } else if (cls == BigDecimal.class) {
                fieldDeserializer.setValue(t, jSONLexer.scanDecimal(c2));
            } else {
                jSONLexer.nextToken(14);
                FieldInfo fieldInfo = fieldDeserializer.fieldInfo;
                fieldDeserializer.setValue(t, defaultJSONParser.parseObject(fieldInfo.fieldType, fieldInfo.name));
                if (jSONLexer.token() == 15) {
                    break;
                }
                check(jSONLexer, c2 == ']' ? 15 : 16);
            }
            i2++;
        }
        jSONLexer.nextToken(16);
        return t;
    }

    @Override // com.alibaba.fastjson.parser.deserializer.ObjectDeserializer
    public int getFastMatchToken() {
        return 12;
    }

    public FieldDeserializer getFieldDeserializer(String str) {
        return getFieldDeserializer(str, null);
    }

    public Type getFieldType(int i2) {
        return this.sortedFieldDeserializers[i2].fieldInfo.fieldType;
    }

    public boolean parseField(DefaultJSONParser defaultJSONParser, String str, Object obj, Type type, Map<String, Object> map) {
        return parseField(defaultJSONParser, str, obj, type, map, null);
    }

    public Object parseRest(DefaultJSONParser defaultJSONParser, Type type, Object obj, Object obj2, int i2) {
        return parseRest(defaultJSONParser, type, obj, obj2, i2, new int[0]);
    }

    public Enum<?> scanEnum(JSONLexer jSONLexer, char c2) {
        StringBuilder m586H = C1499a.m586H("illegal enum. ");
        m586H.append(jSONLexer.info());
        throw new JSONException(m586H.toString());
    }

    public FieldDeserializer smartMatch(String str) {
        return smartMatch(str, null);
    }

    public JavaBeanDeserializer(ParserConfig parserConfig, Class<?> cls, Type type) {
        this(parserConfig, JavaBeanInfo.build(cls, type, parserConfig.propertyNamingStrategy, parserConfig.fieldBased, parserConfig.compatibleWithJavaBean, parserConfig.isJacksonCompatible()));
    }

    public <T> T deserialze(DefaultJSONParser defaultJSONParser, Type type, Object obj, int i2) {
        return (T) deserialze(defaultJSONParser, type, obj, null, i2, null);
    }

    public FieldDeserializer getFieldDeserializer(String str, int[] iArr) {
        FieldDeserializer fieldDeserializer;
        if (str == null) {
            return null;
        }
        Map<String, FieldDeserializer> map = this.fieldDeserializerMap;
        if (map != null && (fieldDeserializer = map.get(str)) != null) {
            return fieldDeserializer;
        }
        int i2 = 0;
        int length = this.sortedFieldDeserializers.length - 1;
        while (i2 <= length) {
            int i3 = (i2 + length) >>> 1;
            int compareTo = this.sortedFieldDeserializers[i3].fieldInfo.name.compareTo(str);
            if (compareTo < 0) {
                i2 = i3 + 1;
            } else {
                if (compareTo <= 0) {
                    if (isSetFlag(i3, iArr)) {
                        return null;
                    }
                    return this.sortedFieldDeserializers[i3];
                }
                length = i3 - 1;
            }
        }
        Map<String, FieldDeserializer> map2 = this.alterNameFieldDeserializers;
        if (map2 != null) {
            return map2.get(str);
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:116:0x020a  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0120  */
    /* JADX WARN: Type inference failed for: r3v14 */
    /* JADX WARN: Type inference failed for: r3v15 */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v5, types: [boolean, int] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean parseField(com.alibaba.fastjson.parser.DefaultJSONParser r22, java.lang.String r23, java.lang.Object r24, java.lang.reflect.Type r25, java.util.Map<java.lang.String, java.lang.Object> r26, int[] r27) {
        /*
            Method dump skipped, instructions count: 587
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.parseField(com.alibaba.fastjson.parser.DefaultJSONParser, java.lang.String, java.lang.Object, java.lang.reflect.Type, java.util.Map, int[]):boolean");
    }

    public Object parseRest(DefaultJSONParser defaultJSONParser, Type type, Object obj, Object obj2, int i2, int[] iArr) {
        return deserialze(defaultJSONParser, type, obj, obj2, i2, iArr);
    }

    public Enum scanEnum(JSONLexerBase jSONLexerBase, char[] cArr, ObjectDeserializer objectDeserializer) {
        EnumDeserializer enumDeserializer = objectDeserializer instanceof EnumDeserializer ? (EnumDeserializer) objectDeserializer : null;
        if (enumDeserializer == null) {
            jSONLexerBase.matchStat = -1;
            return null;
        }
        long scanEnumSymbol = jSONLexerBase.scanEnumSymbol(cArr);
        if (jSONLexerBase.matchStat <= 0) {
            return null;
        }
        Enum enumByHashCode = enumDeserializer.getEnumByHashCode(scanEnumSymbol);
        if (enumByHashCode == null) {
            if (scanEnumSymbol == -3750763034362895579L) {
                return null;
            }
            if (jSONLexerBase.isEnabled(Feature.ErrorOnEnumNotMatch)) {
                StringBuilder m586H = C1499a.m586H("not match enum value, ");
                m586H.append(enumDeserializer.enumClass);
                throw new JSONException(m586H.toString());
            }
        }
        return enumByHashCode;
    }

    public FieldDeserializer smartMatch(String str, int[] iArr) {
        boolean z;
        if (str == null) {
            return null;
        }
        FieldDeserializer fieldDeserializer = getFieldDeserializer(str, iArr);
        if (fieldDeserializer == null) {
            long fnv1a_64_lower = TypeUtils.fnv1a_64_lower(str);
            int i2 = 0;
            if (this.smartMatchHashArray == null) {
                long[] jArr = new long[this.sortedFieldDeserializers.length];
                int i3 = 0;
                while (true) {
                    FieldDeserializer[] fieldDeserializerArr = this.sortedFieldDeserializers;
                    if (i3 >= fieldDeserializerArr.length) {
                        break;
                    }
                    jArr[i3] = TypeUtils.fnv1a_64_lower(fieldDeserializerArr[i3].fieldInfo.name);
                    i3++;
                }
                Arrays.sort(jArr);
                this.smartMatchHashArray = jArr;
            }
            int binarySearch = Arrays.binarySearch(this.smartMatchHashArray, fnv1a_64_lower);
            if (binarySearch < 0) {
                z = str.startsWith("is");
                if (z) {
                    binarySearch = Arrays.binarySearch(this.smartMatchHashArray, TypeUtils.fnv1a_64_lower(str.substring(2)));
                }
            } else {
                z = false;
            }
            if (binarySearch >= 0) {
                if (this.smartMatchHashArrayMapping == null) {
                    short[] sArr = new short[this.smartMatchHashArray.length];
                    Arrays.fill(sArr, (short) -1);
                    while (true) {
                        FieldDeserializer[] fieldDeserializerArr2 = this.sortedFieldDeserializers;
                        if (i2 >= fieldDeserializerArr2.length) {
                            break;
                        }
                        int binarySearch2 = Arrays.binarySearch(this.smartMatchHashArray, TypeUtils.fnv1a_64_lower(fieldDeserializerArr2[i2].fieldInfo.name));
                        if (binarySearch2 >= 0) {
                            sArr[binarySearch2] = (short) i2;
                        }
                        i2++;
                    }
                    this.smartMatchHashArrayMapping = sArr;
                }
                short s = this.smartMatchHashArrayMapping[binarySearch];
                if (s != -1 && !isSetFlag(s, iArr)) {
                    fieldDeserializer = this.sortedFieldDeserializers[s];
                }
            }
            if (fieldDeserializer != null) {
                FieldInfo fieldInfo = fieldDeserializer.fieldInfo;
                if ((fieldInfo.parserFeatures & Feature.DisableFieldSmartMatch.mask) != 0) {
                    return null;
                }
                Class<?> cls = fieldInfo.fieldClass;
                if (z && cls != Boolean.TYPE && cls != Boolean.class) {
                    return null;
                }
            }
        }
        return fieldDeserializer;
    }

    /* JADX WARN: Code restructure failed: missing block: B:157:0x03b1, code lost:
    
        if (r13.isEnabled(com.alibaba.fastjson.parser.Feature.AllowArbitraryCommas) != false) goto L309;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x04cb, code lost:
    
        r12 = r27;
        r1 = getSeeAlso(r12, r32.beanInfo, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x04d3, code lost:
    
        if (r1 != null) goto L379;
     */
    /* JADX WARN: Code restructure failed: missing block: B:234:0x04d5, code lost:
    
        r7 = r12.checkAutoType(r0, com.alibaba.fastjson.util.TypeUtils.getClass(r34), r13.getFeatures());
        r1 = r33.getConfig().getDeserializer(r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:235:0x04eb, code lost:
    
        r2 = (T) r1.deserialze(r33, r7, r35);
     */
    /* JADX WARN: Code restructure failed: missing block: B:236:0x04f1, code lost:
    
        if ((r1 instanceof com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer) == false) goto L387;
     */
    /* JADX WARN: Code restructure failed: missing block: B:237:0x04f3, code lost:
    
        r1 = (com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer) r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:238:0x04f5, code lost:
    
        if (r5 == null) goto L387;
     */
    /* JADX WARN: Code restructure failed: missing block: B:239:0x04f7, code lost:
    
        r1 = r1.getFieldDeserializer(r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:240:0x04fb, code lost:
    
        if (r1 == null) goto L387;
     */
    /* JADX WARN: Code restructure failed: missing block: B:241:0x04fd, code lost:
    
        r1.setValue((java.lang.Object) r2, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:242:0x0500, code lost:
    
        if (r4 == null) goto L389;
     */
    /* JADX WARN: Code restructure failed: missing block: B:243:0x0502, code lost:
    
        r4.object = r26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:244:0x0506, code lost:
    
        r33.setContext(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:245:0x0509, code lost:
    
        return r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:247:0x04ea, code lost:
    
        r7 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:254:0x0519, code lost:
    
        r7 = r4;
        r11 = r6;
        r0 = r19;
        r1 = r1;
        r15 = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:516:0x0902, code lost:
    
        throw new com.alibaba.fastjson.JSONException("syntax error, unexpect token " + com.alibaba.fastjson.parser.JSONToken.name(r13.token()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:730:0x0358, code lost:
    
        if (r3 == (-2)) goto L290;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:147:0x0388  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0072 A[Catch: all -> 0x004d, TRY_LEAVE, TryCatch #4 {all -> 0x004d, blocks: (B:17:0x003d, B:19:0x0042, B:25:0x0057, B:27:0x0062, B:29:0x0068, B:34:0x0072, B:41:0x0081, B:94:0x0097, B:48:0x00e3, B:50:0x00e9, B:55:0x00f0, B:59:0x00f9, B:65:0x0111, B:69:0x0121, B:70:0x012a, B:71:0x012b, B:73:0x014c, B:74:0x0154, B:75:0x0167, B:120:0x016e), top: B:15:0x003b, inners: #7 }] */
    /* JADX WARN: Removed duplicated region for block: B:368:0x0809 A[Catch: all -> 0x0678, TRY_ENTER, TryCatch #15 {all -> 0x0678, blocks: (B:278:0x0673, B:368:0x0809, B:369:0x0811, B:371:0x0817, B:374:0x0829), top: B:274:0x066b }] */
    /* JADX WARN: Removed duplicated region for block: B:486:0x0565 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:498:0x05ac  */
    /* JADX WARN: Removed duplicated region for block: B:504:0x0658  */
    /* JADX WARN: Removed duplicated region for block: B:507:0x065c A[Catch: all -> 0x090b, TryCatch #1 {all -> 0x090b, blocks: (B:161:0x08cd, B:502:0x0650, B:507:0x065c, B:519:0x0662, B:510:0x08b9, B:512:0x08c1, B:515:0x08e4, B:516:0x0902, B:548:0x062f, B:550:0x0635, B:554:0x063b, B:555:0x0648, B:558:0x0903, B:559:0x090a), top: B:160:0x08cd }] */
    /* JADX WARN: Removed duplicated region for block: B:544:0x0602  */
    /* JADX WARN: Removed duplicated region for block: B:576:0x0556  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x091c  */
    /* JADX WARN: Type inference failed for: r15v41, types: [int] */
    /* JADX WARN: Type inference failed for: r15v5 */
    /* JADX WARN: Type inference failed for: r15v56 */
    /* JADX WARN: Type inference failed for: r15v6, types: [int] */
    /* JADX WARN: Type inference failed for: r1v154 */
    /* JADX WARN: Type inference failed for: r1v61 */
    /* JADX WARN: Type inference failed for: r1v68 */
    /* JADX WARN: Type inference failed for: r33v0, types: [com.alibaba.fastjson.parser.DefaultJSONParser] */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v17, types: [com.alibaba.fastjson.parser.ParseContext] */
    /* JADX WARN: Type inference failed for: r7v2, types: [com.alibaba.fastjson.parser.ParseContext] */
    /* JADX WARN: Type inference failed for: r7v20 */
    /* JADX WARN: Type inference failed for: r7v24 */
    /* JADX WARN: Type inference failed for: r7v27 */
    /* JADX WARN: Type inference failed for: r7v3 */
    /* JADX WARN: Type inference failed for: r7v34 */
    /* JADX WARN: Type inference failed for: r7v35 */
    /* JADX WARN: Type inference failed for: r7v5 */
    /* JADX WARN: Type inference failed for: r7v8 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public <T> T deserialze(com.alibaba.fastjson.parser.DefaultJSONParser r33, java.lang.reflect.Type r34, java.lang.Object r35, java.lang.Object r36, int r37, int[] r38) {
        /*
            Method dump skipped, instructions count: 2343
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.deserialze(com.alibaba.fastjson.parser.DefaultJSONParser, java.lang.reflect.Type, java.lang.Object, java.lang.Object, int, int[]):java.lang.Object");
    }

    public JavaBeanDeserializer(ParserConfig parserConfig, JavaBeanInfo javaBeanInfo) {
        this.clazz = javaBeanInfo.clazz;
        this.beanInfo = javaBeanInfo;
        FieldInfo[] fieldInfoArr = javaBeanInfo.sortedFields;
        this.sortedFieldDeserializers = new FieldDeserializer[fieldInfoArr.length];
        int length = fieldInfoArr.length;
        HashMap hashMap = null;
        for (int i2 = 0; i2 < length; i2++) {
            FieldInfo fieldInfo = javaBeanInfo.sortedFields[i2];
            FieldDeserializer createFieldDeserializer = parserConfig.createFieldDeserializer(parserConfig, javaBeanInfo, fieldInfo);
            this.sortedFieldDeserializers[i2] = createFieldDeserializer;
            if (length > 128) {
                if (this.fieldDeserializerMap == null) {
                    this.fieldDeserializerMap = new HashMap();
                }
                this.fieldDeserializerMap.put(fieldInfo.name, createFieldDeserializer);
            }
            for (String str : fieldInfo.alternateNames) {
                if (hashMap == null) {
                    hashMap = new HashMap();
                }
                hashMap.put(str, createFieldDeserializer);
            }
        }
        this.alterNameFieldDeserializers = hashMap;
        FieldInfo[] fieldInfoArr2 = javaBeanInfo.fields;
        this.fieldDeserializers = new FieldDeserializer[fieldInfoArr2.length];
        int length2 = fieldInfoArr2.length;
        for (int i3 = 0; i3 < length2; i3++) {
            this.fieldDeserializers[i3] = getFieldDeserializer(javaBeanInfo.fields[i3].name);
        }
    }

    public FieldDeserializer getFieldDeserializer(long j2) {
        int i2 = 0;
        if (this.hashArray == null) {
            long[] jArr = new long[this.sortedFieldDeserializers.length];
            int i3 = 0;
            while (true) {
                FieldDeserializer[] fieldDeserializerArr = this.sortedFieldDeserializers;
                if (i3 >= fieldDeserializerArr.length) {
                    break;
                }
                jArr[i3] = TypeUtils.fnv1a_64(fieldDeserializerArr[i3].fieldInfo.name);
                i3++;
            }
            Arrays.sort(jArr);
            this.hashArray = jArr;
        }
        int binarySearch = Arrays.binarySearch(this.hashArray, j2);
        if (binarySearch < 0) {
            return null;
        }
        if (this.hashArrayMapping == null) {
            short[] sArr = new short[this.hashArray.length];
            Arrays.fill(sArr, (short) -1);
            while (true) {
                FieldDeserializer[] fieldDeserializerArr2 = this.sortedFieldDeserializers;
                if (i2 >= fieldDeserializerArr2.length) {
                    break;
                }
                int binarySearch2 = Arrays.binarySearch(this.hashArray, TypeUtils.fnv1a_64(fieldDeserializerArr2[i2].fieldInfo.name));
                if (binarySearch2 >= 0) {
                    sArr[binarySearch2] = (short) i2;
                }
                i2++;
            }
            this.hashArrayMapping = sArr;
        }
        short s = this.hashArrayMapping[binarySearch];
        if (s != -1) {
            return this.sortedFieldDeserializers[s];
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x009f, code lost:
    
        if ((r1 instanceof java.lang.Number) == false) goto L216;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x00a1, code lost:
    
        r7.setLong(r0, ((java.lang.Number) r1).longValue());
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x008d, code lost:
    
        if ((r1 instanceof java.lang.Number) == false) goto L212;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x008f, code lost:
    
        r7.setInt(r0, ((java.lang.Number) r1).intValue());
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0079, code lost:
    
        if (r1 != java.lang.Boolean.FALSE) goto L200;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0081, code lost:
    
        if (r1 != java.lang.Boolean.TRUE) goto L201;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x0083, code lost:
    
        r7.setBoolean(r0, true);
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x007b, code lost:
    
        r7.setBoolean(r0, false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:211:0x0236, code lost:
    
        if (r14[r13].fieldClass == java.lang.String.class) goto L152;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x006d, code lost:
    
        if (r6.method != null) goto L198;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x006f, code lost:
    
        r9 = r7.getType();
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x0075, code lost:
    
        if (r9 != java.lang.Boolean.TYPE) goto L199;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0089, code lost:
    
        if (r9 != java.lang.Integer.TYPE) goto L211;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x009b, code lost:
    
        if (r9 != java.lang.Long.TYPE) goto L215;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x00b0, code lost:
    
        if (r9 != java.lang.Float.TYPE) goto L219;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00dd, code lost:
    
        if (r9 != java.lang.Double.TYPE) goto L221;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0108, code lost:
    
        if (r1 == null) goto L225;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x010e, code lost:
    
        if (r8 != r1.getClass()) goto L226;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0110, code lost:
    
        r7.set(r0, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x00e1, code lost:
    
        if ((r1 instanceof java.lang.Number) == false) goto L224;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x00e3, code lost:
    
        r7.setDouble(r0, ((java.lang.Number) r1).doubleValue());
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x00f0, code lost:
    
        if ((r1 instanceof java.lang.String) == false) goto L222;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x00f2, code lost:
    
        r1 = (java.lang.String) r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x00f8, code lost:
    
        if (r1.length() > 10) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x00fa, code lost:
    
        r5 = com.alibaba.fastjson.util.TypeUtils.parseDouble(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0103, code lost:
    
        r7.setDouble(r0, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x00ff, code lost:
    
        r5 = java.lang.Double.parseDouble(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x00b4, code lost:
    
        if ((r1 instanceof java.lang.Number) == false) goto L220;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x00b6, code lost:
    
        r7.setFloat(r0, ((java.lang.Number) r1).floatValue());
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x00c3, code lost:
    
        if ((r1 instanceof java.lang.String) == false) goto L217;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x00c5, code lost:
    
        r1 = (java.lang.String) r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x00cb, code lost:
    
        if (r1.length() > 10) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x00cd, code lost:
    
        r1 = com.alibaba.fastjson.util.TypeUtils.parseFloat(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x00d6, code lost:
    
        r7.setFloat(r0, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x00d2, code lost:
    
        r1 = java.lang.Float.parseFloat(r1);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object createInstance(java.util.Map<java.lang.String, java.lang.Object> r13, com.alibaba.fastjson.parser.ParserConfig r14) {
        /*
            Method dump skipped, instructions count: 711
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.createInstance(java.util.Map, com.alibaba.fastjson.parser.ParserConfig):java.lang.Object");
    }
}
