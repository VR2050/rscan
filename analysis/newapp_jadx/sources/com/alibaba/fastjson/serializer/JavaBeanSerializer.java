package com.alibaba.fastjson.serializer;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.PropertyNamingStrategy;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.util.FieldInfo;
import com.alibaba.fastjson.util.TypeUtils;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class JavaBeanSerializer extends SerializeFilterable implements ObjectSerializer {
    public SerializeBeanInfo beanInfo;
    public final FieldSerializer[] getters;
    private volatile transient long[] hashArray;
    private volatile transient short[] hashArrayMapping;
    public final FieldSerializer[] sortedGetters;

    public JavaBeanSerializer(Class<?> cls) {
        this(cls, (Map<String, String>) null);
    }

    public static Map<String, String> createAliasMap(String... strArr) {
        HashMap hashMap = new HashMap();
        for (String str : strArr) {
            hashMap.put(str, str);
        }
        return hashMap;
    }

    public boolean applyLabel(JSONSerializer jSONSerializer, String str) {
        List<LabelFilter> list = jSONSerializer.labelFilters;
        if (list != null) {
            Iterator<LabelFilter> it = list.iterator();
            while (it.hasNext()) {
                if (!it.next().apply(str)) {
                    return false;
                }
            }
        }
        List<LabelFilter> list2 = this.labelFilters;
        if (list2 == null) {
            return true;
        }
        Iterator<LabelFilter> it2 = list2.iterator();
        while (it2.hasNext()) {
            if (!it2.next().apply(str)) {
                return false;
            }
        }
        return true;
    }

    public BeanContext getBeanContext(int i2) {
        return this.sortedGetters[i2].fieldContext;
    }

    public Set<String> getFieldNames(Object obj) {
        HashSet hashSet = new HashSet();
        for (FieldSerializer fieldSerializer : this.sortedGetters) {
            if (fieldSerializer.getPropertyValueDirect(obj) != null) {
                hashSet.add(fieldSerializer.fieldInfo.name);
            }
        }
        return hashSet;
    }

    public FieldSerializer getFieldSerializer(String str) {
        if (str == null) {
            return null;
        }
        int i2 = 0;
        int length = this.sortedGetters.length - 1;
        while (i2 <= length) {
            int i3 = (i2 + length) >>> 1;
            int compareTo = this.sortedGetters[i3].fieldInfo.name.compareTo(str);
            if (compareTo < 0) {
                i2 = i3 + 1;
            } else {
                if (compareTo <= 0) {
                    return this.sortedGetters[i3];
                }
                length = i3 - 1;
            }
        }
        return null;
    }

    public Type getFieldType(int i2) {
        return this.sortedGetters[i2].fieldInfo.fieldType;
    }

    public Object getFieldValue(Object obj, String str) {
        FieldSerializer fieldSerializer = getFieldSerializer(str);
        if (fieldSerializer == null) {
            throw new JSONException(C1499a.m637w("field not found. ", str));
        }
        try {
            return fieldSerializer.getPropertyValue(obj);
        } catch (IllegalAccessException e2) {
            throw new JSONException(C1499a.m637w("getFieldValue error.", str), e2);
        } catch (InvocationTargetException e3) {
            throw new JSONException(C1499a.m637w("getFieldValue error.", str), e3);
        }
    }

    public List<Object> getFieldValues(Object obj) {
        ArrayList arrayList = new ArrayList(this.sortedGetters.length);
        for (FieldSerializer fieldSerializer : this.sortedGetters) {
            arrayList.add(fieldSerializer.getPropertyValue(obj));
        }
        return arrayList;
    }

    public Map<String, Object> getFieldValuesMap(Object obj) {
        LinkedHashMap linkedHashMap = new LinkedHashMap(this.sortedGetters.length);
        for (FieldSerializer fieldSerializer : this.sortedGetters) {
            boolean isEnabled = SerializerFeature.isEnabled(fieldSerializer.features, SerializerFeature.SkipTransientField);
            FieldInfo fieldInfo = fieldSerializer.fieldInfo;
            if (!isEnabled || fieldInfo == null || !fieldInfo.fieldTransient) {
                if (fieldInfo.unwrapped) {
                    Object json = JSON.toJSON(fieldSerializer.getPropertyValue(obj));
                    if (json instanceof Map) {
                        linkedHashMap.putAll((Map) json);
                    } else {
                        linkedHashMap.put(fieldSerializer.fieldInfo.name, fieldSerializer.getPropertyValue(obj));
                    }
                } else {
                    linkedHashMap.put(fieldInfo.name, fieldSerializer.getPropertyValue(obj));
                }
            }
        }
        return linkedHashMap;
    }

    public List<Object> getObjectFieldValues(Object obj) {
        ArrayList arrayList = new ArrayList(this.sortedGetters.length);
        for (FieldSerializer fieldSerializer : this.sortedGetters) {
            Class<?> cls = fieldSerializer.fieldInfo.fieldClass;
            if (!cls.isPrimitive() && !cls.getName().startsWith("java.lang.")) {
                arrayList.add(fieldSerializer.getPropertyValue(obj));
            }
        }
        return arrayList;
    }

    public int getSize(Object obj) {
        int i2 = 0;
        for (FieldSerializer fieldSerializer : this.sortedGetters) {
            if (fieldSerializer.getPropertyValueDirect(obj) != null) {
                i2++;
            }
        }
        return i2;
    }

    public Class<?> getType() {
        return this.beanInfo.beanType;
    }

    public boolean isWriteAsArray(JSONSerializer jSONSerializer) {
        return isWriteAsArray(jSONSerializer, 0);
    }

    @Override // com.alibaba.fastjson.serializer.ObjectSerializer
    public void write(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        write(jSONSerializer, obj, obj2, type, i2, false);
    }

    public char writeAfter(JSONSerializer jSONSerializer, Object obj, char c2) {
        List<AfterFilter> list = jSONSerializer.afterFilters;
        if (list != null) {
            Iterator<AfterFilter> it = list.iterator();
            while (it.hasNext()) {
                c2 = it.next().writeAfter(jSONSerializer, obj, c2);
            }
        }
        List<AfterFilter> list2 = this.afterFilters;
        if (list2 != null) {
            Iterator<AfterFilter> it2 = list2.iterator();
            while (it2.hasNext()) {
                c2 = it2.next().writeAfter(jSONSerializer, obj, c2);
            }
        }
        return c2;
    }

    public void writeAsArray(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        write(jSONSerializer, obj, obj2, type, i2);
    }

    public void writeAsArrayNonContext(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        write(jSONSerializer, obj, obj2, type, i2);
    }

    public char writeBefore(JSONSerializer jSONSerializer, Object obj, char c2) {
        List<BeforeFilter> list = jSONSerializer.beforeFilters;
        if (list != null) {
            Iterator<BeforeFilter> it = list.iterator();
            while (it.hasNext()) {
                c2 = it.next().writeBefore(jSONSerializer, obj, c2);
            }
        }
        List<BeforeFilter> list2 = this.beforeFilters;
        if (list2 != null) {
            Iterator<BeforeFilter> it2 = list2.iterator();
            while (it2.hasNext()) {
                c2 = it2.next().writeBefore(jSONSerializer, obj, c2);
            }
        }
        return c2;
    }

    public void writeClassName(JSONSerializer jSONSerializer, String str, Object obj) {
        if (str == null) {
            str = jSONSerializer.config.typeKey;
        }
        jSONSerializer.out.writeFieldName(str, false);
        String str2 = this.beanInfo.typeName;
        if (str2 == null) {
            Class<?> cls = obj.getClass();
            if (TypeUtils.isProxy(cls)) {
                cls = cls.getSuperclass();
            }
            str2 = cls.getName();
        }
        jSONSerializer.write(str2);
    }

    public void writeDirectNonContext(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        write(jSONSerializer, obj, obj2, type, i2);
    }

    public void writeNoneASM(JSONSerializer jSONSerializer, Object obj, Object obj2, Type type, int i2) {
        write(jSONSerializer, obj, obj2, type, i2, false);
    }

    public boolean writeReference(JSONSerializer jSONSerializer, Object obj, int i2) {
        IdentityHashMap<Object, SerialContext> identityHashMap;
        SerialContext serialContext = jSONSerializer.context;
        int i3 = SerializerFeature.DisableCircularReferenceDetect.mask;
        if (serialContext == null || (serialContext.features & i3) != 0 || (i2 & i3) != 0 || (identityHashMap = jSONSerializer.references) == null || !identityHashMap.containsKey(obj)) {
            return false;
        }
        jSONSerializer.writeReference(obj);
        return true;
    }

    public JavaBeanSerializer(Class<?> cls, String... strArr) {
        this(cls, createAliasMap(strArr));
    }

    public boolean isWriteAsArray(JSONSerializer jSONSerializer, int i2) {
        int i3 = SerializerFeature.BeanToArray.mask;
        return ((this.beanInfo.features & i3) == 0 && !jSONSerializer.out.beanToArray && (i2 & i3) == 0) ? false : true;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(3:(4:45|46|47|(8:48|49|(1:389)(1:52)|(2:383|384)|(4:59|(1:(1:382))(1:63)|64|(9:(1:71)(10:365|366|367|73|74|(1:76)(16:(3:321|322|(1:325))|81|82|(3:84|(1:86)|(5:91|(2:93|(2:101|(1:103)(2:104|(1:108)))(2:99|100))(1:(2:110|(3:117|(2:120|(1:124))|119)(2:116|100))(2:125|(2:127|(2:134|(1:136)(2:137|(1:141)))(2:133|100))(2:142|(2:144|(2:151|(1:153)(2:154|(1:158)))(2:150|100))(1:(2:162|(2:166|100))))))|78|79|58)(1:90))|(16:168|(2:170|(1:172))|174|(2:176|(2:180|100))|181|(2:183|(2:187|100))|188|(2:190|(2:194|100))|195|(2:197|(2:201|100))|202|(2:204|(2:208|100))|209|(2:211|(2:215|100))|216|(2:222|100))|(1:320)(3:224|(2:230|(1:232))|100)|233|(2:(1:236)(1:263)|237)(2:264|(2:(1:267)|268)(10:(3:270|(1:318)(1:274)|(9:(1:281)(1:315)|(2:283|(2:305|(1:313)(3:311|312|58))(1:(4:289|(1:291)|292|(2:297|(1:299)(1:300))(1:296))(2:301|(1:303)(1:304))))(1:314)|239|(7:243|(2:249|(2:251|(2:252|(2:254|(2:256|257)(1:259))(2:260|261))))|245|(3:247|248|58)|78|79|58)|262|(0)|78|79|58))|319|(0)(0)|239|(8:241|243|(0)|245|(0)|78|79|58)|262|(0)|78|79|58))|238|239|(0)|262|(0)|78|79|58)|77|78|79|58)|72|73|74|(0)(0)|77|78|79|58))|56|57|58))|42|43) */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x02b7, code lost:
    
        if ((r33.beanInfo.features & r4) == 0) goto L253;
     */
    /* JADX WARN: Code restructure failed: missing block: B:258:0x0467, code lost:
    
        if (r0 == false) goto L333;
     */
    /* JADX WARN: Code restructure failed: missing block: B:385:0x00f7, code lost:
    
        if (r11.fieldTransient != false) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:419:0x04d6, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:420:0x04d7, code lost:
    
        r0 = r0;
     */
    /* JADX WARN: Removed duplicated region for block: B:241:0x043a A[Catch: Exception -> 0x0475, all -> 0x0494, TryCatch #4 {Exception -> 0x0475, blocks: (B:74:0x0150, B:81:0x017b, B:84:0x01a3, B:86:0x01af, B:88:0x01ba, B:90:0x01c4, B:93:0x01ce, B:95:0x01da, B:97:0x01de, B:101:0x01e5, B:103:0x01e9, B:104:0x01ed, B:106:0x01f2, B:108:0x01f5, B:110:0x01fb, B:112:0x0207, B:114:0x020b, B:117:0x0212, B:120:0x0219, B:122:0x021e, B:125:0x0222, B:127:0x022a, B:129:0x0236, B:131:0x023a, B:134:0x0241, B:136:0x0245, B:137:0x024a, B:139:0x024f, B:141:0x0252, B:142:0x0257, B:144:0x025f, B:146:0x026b, B:148:0x026f, B:151:0x0276, B:153:0x027a, B:154:0x027f, B:156:0x0284, B:158:0x0287, B:160:0x028e, B:162:0x0292, B:164:0x029c, B:168:0x02a5, B:170:0x02a9, B:172:0x02b2, B:174:0x02b9, B:176:0x02bf, B:178:0x02c3, B:181:0x02ce, B:183:0x02d2, B:185:0x02d6, B:188:0x02e1, B:190:0x02e5, B:192:0x02e9, B:195:0x02f4, B:197:0x02f8, B:199:0x02fc, B:202:0x030a, B:204:0x030e, B:206:0x0312, B:209:0x031f, B:211:0x0323, B:213:0x0327, B:216:0x0335, B:218:0x0339, B:220:0x033d, B:224:0x0349, B:226:0x034d, B:228:0x0351, B:230:0x035c, B:232:0x0369, B:236:0x0375, B:237:0x037b, B:239:0x0436, B:241:0x043a, B:243:0x043e, B:249:0x0448, B:251:0x0450, B:252:0x0458, B:254:0x045e, B:267:0x0386, B:268:0x0389, B:270:0x038f, B:272:0x039b, B:276:0x03b0, B:281:0x03ba, B:283:0x03ca, B:286:0x03d2, B:289:0x03dc, B:291:0x03e4, B:292:0x03ed, B:294:0x03f6, B:296:0x03fd, B:297:0x0401, B:299:0x0404, B:300:0x0408, B:301:0x040c, B:303:0x0411, B:304:0x0415, B:305:0x0419, B:307:0x041d, B:309:0x0421, B:313:0x042f, B:314:0x0433, B:315:0x03c2), top: B:73:0x0150 }] */
    /* JADX WARN: Removed duplicated region for block: B:247:0x046d  */
    /* JADX WARN: Removed duplicated region for block: B:249:0x0448 A[Catch: Exception -> 0x0475, all -> 0x0494, TryCatch #4 {Exception -> 0x0475, blocks: (B:74:0x0150, B:81:0x017b, B:84:0x01a3, B:86:0x01af, B:88:0x01ba, B:90:0x01c4, B:93:0x01ce, B:95:0x01da, B:97:0x01de, B:101:0x01e5, B:103:0x01e9, B:104:0x01ed, B:106:0x01f2, B:108:0x01f5, B:110:0x01fb, B:112:0x0207, B:114:0x020b, B:117:0x0212, B:120:0x0219, B:122:0x021e, B:125:0x0222, B:127:0x022a, B:129:0x0236, B:131:0x023a, B:134:0x0241, B:136:0x0245, B:137:0x024a, B:139:0x024f, B:141:0x0252, B:142:0x0257, B:144:0x025f, B:146:0x026b, B:148:0x026f, B:151:0x0276, B:153:0x027a, B:154:0x027f, B:156:0x0284, B:158:0x0287, B:160:0x028e, B:162:0x0292, B:164:0x029c, B:168:0x02a5, B:170:0x02a9, B:172:0x02b2, B:174:0x02b9, B:176:0x02bf, B:178:0x02c3, B:181:0x02ce, B:183:0x02d2, B:185:0x02d6, B:188:0x02e1, B:190:0x02e5, B:192:0x02e9, B:195:0x02f4, B:197:0x02f8, B:199:0x02fc, B:202:0x030a, B:204:0x030e, B:206:0x0312, B:209:0x031f, B:211:0x0323, B:213:0x0327, B:216:0x0335, B:218:0x0339, B:220:0x033d, B:224:0x0349, B:226:0x034d, B:228:0x0351, B:230:0x035c, B:232:0x0369, B:236:0x0375, B:237:0x037b, B:239:0x0436, B:241:0x043a, B:243:0x043e, B:249:0x0448, B:251:0x0450, B:252:0x0458, B:254:0x045e, B:267:0x0386, B:268:0x0389, B:270:0x038f, B:272:0x039b, B:276:0x03b0, B:281:0x03ba, B:283:0x03ca, B:286:0x03d2, B:289:0x03dc, B:291:0x03e4, B:292:0x03ed, B:294:0x03f6, B:296:0x03fd, B:297:0x0401, B:299:0x0404, B:300:0x0408, B:301:0x040c, B:303:0x0411, B:304:0x0415, B:305:0x0419, B:307:0x041d, B:309:0x0421, B:313:0x042f, B:314:0x0433, B:315:0x03c2), top: B:73:0x0150 }] */
    /* JADX WARN: Removed duplicated region for block: B:283:0x03ca A[Catch: Exception -> 0x0475, all -> 0x0494, TryCatch #4 {Exception -> 0x0475, blocks: (B:74:0x0150, B:81:0x017b, B:84:0x01a3, B:86:0x01af, B:88:0x01ba, B:90:0x01c4, B:93:0x01ce, B:95:0x01da, B:97:0x01de, B:101:0x01e5, B:103:0x01e9, B:104:0x01ed, B:106:0x01f2, B:108:0x01f5, B:110:0x01fb, B:112:0x0207, B:114:0x020b, B:117:0x0212, B:120:0x0219, B:122:0x021e, B:125:0x0222, B:127:0x022a, B:129:0x0236, B:131:0x023a, B:134:0x0241, B:136:0x0245, B:137:0x024a, B:139:0x024f, B:141:0x0252, B:142:0x0257, B:144:0x025f, B:146:0x026b, B:148:0x026f, B:151:0x0276, B:153:0x027a, B:154:0x027f, B:156:0x0284, B:158:0x0287, B:160:0x028e, B:162:0x0292, B:164:0x029c, B:168:0x02a5, B:170:0x02a9, B:172:0x02b2, B:174:0x02b9, B:176:0x02bf, B:178:0x02c3, B:181:0x02ce, B:183:0x02d2, B:185:0x02d6, B:188:0x02e1, B:190:0x02e5, B:192:0x02e9, B:195:0x02f4, B:197:0x02f8, B:199:0x02fc, B:202:0x030a, B:204:0x030e, B:206:0x0312, B:209:0x031f, B:211:0x0323, B:213:0x0327, B:216:0x0335, B:218:0x0339, B:220:0x033d, B:224:0x0349, B:226:0x034d, B:228:0x0351, B:230:0x035c, B:232:0x0369, B:236:0x0375, B:237:0x037b, B:239:0x0436, B:241:0x043a, B:243:0x043e, B:249:0x0448, B:251:0x0450, B:252:0x0458, B:254:0x045e, B:267:0x0386, B:268:0x0389, B:270:0x038f, B:272:0x039b, B:276:0x03b0, B:281:0x03ba, B:283:0x03ca, B:286:0x03d2, B:289:0x03dc, B:291:0x03e4, B:292:0x03ed, B:294:0x03f6, B:296:0x03fd, B:297:0x0401, B:299:0x0404, B:300:0x0408, B:301:0x040c, B:303:0x0411, B:304:0x0415, B:305:0x0419, B:307:0x041d, B:309:0x0421, B:313:0x042f, B:314:0x0433, B:315:0x03c2), top: B:73:0x0150 }] */
    /* JADX WARN: Removed duplicated region for block: B:314:0x0433 A[Catch: Exception -> 0x0475, all -> 0x0494, TryCatch #4 {Exception -> 0x0475, blocks: (B:74:0x0150, B:81:0x017b, B:84:0x01a3, B:86:0x01af, B:88:0x01ba, B:90:0x01c4, B:93:0x01ce, B:95:0x01da, B:97:0x01de, B:101:0x01e5, B:103:0x01e9, B:104:0x01ed, B:106:0x01f2, B:108:0x01f5, B:110:0x01fb, B:112:0x0207, B:114:0x020b, B:117:0x0212, B:120:0x0219, B:122:0x021e, B:125:0x0222, B:127:0x022a, B:129:0x0236, B:131:0x023a, B:134:0x0241, B:136:0x0245, B:137:0x024a, B:139:0x024f, B:141:0x0252, B:142:0x0257, B:144:0x025f, B:146:0x026b, B:148:0x026f, B:151:0x0276, B:153:0x027a, B:154:0x027f, B:156:0x0284, B:158:0x0287, B:160:0x028e, B:162:0x0292, B:164:0x029c, B:168:0x02a5, B:170:0x02a9, B:172:0x02b2, B:174:0x02b9, B:176:0x02bf, B:178:0x02c3, B:181:0x02ce, B:183:0x02d2, B:185:0x02d6, B:188:0x02e1, B:190:0x02e5, B:192:0x02e9, B:195:0x02f4, B:197:0x02f8, B:199:0x02fc, B:202:0x030a, B:204:0x030e, B:206:0x0312, B:209:0x031f, B:211:0x0323, B:213:0x0327, B:216:0x0335, B:218:0x0339, B:220:0x033d, B:224:0x0349, B:226:0x034d, B:228:0x0351, B:230:0x035c, B:232:0x0369, B:236:0x0375, B:237:0x037b, B:239:0x0436, B:241:0x043a, B:243:0x043e, B:249:0x0448, B:251:0x0450, B:252:0x0458, B:254:0x045e, B:267:0x0386, B:268:0x0389, B:270:0x038f, B:272:0x039b, B:276:0x03b0, B:281:0x03ba, B:283:0x03ca, B:286:0x03d2, B:289:0x03dc, B:291:0x03e4, B:292:0x03ed, B:294:0x03f6, B:296:0x03fd, B:297:0x0401, B:299:0x0404, B:300:0x0408, B:301:0x040c, B:303:0x0411, B:304:0x0415, B:305:0x0419, B:307:0x041d, B:309:0x0421, B:313:0x042f, B:314:0x0433, B:315:0x03c2), top: B:73:0x0150 }] */
    /* JADX WARN: Removed duplicated region for block: B:335:0x0508 A[Catch: all -> 0x051b, TRY_ENTER, TryCatch #13 {all -> 0x051b, blocks: (B:335:0x0508, B:336:0x0558, B:338:0x055e, B:339:0x0576, B:341:0x057a, B:344:0x0583, B:345:0x0588, B:349:0x051f, B:351:0x0523, B:353:0x0527, B:354:0x0542), top: B:333:0x0506 }] */
    /* JADX WARN: Removed duplicated region for block: B:338:0x055e A[Catch: all -> 0x051b, TryCatch #13 {all -> 0x051b, blocks: (B:335:0x0508, B:336:0x0558, B:338:0x055e, B:339:0x0576, B:341:0x057a, B:344:0x0583, B:345:0x0588, B:349:0x051f, B:351:0x0523, B:353:0x0527, B:354:0x0542), top: B:333:0x0506 }] */
    /* JADX WARN: Removed duplicated region for block: B:341:0x057a A[Catch: all -> 0x051b, TryCatch #13 {all -> 0x051b, blocks: (B:335:0x0508, B:336:0x0558, B:338:0x055e, B:339:0x0576, B:341:0x057a, B:344:0x0583, B:345:0x0588, B:349:0x051f, B:351:0x0523, B:353:0x0527, B:354:0x0542), top: B:333:0x0506 }] */
    /* JADX WARN: Removed duplicated region for block: B:343:0x0580  */
    /* JADX WARN: Removed duplicated region for block: B:347:0x0581  */
    /* JADX WARN: Removed duplicated region for block: B:348:0x051d  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:402:0x04ae  */
    /* JADX WARN: Removed duplicated region for block: B:410:0x04ca A[Catch: all -> 0x0494, Exception -> 0x04d4, TRY_LEAVE, TryCatch #5 {Exception -> 0x04d4, blocks: (B:404:0x04b2, B:406:0x04ba, B:408:0x04c2, B:410:0x04ca), top: B:403:0x04b2 }] */
    /* JADX WARN: Removed duplicated region for block: B:415:0x04b1  */
    /* JADX WARN: Removed duplicated region for block: B:424:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:425:0x00ac  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00ce A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0156  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0162  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void write(com.alibaba.fastjson.serializer.JSONSerializer r34, java.lang.Object r35, java.lang.Object r36, java.lang.reflect.Type r37, int r38, boolean r39) {
        /*
            Method dump skipped, instructions count: 1422
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.serializer.JavaBeanSerializer.write(com.alibaba.fastjson.serializer.JSONSerializer, java.lang.Object, java.lang.Object, java.lang.reflect.Type, int, boolean):void");
    }

    public JavaBeanSerializer(Class<?> cls, Map<String, String> map) {
        this(TypeUtils.buildBeanInfo(cls, map, null));
    }

    public JavaBeanSerializer(SerializeBeanInfo serializeBeanInfo) {
        FieldSerializer[] fieldSerializerArr;
        boolean z;
        this.beanInfo = serializeBeanInfo;
        this.sortedGetters = new FieldSerializer[serializeBeanInfo.sortedFields.length];
        int i2 = 0;
        while (true) {
            fieldSerializerArr = this.sortedGetters;
            if (i2 >= fieldSerializerArr.length) {
                break;
            }
            fieldSerializerArr[i2] = new FieldSerializer(serializeBeanInfo.beanType, serializeBeanInfo.sortedFields[i2]);
            i2++;
        }
        FieldInfo[] fieldInfoArr = serializeBeanInfo.fields;
        if (fieldInfoArr == serializeBeanInfo.sortedFields) {
            this.getters = fieldSerializerArr;
        } else {
            this.getters = new FieldSerializer[fieldInfoArr.length];
            int i3 = 0;
            while (true) {
                if (i3 >= this.getters.length) {
                    z = false;
                    break;
                }
                FieldSerializer fieldSerializer = getFieldSerializer(serializeBeanInfo.fields[i3].name);
                if (fieldSerializer == null) {
                    z = true;
                    break;
                } else {
                    this.getters[i3] = fieldSerializer;
                    i3++;
                }
            }
            if (z) {
                FieldSerializer[] fieldSerializerArr2 = this.sortedGetters;
                System.arraycopy(fieldSerializerArr2, 0, this.getters, 0, fieldSerializerArr2.length);
            }
        }
        JSONType jSONType = serializeBeanInfo.jsonType;
        if (jSONType != null) {
            for (Class<? extends SerializeFilter> cls : jSONType.serialzeFilters()) {
                try {
                    addFilter(cls.getConstructor(new Class[0]).newInstance(new Object[0]));
                } catch (Exception unused) {
                }
            }
        }
    }

    public FieldSerializer getFieldSerializer(long j2) {
        PropertyNamingStrategy[] propertyNamingStrategyArr;
        int binarySearch;
        if (this.hashArray == null) {
            propertyNamingStrategyArr = PropertyNamingStrategy.values();
            long[] jArr = new long[this.sortedGetters.length * 5];
            int i2 = 0;
            int i3 = 0;
            while (true) {
                FieldSerializer[] fieldSerializerArr = this.sortedGetters;
                if (i2 >= fieldSerializerArr.length) {
                    break;
                }
                String str = fieldSerializerArr[i2].fieldInfo.name;
                jArr[i3] = TypeUtils.fnv1a_64(str);
                i3++;
                for (int i4 = 0; i4 < 5; i4++) {
                    String translate = propertyNamingStrategyArr[i4].translate(str);
                    if (!str.equals(translate)) {
                        jArr[i3] = TypeUtils.fnv1a_64(translate);
                        i3++;
                    }
                }
                i2++;
            }
            Arrays.sort(jArr, 0, i3);
            this.hashArray = new long[i3];
            System.arraycopy(jArr, 0, this.hashArray, 0, i3);
        } else {
            propertyNamingStrategyArr = null;
        }
        int binarySearch2 = Arrays.binarySearch(this.hashArray, j2);
        if (binarySearch2 < 0) {
            return null;
        }
        if (this.hashArrayMapping == null) {
            if (propertyNamingStrategyArr == null) {
                propertyNamingStrategyArr = PropertyNamingStrategy.values();
            }
            short[] sArr = new short[this.hashArray.length];
            Arrays.fill(sArr, (short) -1);
            int i5 = 0;
            while (true) {
                FieldSerializer[] fieldSerializerArr2 = this.sortedGetters;
                if (i5 >= fieldSerializerArr2.length) {
                    break;
                }
                String str2 = fieldSerializerArr2[i5].fieldInfo.name;
                int binarySearch3 = Arrays.binarySearch(this.hashArray, TypeUtils.fnv1a_64(str2));
                if (binarySearch3 >= 0) {
                    sArr[binarySearch3] = (short) i5;
                }
                for (PropertyNamingStrategy propertyNamingStrategy : propertyNamingStrategyArr) {
                    String translate2 = propertyNamingStrategy.translate(str2);
                    if (!str2.equals(translate2) && (binarySearch = Arrays.binarySearch(this.hashArray, TypeUtils.fnv1a_64(translate2))) >= 0) {
                        sArr[binarySearch] = (short) i5;
                    }
                }
                i5++;
            }
            this.hashArrayMapping = sArr;
        }
        short s = this.hashArrayMapping[binarySearch2];
        if (s != -1) {
            return this.sortedGetters[s];
        }
        return null;
    }

    public Object getFieldValue(Object obj, String str, long j2, boolean z) {
        FieldSerializer fieldSerializer = getFieldSerializer(j2);
        if (fieldSerializer == null) {
            if (z) {
                throw new JSONException(C1499a.m637w("field not found. ", str));
            }
            return null;
        }
        try {
            return fieldSerializer.getPropertyValue(obj);
        } catch (IllegalAccessException e2) {
            throw new JSONException(C1499a.m637w("getFieldValue error.", str), e2);
        } catch (InvocationTargetException e3) {
            throw new JSONException(C1499a.m637w("getFieldValue error.", str), e3);
        }
    }
}
