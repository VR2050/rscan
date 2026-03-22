package com.alibaba.fastjson.parser;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.JSONPath;
import com.alibaba.fastjson.JSONPathException;
import com.alibaba.fastjson.parser.deserializer.ExtraProcessable;
import com.alibaba.fastjson.parser.deserializer.ExtraProcessor;
import com.alibaba.fastjson.parser.deserializer.ExtraTypeProvider;
import com.alibaba.fastjson.parser.deserializer.FieldDeserializer;
import com.alibaba.fastjson.parser.deserializer.FieldTypeResolver;
import com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer;
import com.alibaba.fastjson.parser.deserializer.ObjectDeserializer;
import com.alibaba.fastjson.parser.deserializer.ResolveFieldDeserializer;
import com.alibaba.fastjson.serializer.BeanContext;
import com.alibaba.fastjson.serializer.IntegerCodec;
import com.alibaba.fastjson.serializer.LongCodec;
import com.alibaba.fastjson.serializer.StringCodec;
import com.alibaba.fastjson.util.FieldInfo;
import com.alibaba.fastjson.util.TypeUtils;
import java.io.Closeable;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class DefaultJSONParser implements Closeable {
    public static final int NONE = 0;
    public static final int NeedToResolve = 1;
    public static final int TypeNameRedirect = 2;
    private static final Set<Class<?>> primitiveClasses = new HashSet();
    private String[] autoTypeAccept;
    private boolean autoTypeEnable;
    public ParserConfig config;
    public ParseContext context;
    private ParseContext[] contextArray;
    private int contextArrayIndex;
    private DateFormat dateFormat;
    private String dateFormatPattern;
    private List<ExtraProcessor> extraProcessors;
    private List<ExtraTypeProvider> extraTypeProviders;
    public FieldTypeResolver fieldTypeResolver;
    public final Object input;
    public transient BeanContext lastBeanContext;
    public final JSONLexer lexer;
    private int objectKeyLevel;
    public int resolveStatus;
    private List<ResolveTask> resolveTaskList;
    public final SymbolTable symbolTable;

    public static class ResolveTask {
        public final ParseContext context;
        public FieldDeserializer fieldDeserializer;
        public ParseContext ownerContext;
        public final String referenceValue;

        public ResolveTask(ParseContext parseContext, String str) {
            this.context = parseContext;
            this.referenceValue = str;
        }
    }

    static {
        Class<?>[] clsArr = {Boolean.TYPE, Byte.TYPE, Short.TYPE, Integer.TYPE, Long.TYPE, Float.TYPE, Double.TYPE, Boolean.class, Byte.class, Short.class, Integer.class, Long.class, Float.class, Double.class, BigInteger.class, BigDecimal.class, String.class};
        for (int i2 = 0; i2 < 17; i2++) {
            primitiveClasses.add(clsArr[i2]);
        }
    }

    public DefaultJSONParser(String str) {
        this(str, ParserConfig.getGlobalInstance(), JSON.DEFAULT_PARSER_FEATURE);
    }

    private void addContext(ParseContext parseContext) {
        int i2 = this.contextArrayIndex;
        this.contextArrayIndex = i2 + 1;
        ParseContext[] parseContextArr = this.contextArray;
        if (parseContextArr == null) {
            this.contextArray = new ParseContext[8];
        } else if (i2 >= parseContextArr.length) {
            ParseContext[] parseContextArr2 = new ParseContext[(parseContextArr.length * 3) / 2];
            System.arraycopy(parseContextArr, 0, parseContextArr2, 0, parseContextArr.length);
            this.contextArray = parseContextArr2;
        }
        this.contextArray[i2] = parseContext;
    }

    public final void accept(int i2) {
        JSONLexer jSONLexer = this.lexer;
        if (jSONLexer.token() == i2) {
            jSONLexer.nextToken();
            return;
        }
        StringBuilder m586H = C1499a.m586H("syntax error, expect ");
        m586H.append(JSONToken.name(i2));
        m586H.append(", actual ");
        m586H.append(JSONToken.name(jSONLexer.token()));
        throw new JSONException(m586H.toString());
    }

    public void acceptType(String str) {
        JSONLexer jSONLexer = this.lexer;
        jSONLexer.nextTokenWithColon();
        if (jSONLexer.token() != 4) {
            throw new JSONException("type not match error");
        }
        if (!str.equals(jSONLexer.stringVal())) {
            throw new JSONException("type not match error");
        }
        jSONLexer.nextToken();
        if (jSONLexer.token() == 16) {
            jSONLexer.nextToken();
        }
    }

    public void addResolveTask(ResolveTask resolveTask) {
        if (this.resolveTaskList == null) {
            this.resolveTaskList = new ArrayList(2);
        }
        this.resolveTaskList.add(resolveTask);
    }

    public void checkListResolve(Collection collection) {
        if (this.resolveStatus == 1) {
            if (!(collection instanceof List)) {
                ResolveTask lastResolveTask = getLastResolveTask();
                lastResolveTask.fieldDeserializer = new ResolveFieldDeserializer(collection);
                lastResolveTask.ownerContext = this.context;
                setResolveStatus(0);
                return;
            }
            int size = collection.size() - 1;
            ResolveTask lastResolveTask2 = getLastResolveTask();
            lastResolveTask2.fieldDeserializer = new ResolveFieldDeserializer(this, (List) collection, size);
            lastResolveTask2.ownerContext = this.context;
            setResolveStatus(0);
        }
    }

    public void checkMapResolve(Map map, Object obj) {
        if (this.resolveStatus == 1) {
            ResolveFieldDeserializer resolveFieldDeserializer = new ResolveFieldDeserializer(map, obj);
            ResolveTask lastResolveTask = getLastResolveTask();
            lastResolveTask.fieldDeserializer = resolveFieldDeserializer;
            lastResolveTask.ownerContext = this.context;
            setResolveStatus(0);
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        JSONLexer jSONLexer = this.lexer;
        try {
            if (jSONLexer.isEnabled(Feature.AutoCloseSource) && jSONLexer.token() != 20) {
                throw new JSONException("not close json text, token : " + JSONToken.name(jSONLexer.token()));
            }
        } finally {
            jSONLexer.close();
        }
    }

    public void config(Feature feature, boolean z) {
        this.lexer.config(feature, z);
    }

    public ParserConfig getConfig() {
        return this.config;
    }

    public ParseContext getContext() {
        return this.context;
    }

    public String getDateFomartPattern() {
        return this.dateFormatPattern;
    }

    public DateFormat getDateFormat() {
        if (this.dateFormat == null) {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(this.dateFormatPattern, this.lexer.getLocale());
            this.dateFormat = simpleDateFormat;
            simpleDateFormat.setTimeZone(this.lexer.getTimeZone());
        }
        return this.dateFormat;
    }

    public List<ExtraProcessor> getExtraProcessors() {
        if (this.extraProcessors == null) {
            this.extraProcessors = new ArrayList(2);
        }
        return this.extraProcessors;
    }

    public List<ExtraTypeProvider> getExtraTypeProviders() {
        if (this.extraTypeProviders == null) {
            this.extraTypeProviders = new ArrayList(2);
        }
        return this.extraTypeProviders;
    }

    public FieldTypeResolver getFieldTypeResolver() {
        return this.fieldTypeResolver;
    }

    public String getInput() {
        Object obj = this.input;
        return obj instanceof char[] ? new String((char[]) this.input) : obj.toString();
    }

    public ResolveTask getLastResolveTask() {
        return this.resolveTaskList.get(r0.size() - 1);
    }

    public JSONLexer getLexer() {
        return this.lexer;
    }

    public Object getObject(String str) {
        for (int i2 = 0; i2 < this.contextArrayIndex; i2++) {
            if (str.equals(this.contextArray[i2].toString())) {
                return this.contextArray[i2].object;
            }
        }
        return null;
    }

    public int getResolveStatus() {
        return this.resolveStatus;
    }

    public List<ResolveTask> getResolveTaskList() {
        if (this.resolveTaskList == null) {
            this.resolveTaskList = new ArrayList(2);
        }
        return this.resolveTaskList;
    }

    public SymbolTable getSymbolTable() {
        return this.symbolTable;
    }

    public void handleResovleTask(Object obj) {
        Object obj2;
        FieldInfo fieldInfo;
        List<ResolveTask> list = this.resolveTaskList;
        if (list == null) {
            return;
        }
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            ResolveTask resolveTask = this.resolveTaskList.get(i2);
            String str = resolveTask.referenceValue;
            ParseContext parseContext = resolveTask.ownerContext;
            Object obj3 = parseContext != null ? parseContext.object : null;
            if (str.startsWith("$")) {
                obj2 = getObject(str);
                if (obj2 == null) {
                    try {
                        JSONPath compile = JSONPath.compile(str);
                        if (compile.isRef()) {
                            obj2 = compile.eval(obj);
                        }
                    } catch (JSONPathException unused) {
                    }
                }
            } else {
                obj2 = resolveTask.context.object;
            }
            FieldDeserializer fieldDeserializer = resolveTask.fieldDeserializer;
            if (fieldDeserializer != null) {
                if (obj2 != null && obj2.getClass() == JSONObject.class && (fieldInfo = fieldDeserializer.fieldInfo) != null && !Map.class.isAssignableFrom(fieldInfo.fieldClass)) {
                    Object obj4 = this.contextArray[0].object;
                    JSONPath compile2 = JSONPath.compile(str);
                    if (compile2.isRef()) {
                        obj2 = compile2.eval(obj4);
                    }
                }
                fieldDeserializer.setValue(obj3, obj2);
            }
        }
    }

    public boolean isEnabled(Feature feature) {
        return this.lexer.isEnabled(feature);
    }

    public Object parse() {
        return parse(null);
    }

    public <T> List<T> parseArray(Class<T> cls) {
        ArrayList arrayList = new ArrayList();
        parseArray((Class<?>) cls, (Collection) arrayList);
        return arrayList;
    }

    public Object parseArrayWithType(Type type) {
        if (this.lexer.token() == 8) {
            this.lexer.nextToken();
            return null;
        }
        Type[] actualTypeArguments = ((ParameterizedType) type).getActualTypeArguments();
        if (actualTypeArguments.length != 1) {
            throw new JSONException(C1499a.m640z("not support type ", type));
        }
        Type type2 = actualTypeArguments[0];
        if (type2 instanceof Class) {
            ArrayList arrayList = new ArrayList();
            parseArray((Class<?>) type2, (Collection) arrayList);
            return arrayList;
        }
        if (type2 instanceof WildcardType) {
            WildcardType wildcardType = (WildcardType) type2;
            Type type3 = wildcardType.getUpperBounds()[0];
            if (Object.class.equals(type3)) {
                if (wildcardType.getLowerBounds().length == 0) {
                    return parse();
                }
                throw new JSONException(C1499a.m640z("not support type : ", type));
            }
            ArrayList arrayList2 = new ArrayList();
            parseArray((Class<?>) type3, (Collection) arrayList2);
            return arrayList2;
        }
        if (type2 instanceof TypeVariable) {
            TypeVariable typeVariable = (TypeVariable) type2;
            Type[] bounds = typeVariable.getBounds();
            if (bounds.length != 1) {
                throw new JSONException("not support : " + typeVariable);
            }
            Type type4 = bounds[0];
            if (type4 instanceof Class) {
                ArrayList arrayList3 = new ArrayList();
                parseArray((Class<?>) type4, (Collection) arrayList3);
                return arrayList3;
            }
        }
        if (!(type2 instanceof ParameterizedType)) {
            throw new JSONException(C1499a.m640z("TODO : ", type));
        }
        ArrayList arrayList4 = new ArrayList();
        parseArray((ParameterizedType) type2, arrayList4);
        return arrayList4;
    }

    public void parseExtra(Object obj, String str) {
        this.lexer.nextTokenWithColon();
        List<ExtraTypeProvider> list = this.extraTypeProviders;
        Type type = null;
        if (list != null) {
            Iterator<ExtraTypeProvider> it = list.iterator();
            while (it.hasNext()) {
                type = it.next().getExtraType(obj, str);
            }
        }
        Object parse = type == null ? parse() : parseObject(type);
        if (obj instanceof ExtraProcessable) {
            ((ExtraProcessable) obj).processExtra(str, parse);
            return;
        }
        List<ExtraProcessor> list2 = this.extraProcessors;
        if (list2 != null) {
            Iterator<ExtraProcessor> it2 = list2.iterator();
            while (it2.hasNext()) {
                it2.next().processExtra(obj, str, parse);
            }
        }
        if (this.resolveStatus == 1) {
            this.resolveStatus = 0;
        }
    }

    public Object parseKey() {
        if (this.lexer.token() != 18) {
            return parse(null);
        }
        String stringVal = this.lexer.stringVal();
        this.lexer.nextToken(16);
        return stringVal;
    }

    /* JADX WARN: Code restructure failed: missing block: B:267:0x0280, code lost:
    
        r2.nextToken(16);
     */
    /* JADX WARN: Code restructure failed: missing block: B:268:0x028b, code lost:
    
        if (r2.token() != 13) goto L162;
     */
    /* JADX WARN: Code restructure failed: missing block: B:269:0x028d, code lost:
    
        r2.nextToken(16);
     */
    /* JADX WARN: Code restructure failed: missing block: B:272:0x0298, code lost:
    
        if ((r13.config.getDeserializer(r8) instanceof com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer) == false) goto L146;
     */
    /* JADX WARN: Code restructure failed: missing block: B:273:0x029a, code lost:
    
        r9 = com.alibaba.fastjson.util.TypeUtils.cast((java.lang.Object) r14, (java.lang.Class<java.lang.Object>) r8, r13.config);
     */
    /* JADX WARN: Code restructure failed: missing block: B:274:0x02a0, code lost:
    
        if (r9 != null) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:276:0x02a4, code lost:
    
        if (r8 != java.lang.Cloneable.class) goto L150;
     */
    /* JADX WARN: Code restructure failed: missing block: B:277:0x02a6, code lost:
    
        r9 = new java.util.HashMap();
     */
    /* JADX WARN: Code restructure failed: missing block: B:279:0x02b2, code lost:
    
        if ("java.util.Collections$EmptyMap".equals(r7) == false) goto L153;
     */
    /* JADX WARN: Code restructure failed: missing block: B:280:0x02b4, code lost:
    
        r9 = java.util.Collections.emptyMap();
     */
    /* JADX WARN: Code restructure failed: missing block: B:282:0x02bf, code lost:
    
        if ("java.util.Collections$UnmodifiableMap".equals(r7) == false) goto L156;
     */
    /* JADX WARN: Code restructure failed: missing block: B:283:0x02c1, code lost:
    
        r9 = java.util.Collections.unmodifiableMap(new java.util.HashMap());
     */
    /* JADX WARN: Code restructure failed: missing block: B:284:0x02cb, code lost:
    
        r9 = r8.newInstance();
     */
    /* JADX WARN: Code restructure failed: missing block: B:286:0x02d2, code lost:
    
        return r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:287:0x02d3, code lost:
    
        r14 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:289:0x02db, code lost:
    
        throw new com.alibaba.fastjson.JSONException("create instance error", r14);
     */
    /* JADX WARN: Code restructure failed: missing block: B:290:0x02dc, code lost:
    
        setResolveStatus(2);
        r0 = r13.context;
     */
    /* JADX WARN: Code restructure failed: missing block: B:291:0x02e2, code lost:
    
        if (r0 == null) goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:292:0x02e4, code lost:
    
        if (r15 == null) goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:294:0x02e8, code lost:
    
        if ((r15 instanceof java.lang.Integer) != false) goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:296:0x02ee, code lost:
    
        if ((r0.fieldName instanceof java.lang.Integer) != false) goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:297:0x02f0, code lost:
    
        popContext();
     */
    /* JADX WARN: Code restructure failed: missing block: B:299:0x02f7, code lost:
    
        if (r14.size() <= 0) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:300:0x02f9, code lost:
    
        r14 = com.alibaba.fastjson.util.TypeUtils.cast((java.lang.Object) r14, (java.lang.Class<java.lang.Object>) r8, r13.config);
        setResolveStatus(0);
        parseObject(r14);
     */
    /* JADX WARN: Code restructure failed: missing block: B:302:0x0309, code lost:
    
        return r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:303:0x030a, code lost:
    
        r14 = r13.config.getDeserializer(r8);
        r0 = r14.getClass();
     */
    /* JADX WARN: Code restructure failed: missing block: B:304:0x031a, code lost:
    
        if (com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.class.isAssignableFrom(r0) == false) goto L182;
     */
    /* JADX WARN: Code restructure failed: missing block: B:306:0x031e, code lost:
    
        if (r0 == com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer.class) goto L182;
     */
    /* JADX WARN: Code restructure failed: missing block: B:308:0x0322, code lost:
    
        if (r0 == com.alibaba.fastjson.parser.deserializer.ThrowableDeserializer.class) goto L182;
     */
    /* JADX WARN: Code restructure failed: missing block: B:309:0x0324, code lost:
    
        setResolveStatus(0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:312:0x0338, code lost:
    
        return r14.deserialze(r13, r8, r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:314:0x032b, code lost:
    
        if ((r14 instanceof com.alibaba.fastjson.parser.deserializer.MapDeserializer) == false) goto L185;
     */
    /* JADX WARN: Code restructure failed: missing block: B:315:0x032d, code lost:
    
        setResolveStatus(0);
     */
    /* JADX WARN: Removed duplicated region for block: B:137:0x059e A[Catch: all -> 0x0652, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x05aa A[Catch: all -> 0x0652, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:145:0x05b6 A[Catch: all -> 0x0652, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:148:0x05cb A[Catch: all -> 0x0652, TRY_ENTER, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:160:0x05c1 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0449 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x020b A[Catch: all -> 0x0652, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0423 A[Catch: all -> 0x0652, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0472  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x04a5 A[Catch: all -> 0x0652, TryCatch #0 {all -> 0x0652, blocks: (B:24:0x006a, B:26:0x006e, B:28:0x0078, B:31:0x008b, B:35:0x00a0, B:40:0x020b, B:41:0x0211, B:43:0x021c, B:256:0x0224, B:260:0x0238, B:262:0x0246, B:264:0x0279, B:267:0x0280, B:269:0x028d, B:271:0x0290, B:273:0x029a, B:277:0x02a6, B:278:0x02ac, B:280:0x02b4, B:281:0x02b9, B:283:0x02c1, B:284:0x02cb, B:288:0x02d4, B:289:0x02db, B:290:0x02dc, B:293:0x02e6, B:295:0x02ea, B:297:0x02f0, B:298:0x02f3, B:300:0x02f9, B:303:0x030a, B:309:0x0324, B:310:0x0331, B:313:0x0329, B:315:0x032d, B:317:0x024d, B:319:0x0253, B:323:0x0260, B:328:0x0268, B:50:0x0341, B:201:0x0347, B:205:0x034f, B:207:0x0359, B:209:0x036a, B:212:0x036f, B:214:0x0377, B:216:0x037b, B:218:0x0381, B:221:0x0386, B:223:0x038a, B:224:0x03d6, B:226:0x03de, B:229:0x03e7, B:230:0x0401, B:233:0x038d, B:235:0x0395, B:238:0x039a, B:239:0x03a7, B:242:0x03b0, B:246:0x03b6, B:248:0x03bc, B:249:0x03c9, B:251:0x0402, B:252:0x0420, B:54:0x0423, B:56:0x0427, B:58:0x042b, B:61:0x0431, B:65:0x0439, B:194:0x0449, B:196:0x0458, B:198:0x0463, B:199:0x046b, B:200:0x046e, B:80:0x049a, B:82:0x04a5, B:88:0x04ae, B:91:0x04be, B:92:0x04de, B:76:0x047e, B:78:0x0488, B:79:0x0497, B:93:0x048d, B:171:0x04e3, B:173:0x04ed, B:175:0x04f2, B:176:0x04f5, B:178:0x0500, B:179:0x0504, B:189:0x050f, B:181:0x0516, B:186:0x0520, B:187:0x0525, B:117:0x052a, B:119:0x052f, B:122:0x0538, B:124:0x0540, B:126:0x0555, B:128:0x0574, B:129:0x057a, B:132:0x0580, B:133:0x0586, B:135:0x058e, B:137:0x059e, B:140:0x05a6, B:142:0x05aa, B:143:0x05b1, B:145:0x05b6, B:146:0x05b9, B:161:0x05c1, B:148:0x05cb, B:155:0x05d5, B:152:0x05da, B:158:0x05df, B:159:0x05f9, B:167:0x0560, B:168:0x0567, B:103:0x05fa, B:113:0x060c, B:105:0x0613, B:110:0x061d, B:111:0x063d, B:338:0x00b3, B:339:0x00d1, B:412:0x00d6, B:414:0x00e1, B:416:0x00e5, B:418:0x00e9, B:421:0x00ef, B:344:0x00fe, B:346:0x0106, B:350:0x0119, B:351:0x0131, B:353:0x0132, B:354:0x0137, B:363:0x014c, B:365:0x0152, B:367:0x0159, B:368:0x0163, B:371:0x0171, B:375:0x017a, B:376:0x0192, B:377:0x016d, B:378:0x015e, B:380:0x0193, B:381:0x01ab, B:389:0x01b5, B:391:0x01bd, B:394:0x01d0, B:395:0x01f0, B:397:0x01f1, B:398:0x01f6, B:399:0x01f7, B:401:0x0201, B:403:0x063e, B:404:0x0645, B:406:0x0646, B:407:0x064b, B:409:0x064c, B:410:0x0651), top: B:23:0x006a, inners: #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x04aa A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object parseObject(java.util.Map r14, java.lang.Object r15) {
        /*
            Method dump skipped, instructions count: 1623
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.DefaultJSONParser.parseObject(java.util.Map, java.lang.Object):java.lang.Object");
    }

    public void popContext() {
        if (this.lexer.isEnabled(Feature.DisableCircularReferenceDetect)) {
            return;
        }
        this.context = this.context.parent;
        int i2 = this.contextArrayIndex;
        if (i2 <= 0) {
            return;
        }
        int i3 = i2 - 1;
        this.contextArrayIndex = i3;
        this.contextArray[i3] = null;
    }

    public Object resolveReference(String str) {
        if (this.contextArray == null) {
            return null;
        }
        int i2 = 0;
        while (true) {
            ParseContext[] parseContextArr = this.contextArray;
            if (i2 >= parseContextArr.length || i2 >= this.contextArrayIndex) {
                break;
            }
            ParseContext parseContext = parseContextArr[i2];
            if (parseContext.toString().equals(str)) {
                return parseContext.object;
            }
            i2++;
        }
        return null;
    }

    public void setConfig(ParserConfig parserConfig) {
        this.config = parserConfig;
    }

    public void setContext(ParseContext parseContext) {
        if (this.lexer.isEnabled(Feature.DisableCircularReferenceDetect)) {
            return;
        }
        this.context = parseContext;
    }

    public void setDateFomrat(DateFormat dateFormat) {
        this.dateFormat = dateFormat;
    }

    public void setDateFormat(String str) {
        this.dateFormatPattern = str;
        this.dateFormat = null;
    }

    public void setFieldTypeResolver(FieldTypeResolver fieldTypeResolver) {
        this.fieldTypeResolver = fieldTypeResolver;
    }

    public void setResolveStatus(int i2) {
        this.resolveStatus = i2;
    }

    public void throwException(int i2) {
        StringBuilder m586H = C1499a.m586H("syntax error, expect ");
        m586H.append(JSONToken.name(i2));
        m586H.append(", actual ");
        m586H.append(JSONToken.name(this.lexer.token()));
        throw new JSONException(m586H.toString());
    }

    public DefaultJSONParser(String str, ParserConfig parserConfig) {
        this(str, new JSONScanner(str, JSON.DEFAULT_PARSER_FEATURE), parserConfig);
    }

    public Object parse(Object obj) {
        JSONLexer jSONLexer = this.lexer;
        int i2 = jSONLexer.token();
        if (i2 == 2) {
            Number integerValue = jSONLexer.integerValue();
            jSONLexer.nextToken();
            return integerValue;
        }
        if (i2 == 3) {
            Number decimalValue = jSONLexer.decimalValue(jSONLexer.isEnabled(Feature.UseBigDecimal));
            jSONLexer.nextToken();
            return decimalValue;
        }
        if (i2 == 4) {
            String stringVal = jSONLexer.stringVal();
            jSONLexer.nextToken(16);
            if (jSONLexer.isEnabled(Feature.AllowISO8601DateFormat)) {
                JSONScanner jSONScanner = new JSONScanner(stringVal);
                try {
                    if (jSONScanner.scanISO8601DateIfMatch()) {
                        return jSONScanner.getCalendar().getTime();
                    }
                } finally {
                    jSONScanner.close();
                }
            }
            return stringVal;
        }
        if (i2 == 12) {
            return parseObject(new JSONObject(jSONLexer.isEnabled(Feature.OrderedField)), obj);
        }
        if (i2 == 14) {
            JSONArray jSONArray = new JSONArray();
            parseArray(jSONArray, obj);
            return jSONLexer.isEnabled(Feature.UseObjectArray) ? jSONArray.toArray() : jSONArray;
        }
        if (i2 == 18) {
            if ("NaN".equals(jSONLexer.stringVal())) {
                jSONLexer.nextToken();
                return null;
            }
            StringBuilder m586H = C1499a.m586H("syntax error, ");
            m586H.append(jSONLexer.info());
            throw new JSONException(m586H.toString());
        }
        if (i2 == 26) {
            byte[] bytesValue = jSONLexer.bytesValue();
            jSONLexer.nextToken();
            return bytesValue;
        }
        switch (i2) {
            case 6:
                jSONLexer.nextToken();
                return Boolean.TRUE;
            case 7:
                jSONLexer.nextToken();
                return Boolean.FALSE;
            case 8:
                jSONLexer.nextToken();
                return null;
            case 9:
                jSONLexer.nextToken(18);
                if (jSONLexer.token() != 18) {
                    throw new JSONException("syntax error");
                }
                jSONLexer.nextToken(10);
                accept(10);
                long longValue = jSONLexer.integerValue().longValue();
                accept(2);
                accept(11);
                return new Date(longValue);
            default:
                switch (i2) {
                    case 20:
                        if (jSONLexer.isBlankInput()) {
                            return null;
                        }
                        StringBuilder m586H2 = C1499a.m586H("unterminated json string, ");
                        m586H2.append(jSONLexer.info());
                        throw new JSONException(m586H2.toString());
                    case 21:
                        jSONLexer.nextToken();
                        HashSet hashSet = new HashSet();
                        parseArray(hashSet, obj);
                        return hashSet;
                    case 22:
                        jSONLexer.nextToken();
                        TreeSet treeSet = new TreeSet();
                        parseArray(treeSet, obj);
                        return treeSet;
                    case 23:
                        jSONLexer.nextToken();
                        return null;
                    default:
                        StringBuilder m586H3 = C1499a.m586H("syntax error, ");
                        m586H3.append(jSONLexer.info());
                        throw new JSONException(m586H3.toString());
                }
        }
    }

    public DefaultJSONParser(String str, ParserConfig parserConfig, int i2) {
        this(str, new JSONScanner(str, i2), parserConfig);
    }

    public void parseArray(Class<?> cls, Collection collection) {
        parseArray((Type) cls, collection);
    }

    public ParseContext setContext(Object obj, Object obj2) {
        if (this.lexer.isEnabled(Feature.DisableCircularReferenceDetect)) {
            return null;
        }
        return setContext(this.context, obj, obj2);
    }

    public DefaultJSONParser(char[] cArr, int i2, ParserConfig parserConfig, int i3) {
        this(cArr, new JSONScanner(cArr, i2, i3), parserConfig);
    }

    public void parseArray(Type type, Collection collection) {
        parseArray(type, collection, null);
    }

    public DefaultJSONParser(JSONLexer jSONLexer) {
        this(jSONLexer, ParserConfig.getGlobalInstance());
    }

    public void parseArray(Type type, Collection collection, Object obj) {
        ObjectDeserializer deserializer;
        int i2 = this.lexer.token();
        if (i2 == 21 || i2 == 22) {
            this.lexer.nextToken();
            i2 = this.lexer.token();
        }
        if (i2 == 14) {
            if (Integer.TYPE != type) {
                if (String.class == type) {
                    deserializer = StringCodec.instance;
                    this.lexer.nextToken(4);
                } else {
                    deserializer = this.config.getDeserializer(type);
                    this.lexer.nextToken(deserializer.getFastMatchToken());
                }
            } else {
                deserializer = IntegerCodec.instance;
                this.lexer.nextToken(2);
            }
            ParseContext parseContext = this.context;
            setContext(collection, obj);
            int i3 = 0;
            while (true) {
                try {
                    if (this.lexer.isEnabled(Feature.AllowArbitraryCommas)) {
                        while (this.lexer.token() == 16) {
                            this.lexer.nextToken();
                        }
                    }
                    if (this.lexer.token() == 15) {
                        setContext(parseContext);
                        this.lexer.nextToken(16);
                        return;
                    }
                    Object obj2 = null;
                    if (Integer.TYPE != type) {
                        if (String.class == type) {
                            if (this.lexer.token() == 4) {
                                obj2 = this.lexer.stringVal();
                                this.lexer.nextToken(16);
                            } else {
                                Object parse = parse();
                                if (parse != null) {
                                    obj2 = parse.toString();
                                }
                            }
                            collection.add(obj2);
                        } else {
                            if (this.lexer.token() == 8) {
                                this.lexer.nextToken();
                            } else {
                                obj2 = deserializer.deserialze(this, type, Integer.valueOf(i3));
                            }
                            collection.add(obj2);
                            checkListResolve(collection);
                        }
                    } else {
                        collection.add(IntegerCodec.instance.deserialze(this, null, null));
                    }
                    if (this.lexer.token() == 16) {
                        this.lexer.nextToken(deserializer.getFastMatchToken());
                    }
                    i3++;
                } catch (Throwable th) {
                    setContext(parseContext);
                    throw th;
                }
            }
        } else {
            StringBuilder m586H = C1499a.m586H("expect '[', but ");
            m586H.append(JSONToken.name(i2));
            m586H.append(", ");
            m586H.append(this.lexer.info());
            throw new JSONException(m586H.toString());
        }
    }

    public ParseContext setContext(ParseContext parseContext, Object obj, Object obj2) {
        if (this.lexer.isEnabled(Feature.DisableCircularReferenceDetect)) {
            return null;
        }
        ParseContext parseContext2 = new ParseContext(parseContext, obj, obj2);
        this.context = parseContext2;
        addContext(parseContext2);
        return this.context;
    }

    public DefaultJSONParser(JSONLexer jSONLexer, ParserConfig parserConfig) {
        this((Object) null, jSONLexer, parserConfig);
    }

    public final void accept(int i2, int i3) {
        JSONLexer jSONLexer = this.lexer;
        if (jSONLexer.token() == i2) {
            jSONLexer.nextToken(i3);
        } else {
            throwException(i2);
        }
    }

    public DefaultJSONParser(Object obj, JSONLexer jSONLexer, ParserConfig parserConfig) {
        this.dateFormatPattern = JSON.DEFFAULT_DATE_FORMAT;
        this.contextArrayIndex = 0;
        this.resolveStatus = 0;
        this.extraTypeProviders = null;
        this.extraProcessors = null;
        this.fieldTypeResolver = null;
        this.objectKeyLevel = 0;
        this.autoTypeAccept = null;
        this.lexer = jSONLexer;
        this.input = obj;
        this.config = parserConfig;
        this.symbolTable = parserConfig.symbolTable;
        char current = jSONLexer.getCurrent();
        if (current == '{') {
            jSONLexer.next();
            ((JSONLexerBase) jSONLexer).token = 12;
        } else if (current == '[') {
            jSONLexer.next();
            ((JSONLexerBase) jSONLexer).token = 14;
        } else {
            jSONLexer.nextToken();
        }
    }

    public Object[] parseArray(Type[] typeArr) {
        Object cast;
        boolean z;
        Class<?> cls;
        Class cls2;
        int i2 = 8;
        if (this.lexer.token() == 8) {
            this.lexer.nextToken(16);
            return null;
        }
        int i3 = 14;
        if (this.lexer.token() == 14) {
            Object[] objArr = new Object[typeArr.length];
            if (typeArr.length == 0) {
                this.lexer.nextToken(15);
                if (this.lexer.token() == 15) {
                    this.lexer.nextToken(16);
                    return new Object[0];
                }
                throw new JSONException("syntax error");
            }
            this.lexer.nextToken(2);
            int i4 = 0;
            while (i4 < typeArr.length) {
                if (this.lexer.token() == i2) {
                    this.lexer.nextToken(16);
                    cast = null;
                } else {
                    Type type = typeArr[i4];
                    if (type != Integer.TYPE && type != Integer.class) {
                        if (type == String.class) {
                            if (this.lexer.token() == 4) {
                                cast = this.lexer.stringVal();
                                this.lexer.nextToken(16);
                            } else {
                                cast = TypeUtils.cast(parse(), type, this.config);
                            }
                        } else {
                            if (i4 == typeArr.length - 1 && (type instanceof Class) && (((cls2 = (Class) type) != byte[].class && cls2 != char[].class) || this.lexer.token() != 4)) {
                                z = cls2.isArray();
                                cls = cls2.getComponentType();
                            } else {
                                z = false;
                                cls = null;
                            }
                            if (z && this.lexer.token() != i3) {
                                ArrayList arrayList = new ArrayList();
                                ObjectDeserializer deserializer = this.config.getDeserializer(cls);
                                int fastMatchToken = deserializer.getFastMatchToken();
                                if (this.lexer.token() != 15) {
                                    while (true) {
                                        arrayList.add(deserializer.deserialze(this, type, null));
                                        if (this.lexer.token() != 16) {
                                            break;
                                        }
                                        this.lexer.nextToken(fastMatchToken);
                                    }
                                    if (this.lexer.token() != 15) {
                                        StringBuilder m586H = C1499a.m586H("syntax error :");
                                        m586H.append(JSONToken.name(this.lexer.token()));
                                        throw new JSONException(m586H.toString());
                                    }
                                }
                                cast = TypeUtils.cast(arrayList, type, this.config);
                            } else {
                                cast = this.config.getDeserializer(type).deserialze(this, type, Integer.valueOf(i4));
                            }
                        }
                    } else if (this.lexer.token() == 2) {
                        cast = Integer.valueOf(this.lexer.intValue());
                        this.lexer.nextToken(16);
                    } else {
                        cast = TypeUtils.cast(parse(), type, this.config);
                    }
                }
                objArr[i4] = cast;
                if (this.lexer.token() == 15) {
                    break;
                }
                if (this.lexer.token() == 16) {
                    if (i4 == typeArr.length - 1) {
                        this.lexer.nextToken(15);
                    } else {
                        this.lexer.nextToken(2);
                    }
                    i4++;
                    i2 = 8;
                    i3 = 14;
                } else {
                    StringBuilder m586H2 = C1499a.m586H("syntax error :");
                    m586H2.append(JSONToken.name(this.lexer.token()));
                    throw new JSONException(m586H2.toString());
                }
            }
            if (this.lexer.token() == 15) {
                this.lexer.nextToken(16);
                return objArr;
            }
            throw new JSONException("syntax error");
        }
        StringBuilder m586H3 = C1499a.m586H("syntax error : ");
        m586H3.append(this.lexer.tokenName());
        throw new JSONException(m586H3.toString());
    }

    /* JADX WARN: Code restructure failed: missing block: B:70:0x020d, code lost:
    
        return r11;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object parse(com.alibaba.fastjson.parser.deserializer.PropertyProcessable r11, java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 572
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.DefaultJSONParser.parse(com.alibaba.fastjson.parser.deserializer.PropertyProcessable, java.lang.Object):java.lang.Object");
    }

    public final void parseArray(Collection collection) {
        parseArray(collection, (Object) null);
    }

    public final void parseArray(Collection collection, Object obj) {
        Number decimalValue;
        JSONLexer jSONLexer = this.lexer;
        if (jSONLexer.token() == 21 || jSONLexer.token() == 22) {
            jSONLexer.nextToken();
        }
        if (jSONLexer.token() == 14) {
            jSONLexer.nextToken(4);
            ParseContext parseContext = this.context;
            if (parseContext != null && parseContext.level > 512) {
                throw new JSONException("array level > 512");
            }
            setContext(collection, obj);
            int i2 = 0;
            while (true) {
                try {
                    if (jSONLexer.isEnabled(Feature.AllowArbitraryCommas)) {
                        while (jSONLexer.token() == 16) {
                            jSONLexer.nextToken();
                        }
                    }
                    int i3 = jSONLexer.token();
                    Object obj2 = null;
                    obj2 = null;
                    if (i3 == 2) {
                        Number integerValue = jSONLexer.integerValue();
                        jSONLexer.nextToken(16);
                        obj2 = integerValue;
                    } else if (i3 == 3) {
                        if (jSONLexer.isEnabled(Feature.UseBigDecimal)) {
                            decimalValue = jSONLexer.decimalValue(true);
                        } else {
                            decimalValue = jSONLexer.decimalValue(false);
                        }
                        obj2 = decimalValue;
                        jSONLexer.nextToken(16);
                    } else if (i3 == 4) {
                        String stringVal = jSONLexer.stringVal();
                        jSONLexer.nextToken(16);
                        obj2 = stringVal;
                        if (jSONLexer.isEnabled(Feature.AllowISO8601DateFormat)) {
                            JSONScanner jSONScanner = new JSONScanner(stringVal);
                            Object obj3 = stringVal;
                            if (jSONScanner.scanISO8601DateIfMatch()) {
                                obj3 = jSONScanner.getCalendar().getTime();
                            }
                            jSONScanner.close();
                            obj2 = obj3;
                        }
                    } else if (i3 == 6) {
                        Boolean bool = Boolean.TRUE;
                        jSONLexer.nextToken(16);
                        obj2 = bool;
                    } else if (i3 == 7) {
                        Boolean bool2 = Boolean.FALSE;
                        jSONLexer.nextToken(16);
                        obj2 = bool2;
                    } else if (i3 == 8) {
                        jSONLexer.nextToken(4);
                    } else if (i3 == 12) {
                        obj2 = parseObject(new JSONObject(jSONLexer.isEnabled(Feature.OrderedField)), Integer.valueOf(i2));
                    } else {
                        if (i3 == 20) {
                            throw new JSONException("unclosed jsonArray");
                        }
                        if (i3 == 23) {
                            jSONLexer.nextToken(4);
                        } else if (i3 == 14) {
                            JSONArray jSONArray = new JSONArray();
                            parseArray(jSONArray, Integer.valueOf(i2));
                            obj2 = jSONArray;
                            if (jSONLexer.isEnabled(Feature.UseObjectArray)) {
                                obj2 = jSONArray.toArray();
                            }
                        } else if (i3 != 15) {
                            obj2 = parse();
                        } else {
                            jSONLexer.nextToken(16);
                            return;
                        }
                    }
                    collection.add(obj2);
                    checkListResolve(collection);
                    if (jSONLexer.token() == 16) {
                        jSONLexer.nextToken(4);
                    }
                    i2++;
                } finally {
                    setContext(parseContext);
                }
            }
        } else {
            StringBuilder m586H = C1499a.m586H("syntax error, expect [, actual ");
            m586H.append(JSONToken.name(jSONLexer.token()));
            m586H.append(", pos ");
            m586H.append(jSONLexer.pos());
            m586H.append(", fieldName ");
            m586H.append(obj);
            throw new JSONException(m586H.toString());
        }
    }

    public <T> T parseObject(Class<T> cls) {
        return (T) parseObject(cls, (Object) null);
    }

    public <T> T parseObject(Type type) {
        return (T) parseObject(type, (Object) null);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public <T> T parseObject(Type type, Object obj) {
        int i2 = this.lexer.token();
        if (i2 == 8) {
            this.lexer.nextToken();
            return null;
        }
        if (i2 == 4) {
            if (type == byte[].class) {
                T t = (T) this.lexer.bytesValue();
                this.lexer.nextToken();
                return t;
            }
            if (type == char[].class) {
                String stringVal = this.lexer.stringVal();
                this.lexer.nextToken();
                return (T) stringVal.toCharArray();
            }
        }
        ObjectDeserializer deserializer = this.config.getDeserializer(type);
        try {
            if (deserializer.getClass() == JavaBeanDeserializer.class) {
                if (this.lexer.token() != 12 && this.lexer.token() != 14) {
                    throw new JSONException("syntax error,except start with { or [,but actually start with " + this.lexer.tokenName());
                }
                return (T) ((JavaBeanDeserializer) deserializer).deserialze(this, type, obj, 0);
            }
            return (T) deserializer.deserialze(this, type, obj);
        } catch (JSONException e2) {
            throw e2;
        } catch (Throwable th) {
            throw new JSONException(th.getMessage(), th);
        }
    }

    public void parseObject(Object obj) {
        Object deserialze;
        Class<?> cls = obj.getClass();
        ObjectDeserializer deserializer = this.config.getDeserializer(cls);
        JavaBeanDeserializer javaBeanDeserializer = deserializer instanceof JavaBeanDeserializer ? (JavaBeanDeserializer) deserializer : null;
        if (this.lexer.token() != 12 && this.lexer.token() != 16) {
            StringBuilder m586H = C1499a.m586H("syntax error, expect {, actual ");
            m586H.append(this.lexer.tokenName());
            throw new JSONException(m586H.toString());
        }
        while (true) {
            String scanSymbol = this.lexer.scanSymbol(this.symbolTable);
            if (scanSymbol == null) {
                if (this.lexer.token() == 13) {
                    this.lexer.nextToken(16);
                    return;
                } else if (this.lexer.token() == 16 && this.lexer.isEnabled(Feature.AllowArbitraryCommas)) {
                }
            }
            FieldDeserializer fieldDeserializer = javaBeanDeserializer != null ? javaBeanDeserializer.getFieldDeserializer(scanSymbol) : null;
            if (fieldDeserializer == null) {
                if (this.lexer.isEnabled(Feature.IgnoreNotMatch)) {
                    this.lexer.nextTokenWithColon();
                    parse();
                    if (this.lexer.token() == 13) {
                        this.lexer.nextToken();
                        return;
                    }
                } else {
                    StringBuilder m586H2 = C1499a.m586H("setter not found, class ");
                    m586H2.append(cls.getName());
                    m586H2.append(", property ");
                    m586H2.append(scanSymbol);
                    throw new JSONException(m586H2.toString());
                }
            } else {
                FieldInfo fieldInfo = fieldDeserializer.fieldInfo;
                Class<?> cls2 = fieldInfo.fieldClass;
                Type type = fieldInfo.fieldType;
                if (cls2 == Integer.TYPE) {
                    this.lexer.nextTokenWithColon(2);
                    deserialze = IntegerCodec.instance.deserialze(this, type, null);
                } else if (cls2 == String.class) {
                    this.lexer.nextTokenWithColon(4);
                    deserialze = StringCodec.deserialze(this);
                } else if (cls2 == Long.TYPE) {
                    this.lexer.nextTokenWithColon(2);
                    deserialze = LongCodec.instance.deserialze(this, type, null);
                } else {
                    ObjectDeserializer deserializer2 = this.config.getDeserializer(cls2, type);
                    this.lexer.nextTokenWithColon(deserializer2.getFastMatchToken());
                    deserialze = deserializer2.deserialze(this, type, null);
                }
                fieldDeserializer.setValue(obj, deserialze);
                if (this.lexer.token() != 16 && this.lexer.token() == 13) {
                    this.lexer.nextToken(16);
                    return;
                }
            }
        }
    }

    public Object parseObject(Map map) {
        return parseObject(map, (Object) null);
    }

    public JSONObject parseObject() {
        Object parseObject = parseObject((Map) new JSONObject(this.lexer.isEnabled(Feature.OrderedField)));
        if (parseObject instanceof JSONObject) {
            return (JSONObject) parseObject;
        }
        if (parseObject == null) {
            return null;
        }
        return new JSONObject((Map<String, Object>) parseObject);
    }
}
