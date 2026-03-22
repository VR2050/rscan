package com.alibaba.fastjson;

import com.alibaba.fastjson.parser.DefaultJSONParser;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.parser.JSONLexerBase;
import com.alibaba.fastjson.parser.ParserConfig;
import com.alibaba.fastjson.parser.deserializer.FieldDeserializer;
import com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer;
import com.alibaba.fastjson.parser.deserializer.ObjectDeserializer;
import com.alibaba.fastjson.serializer.FieldSerializer;
import com.alibaba.fastjson.serializer.JavaBeanSerializer;
import com.alibaba.fastjson.serializer.ObjectSerializer;
import com.alibaba.fastjson.serializer.SerializeConfig;
import com.alibaba.fastjson.util.FieldInfo;
import com.alibaba.fastjson.util.TypeUtils;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class JSONPath implements JSONAware {
    public static final long LENGTH = -1580386065683472715L;
    public static final long SIZE = 5614464919154503228L;
    private static ConcurrentMap<String, JSONPath> pathCache = new ConcurrentHashMap(128, 0.75f, 1);
    private boolean hasRefSegment;
    private ParserConfig parserConfig;
    private final String path;
    private Segment[] segments;
    private SerializeConfig serializeConfig;

    /* renamed from: com.alibaba.fastjson.JSONPath$1 */
    public static /* synthetic */ class C31221 {
        public static final /* synthetic */ int[] $SwitchMap$com$alibaba$fastjson$JSONPath$Operator;

        static {
            Operator.values();
            int[] iArr = new int[17];
            $SwitchMap$com$alibaba$fastjson$JSONPath$Operator = iArr;
            try {
                iArr[Operator.EQ.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$JSONPath$Operator[Operator.NE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$JSONPath$Operator[Operator.GE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$JSONPath$Operator[Operator.GT.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$JSONPath$Operator[Operator.LE.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$alibaba$fastjson$JSONPath$Operator[Operator.LT.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    public static class ArrayAccessSegment implements Segment {
        private final int index;

        public ArrayAccessSegment(int i2) {
            this.index = i2;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            return jSONPath.getArrayItem(obj2, this.index);
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            if (((JSONLexerBase) defaultJSONParser.lexer).seekArrayToItem(this.index) && context.eval) {
                context.object = defaultJSONParser.parse();
            }
        }

        public boolean remove(JSONPath jSONPath, Object obj) {
            return jSONPath.removeArrayItem(jSONPath, obj, this.index);
        }

        public boolean setValue(JSONPath jSONPath, Object obj, Object obj2) {
            return jSONPath.setArrayItem(jSONPath, obj, this.index, obj2);
        }
    }

    public static class Context {
        public final boolean eval;
        public Object object;
        public final Context parent;

        public Context(Context context, boolean z) {
            this.parent = context;
            this.eval = z;
        }
    }

    public static class DoubleOpSegement implements Filter {

        /* renamed from: op */
        private final Operator f8486op;
        private final String propertyName;
        private final long propertyNameHash;
        private final double value;

        public DoubleOpSegement(String str, double d2, Operator operator) {
            this.propertyName = str;
            this.value = d2;
            this.f8486op = operator;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null || !(propertyValue instanceof Number)) {
                return false;
            }
            double doubleValue = ((Number) propertyValue).doubleValue();
            int ordinal = this.f8486op.ordinal();
            return ordinal != 0 ? ordinal != 1 ? ordinal != 2 ? ordinal != 3 ? ordinal != 4 ? ordinal == 5 && doubleValue <= this.value : doubleValue < this.value : doubleValue >= this.value : doubleValue > this.value : doubleValue != this.value : doubleValue == this.value;
        }
    }

    public interface Filter {
        boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3);
    }

    public static class FilterGroup implements Filter {
        private boolean and;
        private List<Filter> fitlers;

        public FilterGroup(Filter filter, Filter filter2, boolean z) {
            ArrayList arrayList = new ArrayList(2);
            this.fitlers = arrayList;
            arrayList.add(filter);
            this.fitlers.add(filter2);
            this.and = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            if (this.and) {
                Iterator<Filter> it = this.fitlers.iterator();
                while (it.hasNext()) {
                    if (!it.next().apply(jSONPath, obj, obj2, obj3)) {
                        return false;
                    }
                }
                return true;
            }
            Iterator<Filter> it2 = this.fitlers.iterator();
            while (it2.hasNext()) {
                if (it2.next().apply(jSONPath, obj, obj2, obj3)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class FilterSegment implements Segment {
        private final Filter filter;

        public FilterSegment(Filter filter) {
            this.filter = filter;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            if (obj2 == null) {
                return null;
            }
            JSONArray jSONArray = new JSONArray();
            if (!(obj2 instanceof Iterable)) {
                if (this.filter.apply(jSONPath, obj, obj2, obj2)) {
                    return obj2;
                }
                return null;
            }
            for (Object obj3 : (Iterable) obj2) {
                if (this.filter.apply(jSONPath, obj, obj2, obj3)) {
                    jSONArray.add(obj3);
                }
            }
            return jSONArray;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            throw new UnsupportedOperationException();
        }

        public boolean remove(JSONPath jSONPath, Object obj, Object obj2) {
            if (obj2 == null || !(obj2 instanceof Iterable)) {
                return false;
            }
            Iterator it = ((Iterable) obj2).iterator();
            while (it.hasNext()) {
                if (this.filter.apply(jSONPath, obj, obj2, it.next())) {
                    it.remove();
                }
            }
            return true;
        }
    }

    public static class IntBetweenSegement implements Filter {
        private final long endValue;
        private final boolean not;
        private final String propertyName;
        private final long propertyNameHash;
        private final long startValue;

        public IntBetweenSegement(String str, long j2, long j3, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.startValue = j2;
            this.endValue = j3;
            this.not = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null) {
                return false;
            }
            if (propertyValue instanceof Number) {
                long longExtractValue = TypeUtils.longExtractValue((Number) propertyValue);
                if (longExtractValue >= this.startValue && longExtractValue <= this.endValue) {
                    return !this.not;
                }
            }
            return this.not;
        }
    }

    public static class IntInSegement implements Filter {
        private final boolean not;
        private final String propertyName;
        private final long propertyNameHash;
        private final long[] values;

        public IntInSegement(String str, long[] jArr, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.values = jArr;
            this.not = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null) {
                return false;
            }
            if (propertyValue instanceof Number) {
                long longExtractValue = TypeUtils.longExtractValue((Number) propertyValue);
                for (long j2 : this.values) {
                    if (j2 == longExtractValue) {
                        return !this.not;
                    }
                }
            }
            return this.not;
        }
    }

    public static class IntObjInSegement implements Filter {
        private final boolean not;
        private final String propertyName;
        private final long propertyNameHash;
        private final Long[] values;

        public IntObjInSegement(String str, Long[] lArr, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.values = lArr;
            this.not = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            int i2 = 0;
            if (propertyValue == null) {
                Long[] lArr = this.values;
                int length = lArr.length;
                while (i2 < length) {
                    if (lArr[i2] == null) {
                        return !this.not;
                    }
                    i2++;
                }
                return this.not;
            }
            if (propertyValue instanceof Number) {
                long longExtractValue = TypeUtils.longExtractValue((Number) propertyValue);
                Long[] lArr2 = this.values;
                int length2 = lArr2.length;
                while (i2 < length2) {
                    Long l2 = lArr2[i2];
                    if (l2 != null && l2.longValue() == longExtractValue) {
                        return !this.not;
                    }
                    i2++;
                }
            }
            return this.not;
        }
    }

    public static class IntOpSegement implements Filter {

        /* renamed from: op */
        private final Operator f8487op;
        private final String propertyName;
        private final long propertyNameHash;
        private final long value;
        private BigDecimal valueDecimal;
        private Double valueDouble;
        private Float valueFloat;

        public IntOpSegement(String str, long j2, Operator operator) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.value = j2;
            this.f8487op = operator;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null || !(propertyValue instanceof Number)) {
                return false;
            }
            if (propertyValue instanceof BigDecimal) {
                if (this.valueDecimal == null) {
                    this.valueDecimal = BigDecimal.valueOf(this.value);
                }
                int compareTo = this.valueDecimal.compareTo((BigDecimal) propertyValue);
                int ordinal = this.f8487op.ordinal();
                return ordinal != 0 ? ordinal != 1 ? ordinal != 2 ? ordinal != 3 ? ordinal != 4 ? ordinal == 5 && compareTo >= 0 : compareTo > 0 : compareTo <= 0 : compareTo < 0 : compareTo != 0 : compareTo == 0;
            }
            if (propertyValue instanceof Float) {
                if (this.valueFloat == null) {
                    this.valueFloat = Float.valueOf(this.value);
                }
                int compareTo2 = this.valueFloat.compareTo((Float) propertyValue);
                int ordinal2 = this.f8487op.ordinal();
                return ordinal2 != 0 ? ordinal2 != 1 ? ordinal2 != 2 ? ordinal2 != 3 ? ordinal2 != 4 ? ordinal2 == 5 && compareTo2 >= 0 : compareTo2 > 0 : compareTo2 <= 0 : compareTo2 < 0 : compareTo2 != 0 : compareTo2 == 0;
            }
            if (!(propertyValue instanceof Double)) {
                long longExtractValue = TypeUtils.longExtractValue((Number) propertyValue);
                int ordinal3 = this.f8487op.ordinal();
                return ordinal3 != 0 ? ordinal3 != 1 ? ordinal3 != 2 ? ordinal3 != 3 ? ordinal3 != 4 ? ordinal3 == 5 && longExtractValue <= this.value : longExtractValue < this.value : longExtractValue >= this.value : longExtractValue > this.value : longExtractValue != this.value : longExtractValue == this.value;
            }
            if (this.valueDouble == null) {
                this.valueDouble = Double.valueOf(this.value);
            }
            int compareTo3 = this.valueDouble.compareTo((Double) propertyValue);
            int ordinal4 = this.f8487op.ordinal();
            return ordinal4 != 0 ? ordinal4 != 1 ? ordinal4 != 2 ? ordinal4 != 3 ? ordinal4 != 4 ? ordinal4 == 5 && compareTo3 >= 0 : compareTo3 > 0 : compareTo3 <= 0 : compareTo3 < 0 : compareTo3 != 0 : compareTo3 == 0;
        }
    }

    public static class JSONPathParser {

        /* renamed from: ch */
        private char f8488ch;
        private boolean hasRefSegment;
        private int level;
        private final String path;
        private int pos;
        private static final String strArrayRegex = "'\\s*,\\s*'";
        private static final Pattern strArrayPatternx = Pattern.compile(strArrayRegex);

        public JSONPathParser(String str) {
            this.path = str;
            next();
        }

        public static boolean isDigitFirst(char c2) {
            return c2 == '-' || c2 == '+' || (c2 >= '0' && c2 <= '9');
        }

        public void accept(char c2) {
            if (this.f8488ch == c2) {
                if (isEOF()) {
                    return;
                }
                next();
            } else {
                throw new JSONPathException("expect '" + c2 + ", but '" + this.f8488ch + "'");
            }
        }

        public Segment buildArraySegement(String str) {
            int length = str.length();
            char charAt = str.charAt(0);
            int i2 = length - 1;
            char charAt2 = str.charAt(i2);
            int indexOf = str.indexOf(44);
            if (str.length() > 2 && charAt == '\'' && charAt2 == '\'') {
                String substring = str.substring(1, i2);
                return (indexOf == -1 || !strArrayPatternx.matcher(str).find()) ? new PropertySegment(substring, false) : new MultiPropertySegment(substring.split(strArrayRegex));
            }
            int indexOf2 = str.indexOf(58);
            if (indexOf == -1 && indexOf2 == -1) {
                if (TypeUtils.isNumber(str)) {
                    try {
                        return new ArrayAccessSegment(Integer.parseInt(str));
                    } catch (NumberFormatException unused) {
                        return new PropertySegment(str, false);
                    }
                }
                if (str.charAt(0) == '\"' && str.charAt(str.length() - 1) == '\"') {
                    str = str.substring(1, str.length() - 1);
                }
                return new PropertySegment(str, false);
            }
            if (indexOf != -1) {
                String[] split = str.split(ChineseToPinyinResource.Field.COMMA);
                int[] iArr = new int[split.length];
                for (int i3 = 0; i3 < split.length; i3++) {
                    iArr[i3] = Integer.parseInt(split[i3]);
                }
                return new MultiIndexSegment(iArr);
            }
            if (indexOf2 == -1) {
                throw new UnsupportedOperationException();
            }
            String[] split2 = str.split(":");
            int length2 = split2.length;
            int[] iArr2 = new int[length2];
            for (int i4 = 0; i4 < split2.length; i4++) {
                String str2 = split2[i4];
                if (str2.length() != 0) {
                    iArr2[i4] = Integer.parseInt(str2);
                } else {
                    if (i4 != 0) {
                        throw new UnsupportedOperationException();
                    }
                    iArr2[i4] = 0;
                }
            }
            int i5 = iArr2[0];
            int i6 = length2 > 1 ? iArr2[1] : -1;
            int i7 = length2 == 3 ? iArr2[2] : 1;
            if (i6 >= 0 && i6 < i5) {
                throw new UnsupportedOperationException(C1499a.m629o("end must greater than or equals start. start ", i5, ",  end ", i6));
            }
            if (i7 > 0) {
                return new RangeSegment(i5, i6, i7);
            }
            throw new UnsupportedOperationException(C1499a.m626l("step must greater than zero : ", i7));
        }

        public Segment[] explain() {
            String str = this.path;
            if (str == null || str.length() == 0) {
                throw new IllegalArgumentException();
            }
            Segment[] segmentArr = new Segment[8];
            while (true) {
                Segment readSegement = readSegement();
                if (readSegement == null) {
                    break;
                }
                if (readSegement instanceof PropertySegment) {
                    PropertySegment propertySegment = (PropertySegment) readSegement;
                    if (!propertySegment.deep && propertySegment.propertyName.equals("*")) {
                    }
                }
                int i2 = this.level;
                if (i2 == segmentArr.length) {
                    Segment[] segmentArr2 = new Segment[(i2 * 3) / 2];
                    System.arraycopy(segmentArr, 0, segmentArr2, 0, i2);
                    segmentArr = segmentArr2;
                }
                int i3 = this.level;
                this.level = i3 + 1;
                segmentArr[i3] = readSegement;
            }
            int i4 = this.level;
            if (i4 == segmentArr.length) {
                return segmentArr;
            }
            Segment[] segmentArr3 = new Segment[i4];
            System.arraycopy(segmentArr, 0, segmentArr3, 0, i4);
            return segmentArr3;
        }

        public Filter filterRest(Filter filter) {
            char c2 = this.f8488ch;
            boolean z = true;
            boolean z2 = c2 == '&';
            if ((c2 != '&' || getNextChar() != '&') && (this.f8488ch != '|' || getNextChar() != '|')) {
                return filter;
            }
            next();
            next();
            if (this.f8488ch == '(') {
                next();
            } else {
                z = false;
            }
            while (this.f8488ch == ' ') {
                next();
            }
            FilterGroup filterGroup = new FilterGroup(filter, (Filter) parseArrayAccessFilter(false), z2);
            if (z && this.f8488ch == ')') {
                next();
            }
            return filterGroup;
        }

        public char getNextChar() {
            return this.path.charAt(this.pos);
        }

        public boolean isEOF() {
            return this.pos >= this.path.length();
        }

        public void next() {
            String str = this.path;
            int i2 = this.pos;
            this.pos = i2 + 1;
            this.f8488ch = str.charAt(i2);
        }

        public Segment parseArrayAccess(boolean z) {
            Object parseArrayAccessFilter = parseArrayAccessFilter(z);
            return parseArrayAccessFilter instanceof Segment ? (Segment) parseArrayAccessFilter : new FilterSegment((Filter) parseArrayAccessFilter);
        }

        /* JADX WARN: Code restructure failed: missing block: B:34:0x0077, code lost:
        
            r3 = r21.pos;
         */
        /* JADX WARN: Removed duplicated region for block: B:38:0x0095  */
        /* JADX WARN: Removed duplicated region for block: B:52:0x00d3  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Object parseArrayAccessFilter(boolean r22) {
            /*
                Method dump skipped, instructions count: 1590
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.JSONPath.JSONPathParser.parseArrayAccessFilter(boolean):java.lang.Object");
        }

        public double readDoubleValue(long j2) {
            int i2 = this.pos - 1;
            next();
            while (true) {
                char c2 = this.f8488ch;
                if (c2 < '0' || c2 > '9') {
                    break;
                }
                next();
            }
            return Double.parseDouble(this.path.substring(i2, this.pos - 1)) + j2;
        }

        public long readLongValue() {
            int i2 = this.pos - 1;
            char c2 = this.f8488ch;
            if (c2 == '+' || c2 == '-') {
                next();
            }
            while (true) {
                char c3 = this.f8488ch;
                if (c3 < '0' || c3 > '9') {
                    break;
                }
                next();
            }
            return Long.parseLong(this.path.substring(i2, this.pos - 1));
        }

        public String readName() {
            skipWhitespace();
            char c2 = this.f8488ch;
            if (c2 != '\\' && !Character.isJavaIdentifierStart(c2)) {
                StringBuilder m586H = C1499a.m586H("illeal jsonpath syntax. ");
                m586H.append(this.path);
                throw new JSONPathException(m586H.toString());
            }
            StringBuilder sb = new StringBuilder();
            while (!isEOF()) {
                char c3 = this.f8488ch;
                if (c3 == '\\') {
                    next();
                    sb.append(this.f8488ch);
                    if (isEOF()) {
                        return sb.toString();
                    }
                    next();
                } else {
                    if (!Character.isJavaIdentifierPart(c3)) {
                        break;
                    }
                    sb.append(this.f8488ch);
                    next();
                }
            }
            if (isEOF() && Character.isJavaIdentifierPart(this.f8488ch)) {
                sb.append(this.f8488ch);
            }
            return sb.toString();
        }

        public Operator readOp() {
            Operator operator;
            char c2 = this.f8488ch;
            if (c2 == '=') {
                next();
                char c3 = this.f8488ch;
                if (c3 == '~') {
                    next();
                    operator = Operator.REG_MATCH;
                } else if (c3 == '=') {
                    next();
                    operator = Operator.EQ;
                } else {
                    operator = Operator.EQ;
                }
            } else if (c2 == '!') {
                next();
                accept('=');
                operator = Operator.NE;
            } else if (c2 == '<') {
                next();
                if (this.f8488ch == '=') {
                    next();
                    operator = Operator.LE;
                } else {
                    operator = Operator.LT;
                }
            } else if (c2 == '>') {
                next();
                if (this.f8488ch == '=') {
                    next();
                    operator = Operator.GE;
                } else {
                    operator = Operator.GT;
                }
            } else {
                operator = null;
            }
            if (operator != null) {
                return operator;
            }
            String readName = readName();
            if ("not".equalsIgnoreCase(readName)) {
                skipWhitespace();
                String readName2 = readName();
                if ("like".equalsIgnoreCase(readName2)) {
                    return Operator.NOT_LIKE;
                }
                if ("rlike".equalsIgnoreCase(readName2)) {
                    return Operator.NOT_RLIKE;
                }
                if ("in".equalsIgnoreCase(readName2)) {
                    return Operator.NOT_IN;
                }
                if ("between".equalsIgnoreCase(readName2)) {
                    return Operator.NOT_BETWEEN;
                }
                throw new UnsupportedOperationException();
            }
            if ("nin".equalsIgnoreCase(readName)) {
                return Operator.NOT_IN;
            }
            if ("like".equalsIgnoreCase(readName)) {
                return Operator.LIKE;
            }
            if ("rlike".equalsIgnoreCase(readName)) {
                return Operator.RLIKE;
            }
            if ("in".equalsIgnoreCase(readName)) {
                return Operator.IN;
            }
            if ("between".equalsIgnoreCase(readName)) {
                return Operator.BETWEEN;
            }
            throw new UnsupportedOperationException();
        }

        public Segment readSegement() {
            boolean z = true;
            if (this.level == 0 && this.path.length() == 1) {
                if (isDigitFirst(this.f8488ch)) {
                    return new ArrayAccessSegment(this.f8488ch - '0');
                }
                char c2 = this.f8488ch;
                if ((c2 >= 'a' && c2 <= 'z') || (c2 >= 'A' && c2 <= 'Z')) {
                    return new PropertySegment(Character.toString(c2), false);
                }
            }
            while (!isEOF()) {
                skipWhitespace();
                char c3 = this.f8488ch;
                if (c3 != '$') {
                    if (c3 != '.' && c3 != '/') {
                        if (c3 == '[') {
                            return parseArrayAccess(true);
                        }
                        if (this.level == 0) {
                            return new PropertySegment(readName(), false);
                        }
                        StringBuilder m586H = C1499a.m586H("not support jsonpath : ");
                        m586H.append(this.path);
                        throw new JSONPathException(m586H.toString());
                    }
                    next();
                    if (c3 == '.' && this.f8488ch == '.') {
                        next();
                        int length = this.path.length();
                        int i2 = this.pos;
                        if (length > i2 + 3 && this.f8488ch == '[' && this.path.charAt(i2) == '*' && this.path.charAt(this.pos + 1) == ']' && this.path.charAt(this.pos + 2) == '.') {
                            next();
                            next();
                            next();
                            next();
                        }
                    } else {
                        z = false;
                    }
                    char c4 = this.f8488ch;
                    if (c4 == '*') {
                        if (!isEOF()) {
                            next();
                        }
                        return z ? WildCardSegment.instance_deep : WildCardSegment.instance;
                    }
                    if (isDigitFirst(c4)) {
                        return parseArrayAccess(false);
                    }
                    String readName = readName();
                    if (this.f8488ch != '(') {
                        return new PropertySegment(readName, z);
                    }
                    next();
                    if (this.f8488ch != ')') {
                        StringBuilder m586H2 = C1499a.m586H("not support jsonpath : ");
                        m586H2.append(this.path);
                        throw new JSONPathException(m586H2.toString());
                    }
                    if (!isEOF()) {
                        next();
                    }
                    if ("size".equals(readName) || "length".equals(readName)) {
                        return SizeSegment.instance;
                    }
                    if ("max".equals(readName)) {
                        return MaxSegment.instance;
                    }
                    if ("min".equals(readName)) {
                        return MinSegment.instance;
                    }
                    if ("keySet".equals(readName)) {
                        return KeySetSegment.instance;
                    }
                    StringBuilder m586H3 = C1499a.m586H("not support jsonpath : ");
                    m586H3.append(this.path);
                    throw new JSONPathException(m586H3.toString());
                }
                next();
            }
            return null;
        }

        public String readString() {
            char c2 = this.f8488ch;
            next();
            int i2 = this.pos - 1;
            while (this.f8488ch != c2 && !isEOF()) {
                next();
            }
            String substring = this.path.substring(i2, isEOF() ? this.pos : this.pos - 1);
            accept(c2);
            return substring;
        }

        public Object readValue() {
            skipWhitespace();
            if (isDigitFirst(this.f8488ch)) {
                return Long.valueOf(readLongValue());
            }
            char c2 = this.f8488ch;
            if (c2 == '\"' || c2 == '\'') {
                return readString();
            }
            if (c2 != 'n') {
                throw new UnsupportedOperationException();
            }
            if ("null".equals(readName())) {
                return null;
            }
            throw new JSONPathException(this.path);
        }

        public final void skipWhitespace() {
            while (true) {
                char c2 = this.f8488ch;
                if (c2 > ' ') {
                    return;
                }
                if (c2 != ' ' && c2 != '\r' && c2 != '\n' && c2 != '\t' && c2 != '\f' && c2 != '\b') {
                    return;
                } else {
                    next();
                }
            }
        }
    }

    public static class KeySetSegment implements Segment {
        public static final KeySetSegment instance = new KeySetSegment();

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            return jSONPath.evalKeySet(obj2);
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            throw new UnsupportedOperationException();
        }
    }

    public static class MatchSegement implements Filter {
        private final String[] containsValues;
        private final String endsWithValue;
        private final int minLength;
        private final boolean not;
        private final String propertyName;
        private final long propertyNameHash;
        private final String startsWithValue;

        public MatchSegement(String str, String str2, String str3, String[] strArr, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.startsWithValue = str2;
            this.endsWithValue = str3;
            this.containsValues = strArr;
            this.not = z;
            int length = str2 != null ? str2.length() + 0 : 0;
            length = str3 != null ? length + str3.length() : length;
            if (strArr != null) {
                for (String str4 : strArr) {
                    length += str4.length();
                }
            }
            this.minLength = length;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            int i2;
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null) {
                return false;
            }
            String obj4 = propertyValue.toString();
            if (obj4.length() < this.minLength) {
                return this.not;
            }
            String str = this.startsWithValue;
            if (str == null) {
                i2 = 0;
            } else {
                if (!obj4.startsWith(str)) {
                    return this.not;
                }
                i2 = this.startsWithValue.length() + 0;
            }
            String[] strArr = this.containsValues;
            if (strArr != null) {
                for (String str2 : strArr) {
                    int indexOf = obj4.indexOf(str2, i2);
                    if (indexOf == -1) {
                        return this.not;
                    }
                    i2 = indexOf + str2.length();
                }
            }
            String str3 = this.endsWithValue;
            return (str3 == null || obj4.endsWith(str3)) ? !this.not : this.not;
        }
    }

    public static class MaxSegment implements Segment {
        public static final MaxSegment instance = new MaxSegment();

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            if (!(obj2 instanceof Collection)) {
                throw new UnsupportedOperationException();
            }
            Object obj3 = null;
            for (Object obj4 : (Collection) obj2) {
                if (obj4 != null && (obj3 == null || JSONPath.compare(obj3, obj4) < 0)) {
                    obj3 = obj4;
                }
            }
            return obj3;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            throw new UnsupportedOperationException();
        }
    }

    public static class MinSegment implements Segment {
        public static final MinSegment instance = new MinSegment();

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            if (!(obj2 instanceof Collection)) {
                throw new UnsupportedOperationException();
            }
            Object obj3 = null;
            for (Object obj4 : (Collection) obj2) {
                if (obj4 != null && (obj3 == null || JSONPath.compare(obj3, obj4) > 0)) {
                    obj3 = obj4;
                }
            }
            return obj3;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            throw new UnsupportedOperationException();
        }
    }

    public static class MultiIndexSegment implements Segment {
        private final int[] indexes;

        public MultiIndexSegment(int[] iArr) {
            this.indexes = iArr;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            JSONArray jSONArray = new JSONArray(this.indexes.length);
            int i2 = 0;
            while (true) {
                int[] iArr = this.indexes;
                if (i2 >= iArr.length) {
                    return jSONArray;
                }
                jSONArray.add(jSONPath.getArrayItem(obj2, iArr[i2]));
                i2++;
            }
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            if (context.eval) {
                Object parse = defaultJSONParser.parse();
                if (parse instanceof List) {
                    int[] iArr = this.indexes;
                    int length = iArr.length;
                    int[] iArr2 = new int[length];
                    System.arraycopy(iArr, 0, iArr2, 0, length);
                    List list = (List) parse;
                    if (iArr2[0] >= 0) {
                        for (int size = list.size() - 1; size >= 0; size--) {
                            if (Arrays.binarySearch(iArr2, size) < 0) {
                                list.remove(size);
                            }
                        }
                        context.object = list;
                        return;
                    }
                }
            }
            throw new UnsupportedOperationException();
        }
    }

    public static class MultiPropertySegment implements Segment {
        private final String[] propertyNames;
        private final long[] propertyNamesHash;

        public MultiPropertySegment(String[] strArr) {
            this.propertyNames = strArr;
            this.propertyNamesHash = new long[strArr.length];
            int i2 = 0;
            while (true) {
                long[] jArr = this.propertyNamesHash;
                if (i2 >= jArr.length) {
                    return;
                }
                jArr[i2] = TypeUtils.fnv1a_64(strArr[i2]);
                i2++;
            }
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            ArrayList arrayList = new ArrayList(this.propertyNames.length);
            int i2 = 0;
            while (true) {
                String[] strArr = this.propertyNames;
                if (i2 >= strArr.length) {
                    return arrayList;
                }
                arrayList.add(jSONPath.getPropertyValue(obj2, strArr[i2], this.propertyNamesHash[i2]));
                i2++;
            }
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            JSONArray jSONArray;
            Object integerValue;
            JSONLexerBase jSONLexerBase = (JSONLexerBase) defaultJSONParser.lexer;
            Object obj = context.object;
            if (obj == null) {
                jSONArray = new JSONArray();
                context.object = jSONArray;
            } else {
                jSONArray = (JSONArray) obj;
            }
            for (int size = jSONArray.size(); size < this.propertyNamesHash.length; size++) {
                jSONArray.add(null);
            }
            do {
                int seekObjectToField = jSONLexerBase.seekObjectToField(this.propertyNamesHash);
                if (jSONLexerBase.matchStat != 3) {
                    return;
                }
                int i2 = jSONLexerBase.token();
                if (i2 == 2) {
                    integerValue = jSONLexerBase.integerValue();
                    jSONLexerBase.nextToken(16);
                } else if (i2 == 3) {
                    integerValue = jSONLexerBase.decimalValue();
                    jSONLexerBase.nextToken(16);
                } else if (i2 != 4) {
                    integerValue = defaultJSONParser.parse();
                } else {
                    integerValue = jSONLexerBase.stringVal();
                    jSONLexerBase.nextToken(16);
                }
                jSONArray.set(seekObjectToField, integerValue);
            } while (jSONLexerBase.token() == 16);
        }
    }

    public static class NotNullSegement implements Filter {
        private final String propertyName;
        private final long propertyNameHash;

        public NotNullSegement(String str) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            return jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash) != null;
        }
    }

    public static class NullSegement implements Filter {
        private final String propertyName;
        private final long propertyNameHash;

        public NullSegement(String str) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            return jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash) == null;
        }
    }

    public enum Operator {
        EQ,
        NE,
        GT,
        GE,
        LT,
        LE,
        LIKE,
        NOT_LIKE,
        RLIKE,
        NOT_RLIKE,
        IN,
        NOT_IN,
        BETWEEN,
        NOT_BETWEEN,
        And,
        Or,
        REG_MATCH
    }

    public static class PropertySegment implements Segment {
        private final boolean deep;
        private final String propertyName;
        private final long propertyNameHash;

        public PropertySegment(String str, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.deep = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            if (!this.deep) {
                return jSONPath.getPropertyValue(obj2, this.propertyName, this.propertyNameHash);
            }
            ArrayList arrayList = new ArrayList();
            jSONPath.deepScan(obj2, this.propertyName, arrayList);
            return arrayList;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            Object integerValue;
            Object integerValue2;
            Object integerValue3;
            JSONLexerBase jSONLexerBase = (JSONLexerBase) defaultJSONParser.lexer;
            if (this.deep && context.object == null) {
                context.object = new JSONArray();
            }
            if (jSONLexerBase.token() != 14) {
                boolean z = this.deep;
                if (!z) {
                    if (jSONLexerBase.seekObjectToField(this.propertyNameHash, z) == 3 && context.eval) {
                        int i2 = jSONLexerBase.token();
                        if (i2 == 2) {
                            integerValue2 = jSONLexerBase.integerValue();
                            jSONLexerBase.nextToken(16);
                        } else if (i2 == 3) {
                            integerValue2 = jSONLexerBase.decimalValue();
                            jSONLexerBase.nextToken(16);
                        } else if (i2 != 4) {
                            integerValue2 = defaultJSONParser.parse();
                        } else {
                            integerValue2 = jSONLexerBase.stringVal();
                            jSONLexerBase.nextToken(16);
                        }
                        if (context.eval) {
                            context.object = integerValue2;
                            return;
                        }
                        return;
                    }
                    return;
                }
                while (true) {
                    int seekObjectToField = jSONLexerBase.seekObjectToField(this.propertyNameHash, this.deep);
                    if (seekObjectToField == -1) {
                        return;
                    }
                    if (seekObjectToField == 3) {
                        if (context.eval) {
                            int i3 = jSONLexerBase.token();
                            if (i3 == 2) {
                                integerValue = jSONLexerBase.integerValue();
                                jSONLexerBase.nextToken(16);
                            } else if (i3 == 3) {
                                integerValue = jSONLexerBase.decimalValue();
                                jSONLexerBase.nextToken(16);
                            } else if (i3 != 4) {
                                integerValue = defaultJSONParser.parse();
                            } else {
                                integerValue = jSONLexerBase.stringVal();
                                jSONLexerBase.nextToken(16);
                            }
                            if (context.eval) {
                                Object obj = context.object;
                                if (obj instanceof List) {
                                    List list = (List) obj;
                                    if (list.size() == 0 && (integerValue instanceof List)) {
                                        context.object = integerValue;
                                    } else {
                                        list.add(integerValue);
                                    }
                                } else {
                                    context.object = integerValue;
                                }
                            }
                        }
                    } else if (seekObjectToField == 1 || seekObjectToField == 2) {
                        extract(jSONPath, defaultJSONParser, context);
                    }
                }
            } else {
                if ("*".equals(this.propertyName)) {
                    return;
                }
                jSONLexerBase.nextToken();
                JSONArray jSONArray = this.deep ? (JSONArray) context.object : new JSONArray();
                while (true) {
                    int i4 = jSONLexerBase.token();
                    if (i4 == 12) {
                        boolean z2 = this.deep;
                        if (z2) {
                            extract(jSONPath, defaultJSONParser, context);
                        } else {
                            int seekObjectToField2 = jSONLexerBase.seekObjectToField(this.propertyNameHash, z2);
                            if (seekObjectToField2 == 3) {
                                int i5 = jSONLexerBase.token();
                                if (i5 == 2) {
                                    integerValue3 = jSONLexerBase.integerValue();
                                    jSONLexerBase.nextToken();
                                } else if (i5 != 4) {
                                    integerValue3 = defaultJSONParser.parse();
                                } else {
                                    integerValue3 = jSONLexerBase.stringVal();
                                    jSONLexerBase.nextToken();
                                }
                                jSONArray.add(integerValue3);
                                if (jSONLexerBase.token() == 13) {
                                    jSONLexerBase.nextToken();
                                } else {
                                    jSONLexerBase.skipObject(false);
                                }
                            } else if (seekObjectToField2 == -1) {
                                continue;
                            } else {
                                if (this.deep) {
                                    throw new UnsupportedOperationException(jSONLexerBase.info());
                                }
                                jSONLexerBase.skipObject(false);
                            }
                        }
                    } else if (i4 != 14) {
                        switch (i4) {
                            case 2:
                            case 3:
                            case 4:
                            case 5:
                            case 6:
                            case 7:
                            case 8:
                                jSONLexerBase.nextToken();
                                break;
                        }
                    } else if (this.deep) {
                        extract(jSONPath, defaultJSONParser, context);
                    } else {
                        jSONLexerBase.skipObject(false);
                    }
                    if (jSONLexerBase.token() == 15) {
                        jSONLexerBase.nextToken();
                        if (this.deep || jSONArray.size() <= 0) {
                            return;
                        }
                        context.object = jSONArray;
                        return;
                    }
                    if (jSONLexerBase.token() != 16) {
                        StringBuilder m586H = C1499a.m586H("illegal json : ");
                        m586H.append(jSONLexerBase.info());
                        throw new JSONException(m586H.toString());
                    }
                    jSONLexerBase.nextToken();
                }
            }
        }

        public boolean remove(JSONPath jSONPath, Object obj) {
            return jSONPath.removePropertyValue(obj, this.propertyName, this.deep);
        }

        public void setValue(JSONPath jSONPath, Object obj, Object obj2) {
            if (this.deep) {
                jSONPath.deepSet(obj, this.propertyName, this.propertyNameHash, obj2);
            } else {
                jSONPath.setPropertyValue(obj, this.propertyName, this.propertyNameHash, obj2);
            }
        }
    }

    public static class RangeSegment implements Segment {
        private final int end;
        private final int start;
        private final int step;

        public RangeSegment(int i2, int i3, int i4) {
            this.start = i2;
            this.end = i3;
            this.step = i4;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            int intValue = SizeSegment.instance.eval(jSONPath, obj, obj2).intValue();
            int i2 = this.start;
            if (i2 < 0) {
                i2 += intValue;
            }
            int i3 = this.end;
            if (i3 < 0) {
                i3 += intValue;
            }
            int i4 = ((i3 - i2) / this.step) + 1;
            if (i4 == -1) {
                return null;
            }
            ArrayList arrayList = new ArrayList(i4);
            while (i2 <= i3 && i2 < intValue) {
                arrayList.add(jSONPath.getArrayItem(obj2, i2));
                i2 += this.step;
            }
            return arrayList;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            throw new UnsupportedOperationException();
        }
    }

    public static class RefOpSegement implements Filter {

        /* renamed from: op */
        private final Operator f8497op;
        private final String propertyName;
        private final long propertyNameHash;
        private final Segment refSgement;

        public RefOpSegement(String str, Segment segment, Operator operator) {
            this.propertyName = str;
            this.refSgement = segment;
            this.f8497op = operator;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null || !(propertyValue instanceof Number)) {
                return false;
            }
            Object eval = this.refSgement.eval(jSONPath, obj, obj);
            if ((eval instanceof Integer) || (eval instanceof Long) || (eval instanceof Short) || (eval instanceof Byte)) {
                long longExtractValue = TypeUtils.longExtractValue((Number) eval);
                if ((propertyValue instanceof Integer) || (propertyValue instanceof Long) || (propertyValue instanceof Short) || (propertyValue instanceof Byte)) {
                    long longExtractValue2 = TypeUtils.longExtractValue((Number) propertyValue);
                    int ordinal = this.f8497op.ordinal();
                    if (ordinal == 0) {
                        return longExtractValue2 == longExtractValue;
                    }
                    if (ordinal == 1) {
                        return longExtractValue2 != longExtractValue;
                    }
                    if (ordinal == 2) {
                        return longExtractValue2 > longExtractValue;
                    }
                    if (ordinal == 3) {
                        return longExtractValue2 >= longExtractValue;
                    }
                    if (ordinal == 4) {
                        return longExtractValue2 < longExtractValue;
                    }
                    if (ordinal == 5) {
                        return longExtractValue2 <= longExtractValue;
                    }
                } else if (propertyValue instanceof BigDecimal) {
                    int compareTo = BigDecimal.valueOf(longExtractValue).compareTo((BigDecimal) propertyValue);
                    int ordinal2 = this.f8497op.ordinal();
                    return ordinal2 != 0 ? ordinal2 != 1 ? ordinal2 != 2 ? ordinal2 != 3 ? ordinal2 != 4 ? ordinal2 == 5 && compareTo >= 0 : compareTo > 0 : compareTo <= 0 : compareTo < 0 : compareTo != 0 : compareTo == 0;
                }
            }
            throw new UnsupportedOperationException();
        }
    }

    public static class RegMatchSegement implements Filter {

        /* renamed from: op */
        private final Operator f8498op;
        private final Pattern pattern;
        private final String propertyName;
        private final long propertyNameHash;

        public RegMatchSegement(String str, Pattern pattern, Operator operator) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.pattern = pattern;
            this.f8498op = operator;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null) {
                return false;
            }
            return this.pattern.matcher(propertyValue.toString()).matches();
        }
    }

    public static class RlikeSegement implements Filter {
        private final boolean not;
        private final Pattern pattern;
        private final String propertyName;
        private final long propertyNameHash;

        public RlikeSegement(String str, String str2, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.pattern = Pattern.compile(str2);
            this.not = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            if (propertyValue == null) {
                return false;
            }
            boolean matches = this.pattern.matcher(propertyValue.toString()).matches();
            return this.not ? !matches : matches;
        }
    }

    public interface Segment {
        Object eval(JSONPath jSONPath, Object obj, Object obj2);

        void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context);
    }

    public static class SizeSegment implements Segment {
        public static final SizeSegment instance = new SizeSegment();

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            throw new UnsupportedOperationException();
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Integer eval(JSONPath jSONPath, Object obj, Object obj2) {
            return Integer.valueOf(jSONPath.evalSize(obj2));
        }
    }

    public static class StringInSegement implements Filter {
        private final boolean not;
        private final String propertyName;
        private final long propertyNameHash;
        private final String[] values;

        public StringInSegement(String str, String[] strArr, boolean z) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.values = strArr;
            this.not = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            for (String str : this.values) {
                if (str == propertyValue) {
                    return !this.not;
                }
                if (str != null && str.equals(propertyValue)) {
                    return !this.not;
                }
            }
            return this.not;
        }
    }

    public static class StringOpSegement implements Filter {

        /* renamed from: op */
        private final Operator f8499op;
        private final String propertyName;
        private final long propertyNameHash;
        private final String value;

        public StringOpSegement(String str, String str2, Operator operator) {
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.value = str2;
            this.f8499op = operator;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            Object propertyValue = jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash);
            Operator operator = this.f8499op;
            if (operator == Operator.EQ) {
                return this.value.equals(propertyValue);
            }
            if (operator == Operator.NE) {
                return !this.value.equals(propertyValue);
            }
            if (propertyValue == null) {
                return false;
            }
            int compareTo = this.value.compareTo(propertyValue.toString());
            Operator operator2 = this.f8499op;
            return operator2 == Operator.GE ? compareTo <= 0 : operator2 == Operator.GT ? compareTo < 0 : operator2 == Operator.LE ? compareTo >= 0 : operator2 == Operator.LT && compareTo > 0;
        }
    }

    public static class ValueSegment implements Filter {

        /* renamed from: eq */
        private boolean f8500eq;
        private final String propertyName;
        private final long propertyNameHash;
        private final Object value;

        public ValueSegment(String str, Object obj, boolean z) {
            this.f8500eq = true;
            if (obj == null) {
                throw new IllegalArgumentException("value is null");
            }
            this.propertyName = str;
            this.propertyNameHash = TypeUtils.fnv1a_64(str);
            this.value = obj;
            this.f8500eq = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Filter
        public boolean apply(JSONPath jSONPath, Object obj, Object obj2, Object obj3) {
            boolean equals = this.value.equals(jSONPath.getPropertyValue(obj3, this.propertyName, this.propertyNameHash));
            return !this.f8500eq ? !equals : equals;
        }
    }

    public static class WildCardSegment implements Segment {
        public static final WildCardSegment instance = new WildCardSegment(false);
        public static final WildCardSegment instance_deep = new WildCardSegment(true);
        private boolean deep;

        private WildCardSegment(boolean z) {
            this.deep = z;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public Object eval(JSONPath jSONPath, Object obj, Object obj2) {
            if (!this.deep) {
                return jSONPath.getPropertyValues(obj2);
            }
            ArrayList arrayList = new ArrayList();
            jSONPath.deepGetPropertyValues(obj2, arrayList);
            return arrayList;
        }

        @Override // com.alibaba.fastjson.JSONPath.Segment
        public void extract(JSONPath jSONPath, DefaultJSONParser defaultJSONParser, Context context) {
            if (context.eval) {
                Object parse = defaultJSONParser.parse();
                if (this.deep) {
                    ArrayList arrayList = new ArrayList();
                    jSONPath.deepGetPropertyValues(parse, arrayList);
                    context.object = arrayList;
                    return;
                } else {
                    if (parse instanceof JSONObject) {
                        Collection<Object> values = ((JSONObject) parse).values();
                        JSONArray jSONArray = new JSONArray(values.size());
                        Iterator<Object> it = values.iterator();
                        while (it.hasNext()) {
                            jSONArray.add(it.next());
                        }
                        context.object = jSONArray;
                        return;
                    }
                    if (parse instanceof JSONArray) {
                        context.object = parse;
                        return;
                    }
                }
            }
            throw new JSONException("TODO");
        }
    }

    public JSONPath(String str) {
        this(str, SerializeConfig.getGlobalInstance(), ParserConfig.getGlobalInstance());
    }

    public static int compare(Object obj, Object obj2) {
        Object d2;
        Object f2;
        if (obj.getClass() == obj2.getClass()) {
            return ((Comparable) obj).compareTo(obj2);
        }
        Class<?> cls = obj.getClass();
        Class<?> cls2 = obj2.getClass();
        if (cls == BigDecimal.class) {
            if (cls2 == Integer.class) {
                f2 = new BigDecimal(((Integer) obj2).intValue());
            } else if (cls2 == Long.class) {
                f2 = new BigDecimal(((Long) obj2).longValue());
            } else {
                if (cls2 != Float.class) {
                    if (cls2 == Double.class) {
                        f2 = new BigDecimal(((Double) obj2).doubleValue());
                    }
                    return ((Comparable) obj).compareTo(obj2);
                }
                f2 = new BigDecimal(((Float) obj2).floatValue());
            }
            obj2 = f2;
            return ((Comparable) obj).compareTo(obj2);
        }
        if (cls == Long.class) {
            if (cls2 == Integer.class) {
                f2 = new Long(((Integer) obj2).intValue());
                obj2 = f2;
            } else {
                if (cls2 == BigDecimal.class) {
                    d2 = new BigDecimal(((Long) obj).longValue());
                } else if (cls2 == Float.class) {
                    d2 = new Float(((Long) obj).longValue());
                } else if (cls2 == Double.class) {
                    d2 = new Double(((Long) obj).longValue());
                }
                obj = d2;
            }
        } else if (cls == Integer.class) {
            if (cls2 == Long.class) {
                d2 = new Long(((Integer) obj).intValue());
            } else if (cls2 == BigDecimal.class) {
                d2 = new BigDecimal(((Integer) obj).intValue());
            } else if (cls2 == Float.class) {
                d2 = new Float(((Integer) obj).intValue());
            } else if (cls2 == Double.class) {
                d2 = new Double(((Integer) obj).intValue());
            }
            obj = d2;
        } else if (cls == Double.class) {
            if (cls2 == Integer.class) {
                f2 = new Double(((Integer) obj2).intValue());
            } else if (cls2 == Long.class) {
                f2 = new Double(((Long) obj2).longValue());
            } else if (cls2 == Float.class) {
                f2 = new Double(((Float) obj2).floatValue());
            }
            obj2 = f2;
        } else if (cls == Float.class) {
            if (cls2 == Integer.class) {
                f2 = new Float(((Integer) obj2).intValue());
            } else if (cls2 == Long.class) {
                f2 = new Float(((Long) obj2).longValue());
            } else if (cls2 == Double.class) {
                d2 = new Double(((Float) obj).floatValue());
                obj = d2;
            }
            obj2 = f2;
        }
        return ((Comparable) obj).compareTo(obj2);
    }

    public static JSONPath compile(String str) {
        if (str == null) {
            throw new JSONPathException("jsonpath can not be null");
        }
        JSONPath jSONPath = pathCache.get(str);
        if (jSONPath != null) {
            return jSONPath;
        }
        JSONPath jSONPath2 = new JSONPath(str);
        if (pathCache.size() >= 1024) {
            return jSONPath2;
        }
        pathCache.putIfAbsent(str, jSONPath2);
        return pathCache.get(str);
    }

    /* renamed from: eq */
    public static boolean m3644eq(Object obj, Object obj2) {
        if (obj == obj2) {
            return true;
        }
        if (obj == null || obj2 == null) {
            return false;
        }
        if (obj.getClass() == obj2.getClass()) {
            return obj.equals(obj2);
        }
        if (!(obj instanceof Number)) {
            return obj.equals(obj2);
        }
        if (obj2 instanceof Number) {
            return eqNotNull((Number) obj, (Number) obj2);
        }
        return false;
    }

    public static boolean eqNotNull(Number number, Number number2) {
        Class<?> cls = number.getClass();
        boolean isInt = isInt(cls);
        Class<?> cls2 = number2.getClass();
        boolean isInt2 = isInt(cls2);
        if (number instanceof BigDecimal) {
            BigDecimal bigDecimal = (BigDecimal) number;
            if (isInt2) {
                return bigDecimal.equals(BigDecimal.valueOf(TypeUtils.longExtractValue(number2)));
            }
        }
        if (isInt) {
            if (isInt2) {
                return number.longValue() == number2.longValue();
            }
            if (number2 instanceof BigInteger) {
                return BigInteger.valueOf(number.longValue()).equals((BigInteger) number);
            }
        }
        if (isInt2 && (number instanceof BigInteger)) {
            return ((BigInteger) number).equals(BigInteger.valueOf(TypeUtils.longExtractValue(number2)));
        }
        boolean isDouble = isDouble(cls);
        boolean isDouble2 = isDouble(cls2);
        return ((isDouble && isDouble2) || ((isDouble && isInt2) || (isDouble2 && isInt))) && number.doubleValue() == number2.doubleValue();
    }

    public static boolean isDouble(Class<?> cls) {
        return cls == Float.class || cls == Double.class;
    }

    public static boolean isInt(Class<?> cls) {
        return cls == Byte.class || cls == Short.class || cls == Integer.class || cls == Long.class;
    }

    public static Map<String, Object> paths(Object obj) {
        return paths(obj, SerializeConfig.globalInstance);
    }

    public static Object read(String str, String str2) {
        return compile(str2).eval(JSON.parse(str));
    }

    public static Object reserveToArray(Object obj, String... strArr) {
        JSONArray jSONArray = new JSONArray();
        if (strArr != null && strArr.length != 0) {
            for (String str : strArr) {
                JSONPath compile = compile(str);
                compile.init();
                jSONArray.add(compile.eval(obj));
            }
        }
        return jSONArray;
    }

    public static Object reserveToObject(Object obj, String... strArr) {
        Object eval;
        if (strArr == null || strArr.length == 0) {
            return obj;
        }
        JSONObject jSONObject = new JSONObject(true);
        for (String str : strArr) {
            JSONPath compile = compile(str);
            compile.init();
            Segment[] segmentArr = compile.segments;
            if ((segmentArr[segmentArr.length - 1] instanceof PropertySegment) && (eval = compile.eval(obj)) != null) {
                compile.set(jSONObject, eval);
            }
        }
        return jSONObject;
    }

    public void arrayAdd(Object obj, Object... objArr) {
        if (objArr == null || objArr.length == 0 || obj == null) {
            return;
        }
        init();
        Object obj2 = null;
        int i2 = 0;
        int i3 = 0;
        Object obj3 = obj;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i3 >= segmentArr.length) {
                break;
            }
            if (i3 == segmentArr.length - 1) {
                obj2 = obj3;
            }
            obj3 = segmentArr[i3].eval(this, obj, obj3);
            i3++;
        }
        if (obj3 == null) {
            StringBuilder m586H = C1499a.m586H("value not found in path ");
            m586H.append(this.path);
            throw new JSONPathException(m586H.toString());
        }
        if (obj3 instanceof Collection) {
            Collection collection = (Collection) obj3;
            int length = objArr.length;
            while (i2 < length) {
                collection.add(objArr[i2]);
                i2++;
            }
            return;
        }
        Class<?> cls = obj3.getClass();
        if (!cls.isArray()) {
            throw new JSONException(C1499a.m635u("unsupported array put operation. ", cls));
        }
        int length2 = Array.getLength(obj3);
        Object newInstance = Array.newInstance(cls.getComponentType(), objArr.length + length2);
        System.arraycopy(obj3, 0, newInstance, 0, length2);
        while (i2 < objArr.length) {
            Array.set(newInstance, length2 + i2, objArr[i2]);
            i2++;
        }
        Segment segment = this.segments[r8.length - 1];
        if (segment instanceof PropertySegment) {
            ((PropertySegment) segment).setValue(this, obj2, newInstance);
        } else {
            if (!(segment instanceof ArrayAccessSegment)) {
                throw new UnsupportedOperationException();
            }
            ((ArrayAccessSegment) segment).setValue(this, obj2, newInstance);
        }
    }

    public boolean contains(Object obj) {
        if (obj == null) {
            return false;
        }
        init();
        Object obj2 = obj;
        int i2 = 0;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i2 >= segmentArr.length) {
                return true;
            }
            Object eval = segmentArr[i2].eval(this, obj, obj2);
            if (eval == null) {
                return false;
            }
            if (eval == Collections.EMPTY_LIST && (obj2 instanceof List)) {
                return ((List) obj2).contains(eval);
            }
            i2++;
            obj2 = eval;
        }
    }

    public boolean containsValue(Object obj, Object obj2) {
        Object eval = eval(obj);
        if (eval == obj2) {
            return true;
        }
        if (eval == null) {
            return false;
        }
        if (!(eval instanceof Iterable)) {
            return m3644eq(eval, obj2);
        }
        Iterator it = ((Iterable) eval).iterator();
        while (it.hasNext()) {
            if (m3644eq(it.next(), obj2)) {
                return true;
            }
        }
        return false;
    }

    public void deepGetPropertyValues(Object obj, List<Object> list) {
        Collection fieldValues;
        Class<?> cls = obj.getClass();
        JavaBeanSerializer javaBeanSerializer = getJavaBeanSerializer(cls);
        if (javaBeanSerializer != null) {
            try {
                fieldValues = javaBeanSerializer.getFieldValues(obj);
            } catch (Exception e2) {
                StringBuilder m586H = C1499a.m586H("jsonpath error, path ");
                m586H.append(this.path);
                throw new JSONPathException(m586H.toString(), e2);
            }
        } else {
            fieldValues = obj instanceof Map ? ((Map) obj).values() : obj instanceof Collection ? (Collection) obj : null;
        }
        if (fieldValues == null) {
            throw new UnsupportedOperationException(cls.getName());
        }
        for (Object obj2 : fieldValues) {
            if (obj2 == null || ParserConfig.isPrimitive2(obj2.getClass())) {
                list.add(obj2);
            } else {
                deepGetPropertyValues(obj2, list);
            }
        }
    }

    public void deepScan(Object obj, String str, List<Object> list) {
        if (obj == null) {
            return;
        }
        if (obj instanceof Map) {
            for (Map.Entry entry : ((Map) obj).entrySet()) {
                Object value = entry.getValue();
                if (str.equals(entry.getKey())) {
                    if (value instanceof Collection) {
                        list.addAll((Collection) value);
                    } else {
                        list.add(value);
                    }
                } else if (value != null && !ParserConfig.isPrimitive2(value.getClass())) {
                    deepScan(value, str, list);
                }
            }
            return;
        }
        if (obj instanceof Collection) {
            for (Object obj2 : (Collection) obj) {
                if (!ParserConfig.isPrimitive2(obj2.getClass())) {
                    deepScan(obj2, str, list);
                }
            }
            return;
        }
        JavaBeanSerializer javaBeanSerializer = getJavaBeanSerializer(obj.getClass());
        if (javaBeanSerializer == null) {
            if (obj instanceof List) {
                List list2 = (List) obj;
                for (int i2 = 0; i2 < list2.size(); i2++) {
                    deepScan(list2.get(i2), str, list);
                }
                return;
            }
            return;
        }
        try {
            FieldSerializer fieldSerializer = javaBeanSerializer.getFieldSerializer(str);
            if (fieldSerializer == null) {
                Iterator<Object> it = javaBeanSerializer.getFieldValues(obj).iterator();
                while (it.hasNext()) {
                    deepScan(it.next(), str, list);
                }
                return;
            }
            try {
                list.add(fieldSerializer.getPropertyValueDirect(obj));
            } catch (IllegalAccessException e2) {
                throw new JSONException("getFieldValue error." + str, e2);
            } catch (InvocationTargetException e3) {
                throw new JSONException("getFieldValue error." + str, e3);
            }
        } catch (Exception e4) {
            throw new JSONPathException(C1499a.m583E(C1499a.m586H("jsonpath error, path "), this.path, ", segement ", str), e4);
        }
    }

    public void deepSet(Object obj, String str, long j2, Object obj2) {
        if (obj == null) {
            return;
        }
        if (obj instanceof Map) {
            Map map = (Map) obj;
            if (map.containsKey(str)) {
                map.get(str);
                map.put(str, obj2);
                return;
            } else {
                Iterator it = map.values().iterator();
                while (it.hasNext()) {
                    deepSet(it.next(), str, j2, obj2);
                }
                return;
            }
        }
        Class<?> cls = obj.getClass();
        JavaBeanDeserializer javaBeanDeserializer = getJavaBeanDeserializer(cls);
        if (javaBeanDeserializer == null) {
            if (obj instanceof List) {
                List list = (List) obj;
                for (int i2 = 0; i2 < list.size(); i2++) {
                    deepSet(list.get(i2), str, j2, obj2);
                }
                return;
            }
            return;
        }
        try {
            FieldDeserializer fieldDeserializer = javaBeanDeserializer.getFieldDeserializer(str);
            if (fieldDeserializer != null) {
                fieldDeserializer.setValue(obj, obj2);
                return;
            }
            Iterator<Object> it2 = getJavaBeanSerializer(cls).getObjectFieldValues(obj).iterator();
            while (it2.hasNext()) {
                deepSet(it2.next(), str, j2, obj2);
            }
        } catch (Exception e2) {
            throw new JSONPathException(C1499a.m583E(C1499a.m586H("jsonpath error, path "), this.path, ", segement ", str), e2);
        }
    }

    public Object eval(Object obj) {
        if (obj == null) {
            return null;
        }
        init();
        int i2 = 0;
        Object obj2 = obj;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i2 >= segmentArr.length) {
                return obj2;
            }
            obj2 = segmentArr[i2].eval(this, obj, obj2);
            i2++;
        }
    }

    public Set<?> evalKeySet(Object obj) {
        JavaBeanSerializer javaBeanSerializer;
        if (obj == null) {
            return null;
        }
        if (obj instanceof Map) {
            return ((Map) obj).keySet();
        }
        if ((obj instanceof Collection) || (obj instanceof Object[]) || obj.getClass().isArray() || (javaBeanSerializer = getJavaBeanSerializer(obj.getClass())) == null) {
            return null;
        }
        try {
            return javaBeanSerializer.getFieldNames(obj);
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("evalKeySet error : ");
            m586H.append(this.path);
            throw new JSONPathException(m586H.toString(), e2);
        }
    }

    public int evalSize(Object obj) {
        if (obj == null) {
            return -1;
        }
        if (obj instanceof Collection) {
            return ((Collection) obj).size();
        }
        if (obj instanceof Object[]) {
            return ((Object[]) obj).length;
        }
        if (obj.getClass().isArray()) {
            return Array.getLength(obj);
        }
        if (obj instanceof Map) {
            int i2 = 0;
            Iterator it = ((Map) obj).values().iterator();
            while (it.hasNext()) {
                if (it.next() != null) {
                    i2++;
                }
            }
            return i2;
        }
        JavaBeanSerializer javaBeanSerializer = getJavaBeanSerializer(obj.getClass());
        if (javaBeanSerializer == null) {
            return -1;
        }
        try {
            return javaBeanSerializer.getSize(obj);
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("evalSize error : ");
            m586H.append(this.path);
            throw new JSONPathException(m586H.toString(), e2);
        }
    }

    public Object extract(DefaultJSONParser defaultJSONParser) {
        Object obj;
        if (defaultJSONParser == null) {
            return null;
        }
        init();
        if (this.hasRefSegment) {
            return eval(defaultJSONParser.parse());
        }
        if (this.segments.length == 0) {
            return defaultJSONParser.parse();
        }
        Context context = null;
        int i2 = 0;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i2 >= segmentArr.length) {
                return context.object;
            }
            Segment segment = segmentArr[i2];
            boolean z = true;
            boolean z2 = i2 == segmentArr.length - 1;
            if (context == null || (obj = context.object) == null) {
                if (!z2) {
                    Segment segment2 = segmentArr[i2 + 1];
                    if ((!(segment instanceof PropertySegment) || !((PropertySegment) segment).deep || (!(segment2 instanceof ArrayAccessSegment) && !(segment2 instanceof MultiIndexSegment) && !(segment2 instanceof MultiPropertySegment) && !(segment2 instanceof SizeSegment) && !(segment2 instanceof PropertySegment) && !(segment2 instanceof FilterSegment))) && ((!(segment2 instanceof ArrayAccessSegment) || ((ArrayAccessSegment) segment2).index >= 0) && !(segment2 instanceof FilterSegment) && !(segment instanceof WildCardSegment))) {
                        z = false;
                    }
                }
                Context context2 = new Context(context, z);
                segment.extract(this, defaultJSONParser, context2);
                context = context2;
            } else {
                context.object = segment.eval(this, null, obj);
            }
            i2++;
        }
    }

    public Object getArrayItem(Object obj, int i2) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof List) {
            List list = (List) obj;
            if (i2 >= 0) {
                if (i2 < list.size()) {
                    return list.get(i2);
                }
                return null;
            }
            if (Math.abs(i2) <= list.size()) {
                return list.get(list.size() + i2);
            }
            return null;
        }
        if (obj.getClass().isArray()) {
            int length = Array.getLength(obj);
            if (i2 >= 0) {
                if (i2 < length) {
                    return Array.get(obj, i2);
                }
                return null;
            }
            if (Math.abs(i2) <= length) {
                return Array.get(obj, length + i2);
            }
            return null;
        }
        if (obj instanceof Map) {
            Map map = (Map) obj;
            Object obj2 = map.get(Integer.valueOf(i2));
            return obj2 == null ? map.get(Integer.toString(i2)) : obj2;
        }
        if (!(obj instanceof Collection)) {
            if (i2 == 0) {
                return obj;
            }
            throw new UnsupportedOperationException();
        }
        int i3 = 0;
        for (Object obj3 : (Collection) obj) {
            if (i3 == i2) {
                return obj3;
            }
            i3++;
        }
        return null;
    }

    public JavaBeanDeserializer getJavaBeanDeserializer(Class<?> cls) {
        ObjectDeserializer deserializer = this.parserConfig.getDeserializer(cls);
        if (deserializer instanceof JavaBeanDeserializer) {
            return (JavaBeanDeserializer) deserializer;
        }
        return null;
    }

    public JavaBeanSerializer getJavaBeanSerializer(Class<?> cls) {
        ObjectSerializer objectWriter = this.serializeConfig.getObjectWriter(cls);
        if (objectWriter instanceof JavaBeanSerializer) {
            return (JavaBeanSerializer) objectWriter;
        }
        return null;
    }

    public String getPath() {
        return this.path;
    }

    public Object getPropertyValue(Object obj, String str, long j2) {
        JSONArray jSONArray = null;
        if (obj == null) {
            return null;
        }
        if (obj instanceof String) {
            try {
                obj = JSON.parseObject((String) obj);
            } catch (Exception unused) {
            }
        }
        Object obj2 = obj;
        if (obj2 instanceof Map) {
            Map map = (Map) obj2;
            Object obj3 = map.get(str);
            return obj3 == null ? (SIZE == j2 || LENGTH == j2) ? Integer.valueOf(map.size()) : obj3 : obj3;
        }
        JavaBeanSerializer javaBeanSerializer = getJavaBeanSerializer(obj2.getClass());
        if (javaBeanSerializer != null) {
            try {
                return javaBeanSerializer.getFieldValue(obj2, str, j2, false);
            } catch (Exception e2) {
                throw new JSONPathException(C1499a.m583E(C1499a.m586H("jsonpath error, path "), this.path, ", segement ", str), e2);
            }
        }
        int i2 = 0;
        if (obj2 instanceof List) {
            List list = (List) obj2;
            if (SIZE == j2 || LENGTH == j2) {
                return Integer.valueOf(list.size());
            }
            while (i2 < list.size()) {
                Object obj4 = list.get(i2);
                if (obj4 == list) {
                    if (jSONArray == null) {
                        jSONArray = new JSONArray(list.size());
                    }
                    jSONArray.add(obj4);
                } else {
                    Object propertyValue = getPropertyValue(obj4, str, j2);
                    if (propertyValue instanceof Collection) {
                        Collection collection = (Collection) propertyValue;
                        if (jSONArray == null) {
                            jSONArray = new JSONArray(list.size());
                        }
                        jSONArray.addAll(collection);
                    } else if (propertyValue != null) {
                        if (jSONArray == null) {
                            jSONArray = new JSONArray(list.size());
                        }
                        jSONArray.add(propertyValue);
                    }
                }
                i2++;
            }
            return jSONArray == null ? Collections.emptyList() : jSONArray;
        }
        if (obj2 instanceof Object[]) {
            Object[] objArr = (Object[]) obj2;
            if (SIZE == j2 || LENGTH == j2) {
                return Integer.valueOf(objArr.length);
            }
            JSONArray jSONArray2 = new JSONArray(objArr.length);
            while (i2 < objArr.length) {
                Object[] objArr2 = objArr[i2];
                if (objArr2 == objArr) {
                    jSONArray2.add(objArr2);
                } else {
                    Object propertyValue2 = getPropertyValue(objArr2, str, j2);
                    if (propertyValue2 instanceof Collection) {
                        jSONArray2.addAll((Collection) propertyValue2);
                    } else if (propertyValue2 != null) {
                        jSONArray2.add(propertyValue2);
                    }
                }
                i2++;
            }
            return jSONArray2;
        }
        if (obj2 instanceof Enum) {
            Enum r8 = (Enum) obj2;
            if (-4270347329889690746L == j2) {
                return r8.name();
            }
            if (-1014497654951707614L == j2) {
                return Integer.valueOf(r8.ordinal());
            }
        }
        if (obj2 instanceof Calendar) {
            Calendar calendar = (Calendar) obj2;
            if (8963398325558730460L == j2) {
                return Integer.valueOf(calendar.get(1));
            }
            if (-811277319855450459L == j2) {
                return Integer.valueOf(calendar.get(2));
            }
            if (-3851359326990528739L == j2) {
                return Integer.valueOf(calendar.get(5));
            }
            if (4647432019745535567L == j2) {
                return Integer.valueOf(calendar.get(11));
            }
            if (6607618197526598121L == j2) {
                return Integer.valueOf(calendar.get(12));
            }
            if (-6586085717218287427L == j2) {
                return Integer.valueOf(calendar.get(13));
            }
        }
        return null;
    }

    public Collection<Object> getPropertyValues(Object obj) {
        if (obj == null) {
            return null;
        }
        JavaBeanSerializer javaBeanSerializer = getJavaBeanSerializer(obj.getClass());
        if (javaBeanSerializer != null) {
            try {
                return javaBeanSerializer.getFieldValues(obj);
            } catch (Exception e2) {
                StringBuilder m586H = C1499a.m586H("jsonpath error, path ");
                m586H.append(this.path);
                throw new JSONPathException(m586H.toString(), e2);
            }
        }
        if (obj instanceof Map) {
            return ((Map) obj).values();
        }
        if (obj instanceof Collection) {
            return (Collection) obj;
        }
        throw new UnsupportedOperationException();
    }

    public void init() {
        if (this.segments != null) {
            return;
        }
        if ("*".equals(this.path)) {
            this.segments = new Segment[]{WildCardSegment.instance};
            return;
        }
        JSONPathParser jSONPathParser = new JSONPathParser(this.path);
        this.segments = jSONPathParser.explain();
        this.hasRefSegment = jSONPathParser.hasRefSegment;
    }

    public boolean isRef() {
        init();
        int i2 = 0;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i2 >= segmentArr.length) {
                return true;
            }
            Class<?> cls = segmentArr[i2].getClass();
            if (cls != ArrayAccessSegment.class && cls != PropertySegment.class) {
                return false;
            }
            i2++;
        }
    }

    public Set<?> keySet(Object obj) {
        if (obj == null) {
            return null;
        }
        init();
        int i2 = 0;
        Object obj2 = obj;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i2 >= segmentArr.length) {
                return evalKeySet(obj2);
            }
            obj2 = segmentArr[i2].eval(this, obj, obj2);
            i2++;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:58:0x008f, code lost:
    
        if (r1 != null) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0091, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x0094, code lost:
    
        if ((r2 instanceof com.alibaba.fastjson.JSONPath.PropertySegment) == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x0096, code lost:
    
        r2 = (com.alibaba.fastjson.JSONPath.PropertySegment) r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x009a, code lost:
    
        if ((r1 instanceof java.util.Collection) == false) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x009c, code lost:
    
        r12 = r11.segments;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x009f, code lost:
    
        if (r12.length <= 1) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x00a1, code lost:
    
        r12 = r12[r12.length - 2];
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x00a8, code lost:
    
        if ((r12 instanceof com.alibaba.fastjson.JSONPath.RangeSegment) != false) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x00ac, code lost:
    
        if ((r12 instanceof com.alibaba.fastjson.JSONPath.MultiIndexSegment) == false) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x00ae, code lost:
    
        r12 = ((java.util.Collection) r1).iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x00b8, code lost:
    
        if (r12.hasNext() == false) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x00c2, code lost:
    
        if (r2.remove(r11, r12.next()) == false) goto L96;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x00c4, code lost:
    
        r0 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x00c6, code lost:
    
        return r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x00cb, code lost:
    
        return r2.remove(r11, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x00ce, code lost:
    
        if ((r2 instanceof com.alibaba.fastjson.JSONPath.ArrayAccessSegment) == false) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x00d6, code lost:
    
        return ((com.alibaba.fastjson.JSONPath.ArrayAccessSegment) r2).remove(r11, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x00d9, code lost:
    
        if ((r2 instanceof com.alibaba.fastjson.JSONPath.FilterSegment) == false) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x00e1, code lost:
    
        return ((com.alibaba.fastjson.JSONPath.FilterSegment) r2).remove(r11, r12, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x00e7, code lost:
    
        throw new java.lang.UnsupportedOperationException();
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean remove(java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 232
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.JSONPath.remove(java.lang.Object):boolean");
    }

    public boolean removeArrayItem(JSONPath jSONPath, Object obj, int i2) {
        if (!(obj instanceof List)) {
            throw new JSONPathException(C1499a.m635u("unsupported set operation.", obj.getClass()));
        }
        List list = (List) obj;
        if (i2 >= 0) {
            if (i2 >= list.size()) {
                return false;
            }
            list.remove(i2);
            return true;
        }
        int size = list.size() + i2;
        if (size < 0) {
            return false;
        }
        list.remove(size);
        return true;
    }

    public boolean removePropertyValue(Object obj, String str, boolean z) {
        if (obj instanceof Map) {
            Map map = (Map) obj;
            r1 = map.remove(str) != null;
            if (z) {
                Iterator it = map.values().iterator();
                while (it.hasNext()) {
                    removePropertyValue(it.next(), str, z);
                }
            }
            return r1;
        }
        ObjectDeserializer deserializer = this.parserConfig.getDeserializer(obj.getClass());
        JavaBeanDeserializer javaBeanDeserializer = deserializer instanceof JavaBeanDeserializer ? (JavaBeanDeserializer) deserializer : null;
        if (javaBeanDeserializer == null) {
            if (z) {
                return false;
            }
            throw new UnsupportedOperationException();
        }
        FieldDeserializer fieldDeserializer = javaBeanDeserializer.getFieldDeserializer(str);
        if (fieldDeserializer != null) {
            fieldDeserializer.setValue(obj, (String) null);
        } else {
            r1 = false;
        }
        if (z) {
            for (Object obj2 : getPropertyValues(obj)) {
                if (obj2 != null) {
                    removePropertyValue(obj2, str, z);
                }
            }
        }
        return r1;
    }

    public boolean set(Object obj, Object obj2) {
        return set(obj, obj2, true);
    }

    public boolean setArrayItem(JSONPath jSONPath, Object obj, int i2, Object obj2) {
        if (obj instanceof List) {
            List list = (List) obj;
            if (i2 >= 0) {
                list.set(i2, obj2);
            } else {
                list.set(list.size() + i2, obj2);
            }
            return true;
        }
        Class<?> cls = obj.getClass();
        if (!cls.isArray()) {
            throw new JSONPathException(C1499a.m635u("unsupported set operation.", cls));
        }
        int length = Array.getLength(obj);
        if (i2 >= 0) {
            if (i2 < length) {
                Array.set(obj, i2, obj2);
            }
        } else if (Math.abs(i2) <= length) {
            Array.set(obj, length + i2, obj2);
        }
        return true;
    }

    public boolean setPropertyValue(Object obj, String str, long j2, Object obj2) {
        if (obj instanceof Map) {
            ((Map) obj).put(str, obj2);
            return true;
        }
        if (obj instanceof List) {
            for (Object obj3 : (List) obj) {
                if (obj3 != null) {
                    setPropertyValue(obj3, str, j2, obj2);
                }
            }
            return true;
        }
        ObjectDeserializer deserializer = this.parserConfig.getDeserializer(obj.getClass());
        JavaBeanDeserializer javaBeanDeserializer = deserializer instanceof JavaBeanDeserializer ? (JavaBeanDeserializer) deserializer : null;
        if (javaBeanDeserializer == null) {
            throw new UnsupportedOperationException();
        }
        FieldDeserializer fieldDeserializer = javaBeanDeserializer.getFieldDeserializer(j2);
        if (fieldDeserializer == null) {
            return false;
        }
        if (obj2 != null) {
            Class<?> cls = obj2.getClass();
            FieldInfo fieldInfo = fieldDeserializer.fieldInfo;
            if (cls != fieldInfo.fieldClass) {
                obj2 = TypeUtils.cast(obj2, fieldInfo.fieldType, this.parserConfig);
            }
        }
        fieldDeserializer.setValue(obj, obj2);
        return true;
    }

    public int size(Object obj) {
        if (obj == null) {
            return -1;
        }
        init();
        int i2 = 0;
        Object obj2 = obj;
        while (true) {
            Segment[] segmentArr = this.segments;
            if (i2 >= segmentArr.length) {
                return evalSize(obj2);
            }
            obj2 = segmentArr[i2].eval(this, obj, obj2);
            i2++;
        }
    }

    @Override // com.alibaba.fastjson.JSONAware
    public String toJSONString() {
        return JSON.toJSONString(this.path);
    }

    public JSONPath(String str, SerializeConfig serializeConfig, ParserConfig parserConfig) {
        if (str == null || str.length() == 0) {
            throw new JSONPathException("json-path can not be null or empty");
        }
        this.path = str;
        this.serializeConfig = serializeConfig;
        this.parserConfig = parserConfig;
    }

    public static Map<String, Object> paths(Object obj, SerializeConfig serializeConfig) {
        IdentityHashMap identityHashMap = new IdentityHashMap();
        HashMap hashMap = new HashMap();
        paths(identityHashMap, hashMap, "/", obj, serializeConfig);
        return hashMap;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x005b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean set(java.lang.Object r9, java.lang.Object r10, boolean r11) {
        /*
            r8 = this;
            r11 = 0
            if (r9 != 0) goto L4
            return r11
        L4:
            r8.init()
            r0 = 0
            r2 = r9
            r3 = r0
            r1 = 0
        Lb:
            com.alibaba.fastjson.JSONPath$Segment[] r4 = r8.segments
            int r5 = r4.length
            r6 = 1
            if (r1 >= r5) goto L86
            r3 = r4[r1]
            java.lang.Object r4 = r3.eval(r8, r9, r2)
            if (r4 != 0) goto L81
            com.alibaba.fastjson.JSONPath$Segment[] r4 = r8.segments
            int r5 = r4.length
            int r5 = r5 - r6
            if (r1 >= r5) goto L24
            int r5 = r1 + 1
            r4 = r4[r5]
            goto L25
        L24:
            r4 = r0
        L25:
            boolean r5 = r4 instanceof com.alibaba.fastjson.JSONPath.PropertySegment
            if (r5 == 0) goto L61
            boolean r4 = r3 instanceof com.alibaba.fastjson.JSONPath.PropertySegment
            if (r4 == 0) goto L4b
            r4 = r3
            com.alibaba.fastjson.JSONPath$PropertySegment r4 = (com.alibaba.fastjson.JSONPath.PropertySegment) r4
            java.lang.String r4 = com.alibaba.fastjson.JSONPath.PropertySegment.access$400(r4)
            java.lang.Class r5 = r2.getClass()
            com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer r5 = r8.getJavaBeanDeserializer(r5)
            if (r5 == 0) goto L4b
            com.alibaba.fastjson.parser.deserializer.FieldDeserializer r4 = r5.getFieldDeserializer(r4)
            com.alibaba.fastjson.util.FieldInfo r4 = r4.fieldInfo
            java.lang.Class<?> r4 = r4.fieldClass
            com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer r5 = r8.getJavaBeanDeserializer(r4)
            goto L4d
        L4b:
            r4 = r0
            r5 = r4
        L4d:
            if (r5 == 0) goto L5b
            com.alibaba.fastjson.util.JavaBeanInfo r7 = r5.beanInfo
            java.lang.reflect.Constructor<?> r7 = r7.defaultConstructor
            if (r7 == 0) goto L5a
            java.lang.Object r4 = r5.createInstance(r0, r4)
            goto L6c
        L5a:
            return r11
        L5b:
            com.alibaba.fastjson.JSONObject r4 = new com.alibaba.fastjson.JSONObject
            r4.<init>()
            goto L6c
        L61:
            boolean r4 = r4 instanceof com.alibaba.fastjson.JSONPath.ArrayAccessSegment
            if (r4 == 0) goto L6b
            com.alibaba.fastjson.JSONArray r4 = new com.alibaba.fastjson.JSONArray
            r4.<init>()
            goto L6c
        L6b:
            r4 = r0
        L6c:
            if (r4 == 0) goto L87
            boolean r5 = r3 instanceof com.alibaba.fastjson.JSONPath.PropertySegment
            if (r5 == 0) goto L78
            com.alibaba.fastjson.JSONPath$PropertySegment r3 = (com.alibaba.fastjson.JSONPath.PropertySegment) r3
            r3.setValue(r8, r2, r4)
            goto L81
        L78:
            boolean r5 = r3 instanceof com.alibaba.fastjson.JSONPath.ArrayAccessSegment
            if (r5 == 0) goto L87
            com.alibaba.fastjson.JSONPath$ArrayAccessSegment r3 = (com.alibaba.fastjson.JSONPath.ArrayAccessSegment) r3
            r3.setValue(r8, r2, r4)
        L81:
            int r1 = r1 + 1
            r3 = r2
            r2 = r4
            goto Lb
        L86:
            r2 = r3
        L87:
            if (r2 != 0) goto L8a
            return r11
        L8a:
            com.alibaba.fastjson.JSONPath$Segment[] r9 = r8.segments
            int r11 = r9.length
            int r11 = r11 - r6
            r9 = r9[r11]
            boolean r11 = r9 instanceof com.alibaba.fastjson.JSONPath.PropertySegment
            if (r11 == 0) goto L9a
            com.alibaba.fastjson.JSONPath$PropertySegment r9 = (com.alibaba.fastjson.JSONPath.PropertySegment) r9
            r9.setValue(r8, r2, r10)
            return r6
        L9a:
            boolean r11 = r9 instanceof com.alibaba.fastjson.JSONPath.ArrayAccessSegment
            if (r11 == 0) goto La5
            com.alibaba.fastjson.JSONPath$ArrayAccessSegment r9 = (com.alibaba.fastjson.JSONPath.ArrayAccessSegment) r9
            boolean r9 = r9.setValue(r8, r2, r10)
            return r9
        La5:
            java.lang.UnsupportedOperationException r9 = new java.lang.UnsupportedOperationException
            r9.<init>()
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.JSONPath.set(java.lang.Object, java.lang.Object, boolean):boolean");
    }

    public static Object eval(Object obj, String str) {
        return compile(str).eval(obj);
    }

    public static Set<?> keySet(Object obj, String str) {
        JSONPath compile = compile(str);
        return compile.evalKeySet(compile.eval(obj));
    }

    private static void paths(Map<Object, String> map, Map<String, Object> map2, String str, Object obj, SerializeConfig serializeConfig) {
        StringBuilder sb;
        if (obj == null) {
            return;
        }
        int i2 = 0;
        if (map.put(obj, str) != null) {
            Class<?> cls = obj.getClass();
            if (!(cls == String.class || cls == Boolean.class || cls == Character.class || cls == UUID.class || cls.isEnum() || (obj instanceof Number) || (obj instanceof Date))) {
                return;
            }
        }
        map2.put(str, obj);
        if (obj instanceof Map) {
            for (Map.Entry entry : ((Map) obj).entrySet()) {
                Object key = entry.getKey();
                if (key instanceof String) {
                    StringBuilder sb2 = str.equals("/") ? new StringBuilder() : C1499a.m586H(str);
                    sb2.append("/");
                    sb2.append(key);
                    paths(map, map2, sb2.toString(), entry.getValue(), serializeConfig);
                }
            }
            return;
        }
        if (obj instanceof Collection) {
            for (Object obj2 : (Collection) obj) {
                StringBuilder sb3 = str.equals("/") ? new StringBuilder() : C1499a.m586H(str);
                sb3.append("/");
                sb3.append(i2);
                paths(map, map2, sb3.toString(), obj2, serializeConfig);
                i2++;
            }
            return;
        }
        Class<?> cls2 = obj.getClass();
        if (cls2.isArray()) {
            int length = Array.getLength(obj);
            while (i2 < length) {
                Object obj3 = Array.get(obj, i2);
                StringBuilder sb4 = str.equals("/") ? new StringBuilder() : C1499a.m586H(str);
                sb4.append("/");
                sb4.append(i2);
                paths(map, map2, sb4.toString(), obj3, serializeConfig);
                i2++;
            }
            return;
        }
        if (ParserConfig.isPrimitive2(cls2) || cls2.isEnum()) {
            return;
        }
        ObjectSerializer objectWriter = serializeConfig.getObjectWriter(cls2);
        if (objectWriter instanceof JavaBeanSerializer) {
            try {
                for (Map.Entry<String, Object> entry2 : ((JavaBeanSerializer) objectWriter).getFieldValuesMap(obj).entrySet()) {
                    String key2 = entry2.getKey();
                    if (key2 instanceof String) {
                        if (str.equals("/")) {
                            sb = new StringBuilder();
                            sb.append("/");
                        } else {
                            sb = new StringBuilder();
                            sb.append(str);
                            sb.append("/");
                        }
                        sb.append(key2);
                        paths(map, map2, sb.toString(), entry2.getValue(), serializeConfig);
                    }
                }
            } catch (Exception e2) {
                throw new JSONException("toJSON error", e2);
            }
        }
    }

    public static int size(Object obj, String str) {
        JSONPath compile = compile(str);
        return compile.evalSize(compile.eval(obj));
    }

    public static boolean contains(Object obj, String str) {
        if (obj == null) {
            return false;
        }
        return compile(str).contains(obj);
    }

    public static boolean containsValue(Object obj, String str, Object obj2) {
        return compile(str).containsValue(obj, obj2);
    }

    public static Object extract(String str, String str2, ParserConfig parserConfig, int i2, Feature... featureArr) {
        DefaultJSONParser defaultJSONParser = new DefaultJSONParser(str, parserConfig, i2 | Feature.OrderedField.mask);
        Object extract = compile(str2).extract(defaultJSONParser);
        defaultJSONParser.lexer.close();
        return extract;
    }

    public static void arrayAdd(Object obj, String str, Object... objArr) {
        compile(str).arrayAdd(obj, objArr);
    }

    public static Object extract(String str, String str2) {
        return extract(str, str2, ParserConfig.global, JSON.DEFAULT_PARSER_FEATURE, new Feature[0]);
    }

    public static boolean set(Object obj, String str, Object obj2) {
        return compile(str).set(obj, obj2);
    }

    public static boolean remove(Object obj, String str) {
        return compile(str).remove(obj);
    }
}
