package com.alibaba.fastjson.parser;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.util.IOUtils;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import java.io.Closeable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public abstract class JSONLexerBase implements JSONLexer, Closeable {
    public static final int INT_MULTMIN_RADIX_TEN = -214748364;
    public static final long MULTMIN_RADIX_TEN = -922337203685477580L;
    private static final ThreadLocal<char[]> SBUF_LOCAL = new ThreadLocal<>();
    public static final int[] digits;
    public static final char[] typeFieldName;

    /* renamed from: bp */
    public int f8506bp;

    /* renamed from: ch */
    public char f8507ch;
    public int eofPos;
    public int features;
    public boolean hasSpecial;

    /* renamed from: np */
    public int f8508np;
    public int pos;
    public char[] sbuf;

    /* renamed from: sp */
    public int f8509sp;
    public String stringDefaultValue;
    public int token;
    public Calendar calendar = null;
    public TimeZone timeZone = JSON.defaultTimeZone;
    public Locale locale = JSON.defaultLocale;
    public int matchStat = 0;
    public int nanos = 0;

    static {
        StringBuilder m586H = C1499a.m586H("\"");
        m586H.append(JSON.DEFAULT_TYPE_KEY);
        m586H.append("\":\"");
        typeFieldName = m586H.toString().toCharArray();
        digits = new int[103];
        for (int i2 = 48; i2 <= 57; i2++) {
            digits[i2] = i2 - 48;
        }
        for (int i3 = 97; i3 <= 102; i3++) {
            digits[i3] = (i3 - 97) + 10;
        }
        for (int i4 = 65; i4 <= 70; i4++) {
            digits[i4] = (i4 - 65) + 10;
        }
    }

    public JSONLexerBase(int i2) {
        this.stringDefaultValue = null;
        this.features = i2;
        if ((i2 & Feature.InitStringFieldAsEmpty.mask) != 0) {
            this.stringDefaultValue = "";
        }
        char[] cArr = SBUF_LOCAL.get();
        this.sbuf = cArr;
        if (cArr == null) {
            this.sbuf = new char[512];
        }
    }

    public static boolean isWhitespace(char c2) {
        return c2 <= ' ' && (c2 == ' ' || c2 == '\n' || c2 == '\r' || c2 == '\t' || c2 == '\f' || c2 == '\b');
    }

    public static String readString(char[] cArr, int i2) {
        int i3;
        char[] cArr2 = new char[i2];
        int i4 = 0;
        int i5 = 0;
        while (i4 < i2) {
            char c2 = cArr[i4];
            if (c2 != '\\') {
                cArr2[i5] = c2;
                i5++;
            } else {
                i4++;
                char c3 = cArr[i4];
                if (c3 == '\"') {
                    i3 = i5 + 1;
                    cArr2[i5] = Typography.quote;
                } else if (c3 != '\'') {
                    if (c3 != 'F') {
                        if (c3 == '\\') {
                            i3 = i5 + 1;
                            cArr2[i5] = '\\';
                        } else if (c3 == 'b') {
                            i3 = i5 + 1;
                            cArr2[i5] = '\b';
                        } else if (c3 != 'f') {
                            if (c3 == 'n') {
                                i3 = i5 + 1;
                                cArr2[i5] = '\n';
                            } else if (c3 == 'r') {
                                i3 = i5 + 1;
                                cArr2[i5] = '\r';
                            } else if (c3 != 'x') {
                                switch (c3) {
                                    case '/':
                                        i3 = i5 + 1;
                                        cArr2[i5] = '/';
                                        break;
                                    case '0':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 0;
                                        break;
                                    case '1':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 1;
                                        break;
                                    case '2':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 2;
                                        break;
                                    case '3':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 3;
                                        break;
                                    case '4':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 4;
                                        break;
                                    case '5':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 5;
                                        break;
                                    case '6':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 6;
                                        break;
                                    case '7':
                                        i3 = i5 + 1;
                                        cArr2[i5] = 7;
                                        break;
                                    default:
                                        switch (c3) {
                                            case 't':
                                                i3 = i5 + 1;
                                                cArr2[i5] = '\t';
                                                break;
                                            case 'u':
                                                i3 = i5 + 1;
                                                int i6 = i4 + 1;
                                                int i7 = i6 + 1;
                                                int i8 = i7 + 1;
                                                i4 = i8 + 1;
                                                cArr2[i5] = (char) Integer.parseInt(new String(new char[]{cArr[i6], cArr[i7], cArr[i8], cArr[i4]}), 16);
                                                break;
                                            case 'v':
                                                i3 = i5 + 1;
                                                cArr2[i5] = 11;
                                                break;
                                            default:
                                                throw new JSONException("unclosed.str.lit");
                                        }
                                }
                            } else {
                                i3 = i5 + 1;
                                int[] iArr = digits;
                                int i9 = i4 + 1;
                                int i10 = iArr[cArr[i9]] * 16;
                                i4 = i9 + 1;
                                cArr2[i5] = (char) (i10 + iArr[cArr[i4]]);
                            }
                        }
                    }
                    i3 = i5 + 1;
                    cArr2[i5] = '\f';
                } else {
                    i3 = i5 + 1;
                    cArr2[i5] = '\'';
                }
                i5 = i3;
            }
            i4++;
        }
        return new String(cArr2, 0, i5);
    }

    /* JADX WARN: Code restructure failed: missing block: B:89:0x014a, code lost:
    
        throw new com.alibaba.fastjson.JSONException("invalid escape character \\x" + r1 + r2);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void scanStringSingleQuote() {
        /*
            Method dump skipped, instructions count: 438
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.scanStringSingleQuote():void");
    }

    public abstract String addSymbol(int i2, int i3, int i4, SymbolTable symbolTable);

    public abstract void arrayCopy(int i2, char[] cArr, int i3, int i4);

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract byte[] bytesValue();

    public abstract boolean charArrayCompare(char[] cArr);

    public abstract char charAt(int i2);

    @Override // com.alibaba.fastjson.parser.JSONLexer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        char[] cArr = this.sbuf;
        if (cArr.length <= 8192) {
            SBUF_LOCAL.set(cArr);
        }
        this.sbuf = null;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public void config(Feature feature, boolean z) {
        int config = Feature.config(this.features, feature, z);
        this.features = config;
        if ((config & Feature.InitStringFieldAsEmpty.mask) != 0) {
            this.stringDefaultValue = "";
        }
    }

    public abstract void copyTo(int i2, int i3, char[] cArr);

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final Number decimalValue(boolean z) {
        char charAt = charAt((this.f8508np + this.f8509sp) - 1);
        try {
            return charAt == 'F' ? Float.valueOf(Float.parseFloat(numberString())) : charAt == 'D' ? Double.valueOf(Double.parseDouble(numberString())) : z ? decimalValue() : Double.valueOf(doubleValue());
        } catch (NumberFormatException e2) {
            throw new JSONException(e2.getMessage() + ", " + info());
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract BigDecimal decimalValue();

    public double doubleValue() {
        return Double.parseDouble(numberString());
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public float floatValue() {
        char charAt;
        String numberString = numberString();
        float parseFloat = Float.parseFloat(numberString);
        if ((parseFloat == 0.0f || parseFloat == Float.POSITIVE_INFINITY) && (charAt = numberString.charAt(0)) > '0' && charAt <= '9') {
            throw new JSONException(C1499a.m637w("float overflow : ", numberString));
        }
        return parseFloat;
    }

    public Calendar getCalendar() {
        return this.calendar;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final char getCurrent() {
        return this.f8507ch;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public int getFeatures() {
        return this.features;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public Locale getLocale() {
        return this.locale;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public TimeZone getTimeZone() {
        return this.timeZone;
    }

    public abstract int indexOf(char c2, int i2);

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public String info() {
        return "";
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int intValue() {
        int i2;
        boolean z;
        int i3 = 0;
        if (this.f8508np == -1) {
            this.f8508np = 0;
        }
        int i4 = this.f8508np;
        int i5 = this.f8509sp + i4;
        if (charAt(i4) == '-') {
            i2 = Integer.MIN_VALUE;
            i4++;
            z = true;
        } else {
            i2 = -2147483647;
            z = false;
        }
        if (i4 < i5) {
            i3 = -(charAt(i4) - '0');
            i4++;
        }
        while (i4 < i5) {
            int i6 = i4 + 1;
            char charAt = charAt(i4);
            if (charAt == 'L' || charAt == 'S' || charAt == 'B') {
                i4 = i6;
                break;
            }
            int i7 = charAt - '0';
            if (i3 < -214748364) {
                throw new NumberFormatException(numberString());
            }
            int i8 = i3 * 10;
            if (i8 < i2 + i7) {
                throw new NumberFormatException(numberString());
            }
            i3 = i8 - i7;
            i4 = i6;
        }
        if (!z) {
            return -i3;
        }
        if (i4 > this.f8508np + 1) {
            return i3;
        }
        throw new NumberFormatException(numberString());
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final Number integerValue() {
        long j2;
        long j3;
        boolean z = false;
        if (this.f8508np == -1) {
            this.f8508np = 0;
        }
        int i2 = this.f8508np;
        int i3 = this.f8509sp + i2;
        char c2 = ' ';
        char charAt = charAt(i3 - 1);
        if (charAt == 'B') {
            i3--;
            c2 = 'B';
        } else if (charAt == 'L') {
            i3--;
            c2 = 'L';
        } else if (charAt == 'S') {
            i3--;
            c2 = 'S';
        }
        if (charAt(this.f8508np) == '-') {
            j2 = Long.MIN_VALUE;
            i2++;
            z = true;
        } else {
            j2 = -9223372036854775807L;
        }
        long j4 = MULTMIN_RADIX_TEN;
        if (i2 < i3) {
            j3 = -(charAt(i2) - '0');
            i2++;
        } else {
            j3 = 0;
        }
        while (i2 < i3) {
            int i4 = i2 + 1;
            int charAt2 = charAt(i2) - '0';
            if (j3 < j4) {
                return new BigInteger(numberString());
            }
            long j5 = j3 * 10;
            long j6 = charAt2;
            if (j5 < j2 + j6) {
                return new BigInteger(numberString());
            }
            j3 = j5 - j6;
            i2 = i4;
            j4 = MULTMIN_RADIX_TEN;
        }
        if (!z) {
            long j7 = -j3;
            return (j7 > 2147483647L || c2 == 'L') ? Long.valueOf(j7) : c2 == 'S' ? Short.valueOf((short) j7) : c2 == 'B' ? Byte.valueOf((byte) j7) : Integer.valueOf((int) j7);
        }
        if (i2 > this.f8508np + 1) {
            return (j3 < -2147483648L || c2 == 'L') ? Long.valueOf(j3) : c2 == 'S' ? Short.valueOf((short) j3) : c2 == 'B' ? Byte.valueOf((byte) j3) : Integer.valueOf((int) j3);
        }
        throw new NumberFormatException(numberString());
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public boolean isBlankInput() {
        int i2 = 0;
        while (true) {
            char charAt = charAt(i2);
            if (charAt == 26) {
                this.token = 20;
                return true;
            }
            if (!isWhitespace(charAt)) {
                return false;
            }
            i2++;
        }
    }

    public abstract boolean isEOF();

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final boolean isEnabled(Feature feature) {
        return isEnabled(feature.mask);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final boolean isRef() {
        return this.f8509sp == 4 && charAt(this.f8508np + 1) == '$' && charAt(this.f8508np + 2) == 'r' && charAt(this.f8508np + 3) == 'e' && charAt(this.f8508np + 4) == 'f';
    }

    public void lexError(String str, Object... objArr) {
        this.token = 1;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0038  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0085  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:22:0x005c -> B:10:0x0032). Please report as a decompilation issue!!! */
    @Override // com.alibaba.fastjson.parser.JSONLexer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long longValue() {
        /*
            r15 = this;
            int r0 = r15.f8508np
            r1 = 0
            r2 = -1
            if (r0 != r2) goto L8
            r15.f8508np = r1
        L8:
            int r0 = r15.f8508np
            int r2 = r15.f8509sp
            int r2 = r2 + r0
            char r3 = r15.charAt(r0)
            r4 = 45
            r5 = 1
            if (r3 != r4) goto L1c
            r3 = -9223372036854775808
            int r0 = r0 + 1
            r1 = 1
            goto L21
        L1c:
            r3 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
        L21:
            r6 = -922337203685477580(0xf333333333333334, double:-8.390303882365713E246)
            if (r0 >= r2) goto L34
            int r8 = r0 + 1
            char r0 = r15.charAt(r0)
            int r0 = r0 + (-48)
            int r0 = -r0
            long r9 = (long) r0
        L32:
            r0 = r8
            goto L36
        L34:
            r9 = 0
        L36:
            if (r0 >= r2) goto L73
            int r8 = r0 + 1
            char r0 = r15.charAt(r0)
            r11 = 76
            if (r0 == r11) goto L72
            r11 = 83
            if (r0 == r11) goto L72
            r11 = 66
            if (r0 != r11) goto L4b
            goto L72
        L4b:
            int r0 = r0 + (-48)
            int r11 = (r9 > r6 ? 1 : (r9 == r6 ? 0 : -1))
            if (r11 < 0) goto L68
            r11 = 10
            long r9 = r9 * r11
            long r11 = (long) r0
            long r13 = r3 + r11
            int r0 = (r9 > r13 ? 1 : (r9 == r13 ? 0 : -1))
            if (r0 < 0) goto L5e
            long r9 = r9 - r11
            goto L32
        L5e:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.String r1 = r15.numberString()
            r0.<init>(r1)
            throw r0
        L68:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.String r1 = r15.numberString()
            r0.<init>(r1)
            throw r0
        L72:
            r0 = r8
        L73:
            if (r1 == 0) goto L85
            int r1 = r15.f8508np
            int r1 = r1 + r5
            if (r0 <= r1) goto L7b
            return r9
        L7b:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.String r1 = r15.numberString()
            r0.<init>(r1)
            throw r0
        L85:
            long r0 = -r9
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.longValue():long");
    }

    public final boolean matchField(char[] cArr) {
        while (!charArrayCompare(cArr)) {
            if (!isWhitespace(this.f8507ch)) {
                return false;
            }
            next();
        }
        int length = this.f8506bp + cArr.length;
        this.f8506bp = length;
        char charAt = charAt(length);
        this.f8507ch = charAt;
        if (charAt == '{') {
            next();
            this.token = 12;
        } else if (charAt == '[') {
            next();
            this.token = 14;
        } else if (charAt == 'S' && charAt(this.f8506bp + 1) == 'e' && charAt(this.f8506bp + 2) == 't' && charAt(this.f8506bp + 3) == '[') {
            int i2 = this.f8506bp + 3;
            this.f8506bp = i2;
            this.f8507ch = charAt(i2);
            this.token = 21;
        } else {
            nextToken();
        }
        return true;
    }

    public boolean matchField2(char[] cArr) {
        throw new UnsupportedOperationException();
    }

    public final int matchStat() {
        return this.matchStat;
    }

    public Collection<String> newCollectionByType(Class<?> cls) {
        if (cls.isAssignableFrom(HashSet.class)) {
            return new HashSet();
        }
        if (cls.isAssignableFrom(ArrayList.class)) {
            return new ArrayList();
        }
        if (cls.isAssignableFrom(LinkedList.class)) {
            return new LinkedList();
        }
        try {
            return (Collection) cls.newInstance();
        } catch (Exception e2) {
            throw new JSONException(e2.getMessage(), e2);
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract char next();

    public final void nextIdent() {
        while (isWhitespace(this.f8507ch)) {
            next();
        }
        char c2 = this.f8507ch;
        if (c2 == '_' || c2 == '$' || Character.isLetter(c2)) {
            scanIdent();
        } else {
            nextToken();
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextToken() {
        this.f8509sp = 0;
        while (true) {
            this.pos = this.f8506bp;
            char c2 = this.f8507ch;
            if (c2 == '/') {
                skipComment();
            } else {
                if (c2 == '\"') {
                    scanString();
                    return;
                }
                if (c2 == ',') {
                    next();
                    this.token = 16;
                    return;
                }
                if (c2 >= '0' && c2 <= '9') {
                    scanNumber();
                    return;
                }
                if (c2 == '-') {
                    scanNumber();
                    return;
                }
                switch (c2) {
                    case '\b':
                    case '\t':
                    case '\n':
                    case '\f':
                    case '\r':
                    case ' ':
                        next();
                        break;
                    case '\'':
                        if (!isEnabled(Feature.AllowSingleQuotes)) {
                            throw new JSONException("Feature.AllowSingleQuotes is false");
                        }
                        scanStringSingleQuote();
                        return;
                    case '(':
                        next();
                        this.token = 10;
                        return;
                    case ')':
                        next();
                        this.token = 11;
                        return;
                    case '+':
                        next();
                        scanNumber();
                        return;
                    case '.':
                        next();
                        this.token = 25;
                        return;
                    case ':':
                        next();
                        this.token = 17;
                        return;
                    case ';':
                        next();
                        this.token = 24;
                        return;
                    case 'N':
                    case 'S':
                    case 'T':
                    case 'u':
                        scanIdent();
                        return;
                    case '[':
                        next();
                        this.token = 14;
                        return;
                    case ']':
                        next();
                        this.token = 15;
                        return;
                    case 'f':
                        scanFalse();
                        return;
                    case 'n':
                        scanNullOrNew();
                        return;
                    case 't':
                        scanTrue();
                        return;
                    case 'x':
                        scanHex();
                        return;
                    case '{':
                        next();
                        this.token = 12;
                        return;
                    case '}':
                        next();
                        this.token = 13;
                        return;
                    default:
                        if (isEOF()) {
                            if (this.token == 20) {
                                throw new JSONException("EOF error");
                            }
                            this.token = 20;
                            int i2 = this.f8506bp;
                            this.pos = i2;
                            this.eofPos = i2;
                            return;
                        }
                        char c3 = this.f8507ch;
                        if (c3 > 31 && c3 != 127) {
                            lexError("illegal.char", String.valueOf((int) c3));
                            next();
                            return;
                        } else {
                            next();
                            break;
                        }
                }
            }
        }
    }

    public final void nextTokenWithChar(char c2) {
        this.f8509sp = 0;
        while (true) {
            char c3 = this.f8507ch;
            if (c3 == c2) {
                next();
                nextToken();
                return;
            }
            if (c3 != ' ' && c3 != '\n' && c3 != '\r' && c3 != '\t' && c3 != '\f' && c3 != '\b') {
                throw new JSONException("not match " + c2 + " - " + this.f8507ch + ", info : " + info());
            }
            next();
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextTokenWithColon() {
        nextTokenWithChar(':');
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract String numberString();

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int pos() {
        return this.pos;
    }

    public final void putChar(char c2) {
        int i2 = this.f8509sp;
        char[] cArr = this.sbuf;
        if (i2 == cArr.length) {
            char[] cArr2 = new char[cArr.length * 2];
            System.arraycopy(cArr, 0, cArr2, 0, cArr.length);
            this.sbuf = cArr2;
        }
        char[] cArr3 = this.sbuf;
        int i3 = this.f8509sp;
        this.f8509sp = i3 + 1;
        cArr3[i3] = c2;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void resetStringPosition() {
        this.f8509sp = 0;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public boolean scanBoolean(char c2) {
        boolean z = false;
        this.matchStat = 0;
        char charAt = charAt(this.f8506bp + 0);
        int i2 = 5;
        if (charAt == 't') {
            if (charAt(this.f8506bp + 1) != 'r' || C1499a.m605a(this.f8506bp, 1, 1, this) != 'u' || C1499a.m605a(this.f8506bp, 1, 2, this) != 'e') {
                this.matchStat = -1;
                return false;
            }
            charAt = charAt(this.f8506bp + 4);
            z = true;
        } else if (charAt != 'f') {
            if (charAt == '1') {
                charAt = charAt(this.f8506bp + 1);
                z = true;
            } else if (charAt == '0') {
                charAt = charAt(this.f8506bp + 1);
            } else {
                i2 = 1;
            }
            i2 = 2;
        } else {
            if (charAt(this.f8506bp + 1) != 'a' || C1499a.m605a(this.f8506bp, 1, 1, this) != 'l' || C1499a.m605a(this.f8506bp, 1, 2, this) != 's' || C1499a.m605a(this.f8506bp, 1, 3, this) != 'e') {
                this.matchStat = -1;
                return false;
            }
            charAt = charAt(this.f8506bp + 5);
            i2 = 6;
        }
        while (charAt != c2) {
            if (!isWhitespace(charAt)) {
                this.matchStat = -1;
                return z;
            }
            charAt = charAt(this.f8506bp + i2);
            i2++;
        }
        int i3 = this.f8506bp + i2;
        this.f8506bp = i3;
        this.f8507ch = charAt(i3);
        this.matchStat = 3;
        return z;
    }

    public Date scanDate(char c2) {
        long j2;
        Date date;
        int i2;
        boolean z = false;
        this.matchStat = 0;
        char charAt = charAt(this.f8506bp + 0);
        int i3 = 5;
        if (charAt == '\"') {
            int indexOf = indexOf(Typography.quote, this.f8506bp + 1);
            if (indexOf == -1) {
                throw new JSONException("unclosed str");
            }
            int i4 = this.f8506bp + 1;
            String subString = subString(i4, indexOf - i4);
            if (subString.indexOf(92) != -1) {
                while (true) {
                    int i5 = 0;
                    for (int i6 = indexOf - 1; i6 >= 0 && charAt(i6) == '\\'; i6--) {
                        i5++;
                    }
                    if (i5 % 2 == 0) {
                        break;
                    }
                    indexOf = indexOf(Typography.quote, indexOf + 1);
                }
                int i7 = this.f8506bp;
                int i8 = indexOf - (i7 + 1);
                subString = readString(sub_chars(i7 + 1, i8), i8);
            }
            int i9 = this.f8506bp;
            int i10 = (indexOf - (i9 + 1)) + 1 + 1;
            int i11 = i10 + 1;
            charAt = charAt(i9 + i10);
            JSONScanner jSONScanner = new JSONScanner(subString);
            try {
                if (!jSONScanner.scanISO8601DateIfMatch(false)) {
                    this.matchStat = -1;
                    return null;
                }
                date = jSONScanner.getCalendar().getTime();
                jSONScanner.close();
                i3 = i11;
            } finally {
                jSONScanner.close();
            }
        } else {
            char c3 = '9';
            int i12 = 2;
            if (charAt == '-' || (charAt >= '0' && charAt <= '9')) {
                if (charAt == '-') {
                    charAt = charAt(this.f8506bp + 1);
                    z = true;
                } else {
                    i12 = 1;
                }
                if (charAt < '0' || charAt > '9') {
                    j2 = 0;
                } else {
                    j2 = charAt - '0';
                    while (true) {
                        i2 = i12 + 1;
                        charAt = charAt(this.f8506bp + i12);
                        if (charAt < '0' || charAt > c3) {
                            break;
                        }
                        j2 = (j2 * 10) + (charAt - '0');
                        c3 = '9';
                        i12 = i2;
                    }
                    i12 = i2;
                }
                if (j2 < 0) {
                    this.matchStat = -1;
                    return null;
                }
                if (z) {
                    j2 = -j2;
                }
                date = new Date(j2);
                i3 = i12;
            } else {
                if (charAt != 'n' || charAt(this.f8506bp + 1) != 'u' || C1499a.m605a(this.f8506bp, 1, 1, this) != 'l' || C1499a.m605a(this.f8506bp, 1, 2, this) != 'l') {
                    this.matchStat = -1;
                    return null;
                }
                this.matchStat = 5;
                charAt = charAt(this.f8506bp + 4);
                date = null;
            }
        }
        if (charAt == ',') {
            int i13 = this.f8506bp + i3;
            this.f8506bp = i13;
            this.f8507ch = charAt(i13);
            this.matchStat = 3;
            this.token = 16;
            return date;
        }
        if (charAt != ']') {
            this.matchStat = -1;
            return null;
        }
        int i14 = i3 + 1;
        char charAt2 = charAt(this.f8506bp + i3);
        if (charAt2 == ',') {
            this.token = 16;
            int i15 = this.f8506bp + i14;
            this.f8506bp = i15;
            this.f8507ch = charAt(i15);
        } else if (charAt2 == ']') {
            this.token = 15;
            int i16 = this.f8506bp + i14;
            this.f8506bp = i16;
            this.f8507ch = charAt(i16);
        } else if (charAt2 == '}') {
            this.token = 13;
            int i17 = this.f8506bp + i14;
            this.f8506bp = i17;
            this.f8507ch = charAt(i17);
        } else {
            if (charAt2 != 26) {
                this.matchStat = -1;
                return null;
            }
            this.token = 20;
            this.f8506bp = (i14 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return date;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public BigDecimal scanDecimal(char c2) {
        int i2;
        int i3;
        char charAt;
        JSONLexerBase jSONLexerBase;
        int i4;
        int i5;
        char c3;
        this.matchStat = 0;
        char charAt2 = charAt(this.f8506bp + 0);
        boolean z = charAt2 == '\"';
        if (z) {
            charAt2 = charAt(this.f8506bp + 1);
            i2 = 2;
        } else {
            i2 = 1;
        }
        if (charAt2 == '-') {
            charAt2 = charAt(this.f8506bp + i2);
            i2++;
        }
        if (charAt2 < '0' || charAt2 > '9') {
            if (charAt2 != 'n' || charAt(this.f8506bp + i2) != 'u' || C1499a.m605a(this.f8506bp, i2, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i2, 2, this) != 'l') {
                this.matchStat = -1;
                return null;
            }
            this.matchStat = 5;
            int i6 = i2 + 3;
            int i7 = i6 + 1;
            char charAt3 = charAt(this.f8506bp + i6);
            if (z && charAt3 == '\"') {
                int i8 = i7 + 1;
                char charAt4 = charAt(this.f8506bp + i7);
                i7 = i8;
                charAt3 = charAt4;
            }
            while (charAt3 != ',') {
                if (charAt3 == '}') {
                    int i9 = this.f8506bp + i7;
                    this.f8506bp = i9;
                    this.f8507ch = charAt(i9);
                    this.matchStat = 5;
                    this.token = 13;
                    return null;
                }
                if (!isWhitespace(charAt3)) {
                    this.matchStat = -1;
                    return null;
                }
                int i10 = i7 + 1;
                char charAt5 = charAt(this.f8506bp + i7);
                i7 = i10;
                charAt3 = charAt5;
            }
            int i11 = this.f8506bp + i7;
            this.f8506bp = i11;
            this.f8507ch = charAt(i11);
            this.matchStat = 5;
            this.token = 16;
            return null;
        }
        while (true) {
            i3 = i2 + 1;
            charAt = charAt(this.f8506bp + i2);
            if (charAt < '0' || charAt > '9') {
                break;
            }
            i2 = i3;
        }
        if (charAt == '.') {
            int i12 = i3 + 1;
            char charAt6 = charAt(this.f8506bp + i3);
            if (charAt6 >= '0' && charAt6 <= '9') {
                while (true) {
                    i3 = i12 + 1;
                    charAt = charAt(this.f8506bp + i12);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    i12 = i3;
                }
            } else {
                this.matchStat = -1;
                return null;
            }
        }
        if (charAt == 'e' || charAt == 'E') {
            int i13 = i3 + 1;
            charAt = charAt(this.f8506bp + i3);
            if (charAt == '+' || charAt == '-') {
                int i14 = i13 + 1;
                charAt = charAt(this.f8506bp + i13);
                jSONLexerBase = this;
                i3 = i14;
                c3 = '0';
            } else {
                i3 = i13;
                c3 = '0';
                jSONLexerBase = this;
            }
            while (charAt >= c3 && charAt <= '9') {
                charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
                i3++;
            }
        } else {
            jSONLexerBase = this;
        }
        if (!z) {
            i4 = jSONLexerBase.f8506bp;
            i5 = ((i4 + i3) - i4) - 1;
        } else {
            if (charAt != '\"') {
                jSONLexerBase.matchStat = -1;
                return null;
            }
            int i15 = i3 + 1;
            charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
            int i16 = jSONLexerBase.f8506bp;
            i4 = i16 + 1;
            i5 = ((i16 + i15) - i4) - 2;
            i3 = i15;
        }
        BigDecimal bigDecimal = new BigDecimal(jSONLexerBase.sub_chars(i4, i5));
        if (charAt == ',') {
            int i17 = jSONLexerBase.f8506bp + i3;
            jSONLexerBase.f8506bp = i17;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i17);
            jSONLexerBase.matchStat = 3;
            jSONLexerBase.token = 16;
            return bigDecimal;
        }
        if (charAt != ']') {
            jSONLexerBase.matchStat = -1;
            return null;
        }
        int i18 = i3 + 1;
        char charAt7 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
        if (charAt7 == ',') {
            jSONLexerBase.token = 16;
            int i19 = jSONLexerBase.f8506bp + i18;
            jSONLexerBase.f8506bp = i19;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i19);
        } else if (charAt7 == ']') {
            jSONLexerBase.token = 15;
            int i20 = jSONLexerBase.f8506bp + i18;
            jSONLexerBase.f8506bp = i20;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i20);
        } else if (charAt7 == '}') {
            jSONLexerBase.token = 13;
            int i21 = jSONLexerBase.f8506bp + i18;
            jSONLexerBase.f8506bp = i21;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i21);
        } else {
            if (charAt7 != 26) {
                jSONLexerBase.matchStat = -1;
                return null;
            }
            jSONLexerBase.token = 20;
            jSONLexerBase.f8506bp = (i18 - 1) + jSONLexerBase.f8506bp;
            jSONLexerBase.f8507ch = JSONLexer.EOI;
        }
        jSONLexerBase.matchStat = 4;
        return bigDecimal;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public double scanDouble(char c2) {
        int i2;
        int i3;
        char charAt;
        boolean z;
        long j2;
        JSONLexerBase jSONLexerBase;
        double d2;
        int i4;
        long j3;
        boolean z2;
        boolean z3;
        char c3;
        char c4;
        int i5;
        int i6;
        double parseDouble;
        int i7;
        this.matchStat = 0;
        char charAt2 = charAt(this.f8506bp + 0);
        boolean z4 = charAt2 == '\"';
        if (z4) {
            charAt2 = charAt(this.f8506bp + 1);
            i2 = 2;
        } else {
            i2 = 1;
        }
        boolean z5 = charAt2 == '-';
        if (z5) {
            charAt2 = charAt(this.f8506bp + i2);
            i2++;
        }
        char c5 = '0';
        if (charAt2 >= '0') {
            char c6 = '9';
            if (charAt2 <= '9') {
                long j4 = charAt2 - '0';
                while (true) {
                    i3 = i2 + 1;
                    charAt = charAt(this.f8506bp + i2);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    j4 = (j4 * 10) + (charAt - '0');
                    i2 = i3;
                }
                if (charAt == '.') {
                    int i8 = i3 + 1;
                    char charAt3 = charAt(this.f8506bp + i3);
                    if (charAt3 >= '0' && charAt3 <= '9') {
                        z = z5;
                        j4 = (j4 * 10) + (charAt3 - '0');
                        j2 = 10;
                        while (true) {
                            i3 = i8 + 1;
                            charAt = charAt(this.f8506bp + i8);
                            if (charAt < c5 || charAt > c6) {
                                break;
                            }
                            j4 = (j4 * 10) + (charAt - '0');
                            j2 *= 10;
                            i8 = i3;
                            c5 = '0';
                            c6 = '9';
                        }
                    } else {
                        this.matchStat = -1;
                        return ShadowDrawableWrapper.COS_45;
                    }
                } else {
                    z = z5;
                    j2 = 1;
                }
                boolean z6 = charAt == 'e' || charAt == 'E';
                if (z6) {
                    int i9 = i3 + 1;
                    char charAt4 = charAt(this.f8506bp + i3);
                    if (charAt4 == '+' || charAt4 == '-') {
                        charAt4 = charAt(this.f8506bp + i9);
                        jSONLexerBase = this;
                        d2 = 0.0d;
                        i7 = i9 + 1;
                    } else {
                        jSONLexerBase = this;
                        d2 = 0.0d;
                        i7 = i9;
                    }
                    long j5 = j4;
                    i4 = -1;
                    j3 = j2;
                    z2 = z6;
                    z3 = z4;
                    c3 = charAt4;
                    c4 = c2;
                    while (c3 >= '0' && c3 <= '9') {
                        c3 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i7);
                        i7++;
                    }
                    j4 = j5;
                    i3 = i7;
                } else {
                    jSONLexerBase = this;
                    d2 = 0.0d;
                    i4 = -1;
                    j3 = j2;
                    z2 = z6;
                    z3 = z4;
                    c3 = charAt;
                    c4 = c2;
                }
                if (!z3) {
                    i5 = jSONLexerBase.f8506bp;
                    i6 = ((i5 + i3) - i5) - 1;
                } else {
                    if (c3 != '\"') {
                        jSONLexerBase.matchStat = i4;
                        return d2;
                    }
                    int i10 = i3 + 1;
                    c3 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
                    int i11 = jSONLexerBase.f8506bp;
                    i5 = i11 + 1;
                    i6 = ((i11 + i10) - i5) - 2;
                    i3 = i10;
                }
                if (z2 || i6 >= 17) {
                    parseDouble = Double.parseDouble(jSONLexerBase.subString(i5, i6));
                } else {
                    parseDouble = j4 / j3;
                    if (z) {
                        parseDouble = -parseDouble;
                    }
                }
                if (c3 != c4) {
                    jSONLexerBase.matchStat = i4;
                    return parseDouble;
                }
                int i12 = jSONLexerBase.f8506bp + i3;
                jSONLexerBase.f8506bp = i12;
                jSONLexerBase.f8507ch = jSONLexerBase.charAt(i12);
                jSONLexerBase.matchStat = 3;
                jSONLexerBase.token = 16;
                return parseDouble;
            }
        }
        if (charAt2 != 'n' || charAt(this.f8506bp + i2) != 'u' || C1499a.m605a(this.f8506bp, i2, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i2, 2, this) != 'l') {
            this.matchStat = -1;
            return ShadowDrawableWrapper.COS_45;
        }
        this.matchStat = 5;
        int i13 = i2 + 3;
        int i14 = i13 + 1;
        char charAt5 = charAt(this.f8506bp + i13);
        if (z4 && charAt5 == '\"') {
            int i15 = i14 + 1;
            char charAt6 = charAt(this.f8506bp + i14);
            i14 = i15;
            charAt5 = charAt6;
        }
        while (charAt5 != ',') {
            if (charAt5 == ']') {
                int i16 = this.f8506bp + i14;
                this.f8506bp = i16;
                this.f8507ch = charAt(i16);
                this.matchStat = 5;
                this.token = 15;
                return ShadowDrawableWrapper.COS_45;
            }
            if (!isWhitespace(charAt5)) {
                this.matchStat = -1;
                return ShadowDrawableWrapper.COS_45;
            }
            int i17 = i14 + 1;
            char charAt7 = charAt(this.f8506bp + i14);
            i14 = i17;
            charAt5 = charAt7;
        }
        int i18 = this.f8506bp + i14;
        this.f8506bp = i18;
        this.f8507ch = charAt(i18);
        this.matchStat = 5;
        this.token = 16;
        return ShadowDrawableWrapper.COS_45;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public Enum<?> scanEnum(Class<?> cls, SymbolTable symbolTable, char c2) {
        String scanSymbolWithSeperator = scanSymbolWithSeperator(symbolTable, c2);
        if (scanSymbolWithSeperator == null) {
            return null;
        }
        return Enum.valueOf(cls, scanSymbolWithSeperator);
    }

    public long scanEnumSymbol(char[] cArr) {
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return 0L;
        }
        int length = cArr.length;
        int i2 = length + 1;
        if (charAt(this.f8506bp + length) != '\"') {
            this.matchStat = -1;
            return 0L;
        }
        long j2 = -3750763034362895579L;
        while (true) {
            int i3 = i2 + 1;
            char charAt = charAt(this.f8506bp + i2);
            if (charAt == '\"') {
                int i4 = i3 + 1;
                char charAt2 = charAt(this.f8506bp + i3);
                if (charAt2 == ',') {
                    int i5 = this.f8506bp + i4;
                    this.f8506bp = i5;
                    this.f8507ch = charAt(i5);
                    this.matchStat = 3;
                    return j2;
                }
                if (charAt2 != '}') {
                    this.matchStat = -1;
                    return 0L;
                }
                int i6 = i4 + 1;
                char charAt3 = charAt(this.f8506bp + i4);
                if (charAt3 == ',') {
                    this.token = 16;
                    int i7 = this.f8506bp + i6;
                    this.f8506bp = i7;
                    this.f8507ch = charAt(i7);
                } else if (charAt3 == ']') {
                    this.token = 15;
                    int i8 = this.f8506bp + i6;
                    this.f8506bp = i8;
                    this.f8507ch = charAt(i8);
                } else if (charAt3 == '}') {
                    this.token = 13;
                    int i9 = this.f8506bp + i6;
                    this.f8506bp = i9;
                    this.f8507ch = charAt(i9);
                } else {
                    if (charAt3 != 26) {
                        this.matchStat = -1;
                        return 0L;
                    }
                    this.token = 20;
                    this.f8506bp = (i6 - 1) + this.f8506bp;
                    this.f8507ch = JSONLexer.EOI;
                }
                this.matchStat = 4;
                return j2;
            }
            j2 = (j2 ^ ((charAt < 'A' || charAt > 'Z') ? charAt : charAt + ' ')) * 1099511628211L;
            if (charAt == '\\') {
                this.matchStat = -1;
                return 0L;
            }
            i2 = i3;
        }
    }

    public final void scanFalse() {
        if (this.f8507ch != 'f') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.f8507ch != 'a') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.f8507ch != 'l') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.f8507ch != 's') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.f8507ch != 'e') {
            throw new JSONException("error parse false");
        }
        next();
        char c2 = this.f8507ch;
        if (c2 != ' ' && c2 != ',' && c2 != '}' && c2 != ']' && c2 != '\n' && c2 != '\r' && c2 != '\t' && c2 != 26 && c2 != '\f' && c2 != '\b' && c2 != ':' && c2 != '/') {
            throw new JSONException("scan false error");
        }
        this.token = 7;
    }

    public BigInteger scanFieldBigInteger(char[] cArr) {
        int i2;
        char charAt;
        boolean z;
        int length;
        int i3;
        BigInteger bigInteger;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return null;
        }
        int length2 = cArr.length;
        int i4 = length2 + 1;
        char charAt2 = charAt(this.f8506bp + length2);
        boolean z2 = charAt2 == '\"';
        if (z2) {
            charAt2 = charAt(this.f8506bp + i4);
            i4++;
        }
        boolean z3 = charAt2 == '-';
        if (z3) {
            charAt2 = charAt(this.f8506bp + i4);
            i4++;
        }
        char c2 = '0';
        if (charAt2 >= '0') {
            char c3 = '9';
            if (charAt2 <= '9') {
                long j2 = charAt2 - '0';
                while (true) {
                    i2 = i4 + 1;
                    charAt = charAt(this.f8506bp + i4);
                    if (charAt < c2 || charAt > c3) {
                        break;
                    }
                    long j3 = (10 * j2) + (charAt - '0');
                    if (j3 < j2) {
                        z = true;
                        break;
                    }
                    j2 = j3;
                    i4 = i2;
                    c2 = '0';
                    c3 = '9';
                }
                z = false;
                if (!z2) {
                    int i5 = this.f8506bp;
                    length = cArr.length + i5;
                    i3 = ((i5 + i2) - length) - 1;
                } else {
                    if (charAt != '\"') {
                        this.matchStat = -1;
                        return null;
                    }
                    int i6 = i2 + 1;
                    charAt = charAt(this.f8506bp + i2);
                    int i7 = this.f8506bp;
                    length = cArr.length + i7 + 1;
                    i3 = ((i7 + i6) - length) - 2;
                    i2 = i6;
                }
                if (z || (i3 >= 20 && (!z3 || i3 >= 21))) {
                    bigInteger = new BigInteger(subString(length, i3));
                } else {
                    if (z3) {
                        j2 = -j2;
                    }
                    bigInteger = BigInteger.valueOf(j2);
                }
                if (charAt == ',') {
                    int i8 = this.f8506bp + i2;
                    this.f8506bp = i8;
                    this.f8507ch = charAt(i8);
                    this.matchStat = 3;
                    this.token = 16;
                    return bigInteger;
                }
                if (charAt != '}') {
                    this.matchStat = -1;
                    return null;
                }
                int i9 = i2 + 1;
                char charAt3 = charAt(this.f8506bp + i2);
                if (charAt3 == ',') {
                    this.token = 16;
                    int i10 = this.f8506bp + i9;
                    this.f8506bp = i10;
                    this.f8507ch = charAt(i10);
                } else if (charAt3 == ']') {
                    this.token = 15;
                    int i11 = this.f8506bp + i9;
                    this.f8506bp = i11;
                    this.f8507ch = charAt(i11);
                } else if (charAt3 == '}') {
                    this.token = 13;
                    int i12 = this.f8506bp + i9;
                    this.f8506bp = i12;
                    this.f8507ch = charAt(i12);
                } else {
                    if (charAt3 != 26) {
                        this.matchStat = -1;
                        return null;
                    }
                    this.token = 20;
                    this.f8506bp = (i9 - 1) + this.f8506bp;
                    this.f8507ch = JSONLexer.EOI;
                }
                this.matchStat = 4;
                return bigInteger;
            }
        }
        if (charAt2 != 'n' || charAt(this.f8506bp + i4) != 'u' || C1499a.m605a(this.f8506bp, i4, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i4, 2, this) != 'l') {
            this.matchStat = -1;
            return null;
        }
        this.matchStat = 5;
        int i13 = i4 + 3;
        int i14 = i13 + 1;
        char charAt4 = charAt(this.f8506bp + i13);
        if (z2 && charAt4 == '\"') {
            charAt4 = charAt(this.f8506bp + i14);
            i14++;
        }
        while (charAt4 != ',') {
            if (charAt4 == '}') {
                int i15 = this.f8506bp + i14;
                this.f8506bp = i15;
                this.f8507ch = charAt(i15);
                this.matchStat = 5;
                this.token = 13;
                return null;
            }
            if (!isWhitespace(charAt4)) {
                this.matchStat = -1;
                return null;
            }
            charAt4 = charAt(this.f8506bp + i14);
            i14++;
        }
        int i16 = this.f8506bp + i14;
        this.f8506bp = i16;
        this.f8507ch = charAt(i16);
        this.matchStat = 5;
        this.token = 16;
        return null;
    }

    public boolean scanFieldBoolean(char[] cArr) {
        int i2;
        boolean z;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return false;
        }
        int length = cArr.length;
        int i3 = length + 1;
        char charAt = charAt(this.f8506bp + length);
        if (charAt == 't') {
            int i4 = i3 + 1;
            if (charAt(this.f8506bp + i3) != 'r') {
                this.matchStat = -1;
                return false;
            }
            int i5 = i4 + 1;
            if (charAt(this.f8506bp + i4) != 'u') {
                this.matchStat = -1;
                return false;
            }
            i2 = i5 + 1;
            if (charAt(this.f8506bp + i5) != 'e') {
                this.matchStat = -1;
                return false;
            }
            z = true;
        } else {
            if (charAt != 'f') {
                this.matchStat = -1;
                return false;
            }
            int i6 = i3 + 1;
            if (charAt(this.f8506bp + i3) != 'a') {
                this.matchStat = -1;
                return false;
            }
            int i7 = i6 + 1;
            if (charAt(this.f8506bp + i6) != 'l') {
                this.matchStat = -1;
                return false;
            }
            int i8 = i7 + 1;
            if (charAt(this.f8506bp + i7) != 's') {
                this.matchStat = -1;
                return false;
            }
            int i9 = i8 + 1;
            if (charAt(this.f8506bp + i8) != 'e') {
                this.matchStat = -1;
                return false;
            }
            i2 = i9;
            z = false;
        }
        int i10 = i2 + 1;
        char charAt2 = charAt(this.f8506bp + i2);
        if (charAt2 == ',') {
            int i11 = this.f8506bp + i10;
            this.f8506bp = i11;
            this.f8507ch = charAt(i11);
            this.matchStat = 3;
            this.token = 16;
            return z;
        }
        if (charAt2 != '}') {
            this.matchStat = -1;
            return false;
        }
        int i12 = i10 + 1;
        char charAt3 = charAt(this.f8506bp + i10);
        if (charAt3 == ',') {
            this.token = 16;
            int i13 = this.f8506bp + i12;
            this.f8506bp = i13;
            this.f8507ch = charAt(i13);
        } else if (charAt3 == ']') {
            this.token = 15;
            int i14 = this.f8506bp + i12;
            this.f8506bp = i14;
            this.f8507ch = charAt(i14);
        } else if (charAt3 == '}') {
            this.token = 13;
            int i15 = this.f8506bp + i12;
            this.f8506bp = i15;
            this.f8507ch = charAt(i15);
        } else {
            if (charAt3 != 26) {
                this.matchStat = -1;
                return false;
            }
            this.token = 20;
            this.f8506bp = (i12 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return z;
    }

    public Date scanFieldDate(char[] cArr) {
        int i2;
        long j2;
        Date date;
        int i3;
        char charAt;
        boolean z = false;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return null;
        }
        int length = cArr.length;
        int i4 = length + 1;
        char charAt2 = charAt(this.f8506bp + length);
        if (charAt2 == '\"') {
            int indexOf = indexOf(Typography.quote, this.f8506bp + cArr.length + 1);
            if (indexOf == -1) {
                throw new JSONException("unclosed str");
            }
            int length2 = this.f8506bp + cArr.length + 1;
            String subString = subString(length2, indexOf - length2);
            if (subString.indexOf(92) != -1) {
                while (true) {
                    int i5 = 0;
                    for (int i6 = indexOf - 1; i6 >= 0 && charAt(i6) == '\\'; i6--) {
                        i5++;
                    }
                    if (i5 % 2 == 0) {
                        break;
                    }
                    indexOf = indexOf(Typography.quote, indexOf + 1);
                }
                int i7 = this.f8506bp;
                int length3 = indexOf - ((cArr.length + i7) + 1);
                subString = readString(sub_chars(i7 + cArr.length + 1, length3), length3);
            }
            int i8 = this.f8506bp;
            int length4 = (indexOf - ((cArr.length + i8) + 1)) + 1 + i4;
            i2 = length4 + 1;
            charAt2 = charAt(i8 + length4);
            JSONScanner jSONScanner = new JSONScanner(subString);
            try {
                if (!jSONScanner.scanISO8601DateIfMatch(false)) {
                    this.matchStat = -1;
                    return null;
                }
                date = jSONScanner.getCalendar().getTime();
            } finally {
                jSONScanner.close();
            }
        } else {
            if (charAt2 != '-' && (charAt2 < '0' || charAt2 > '9')) {
                this.matchStat = -1;
                return null;
            }
            if (charAt2 == '-') {
                charAt2 = charAt(this.f8506bp + i4);
                i4++;
                z = true;
            }
            if (charAt2 < '0' || charAt2 > '9') {
                i2 = i4;
                j2 = 0;
            } else {
                j2 = charAt2 - '0';
                while (true) {
                    i3 = i4 + 1;
                    charAt = charAt(this.f8506bp + i4);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    j2 = (j2 * 10) + (charAt - '0');
                    i4 = i3;
                }
                charAt2 = charAt;
                i2 = i3;
            }
            if (j2 < 0) {
                this.matchStat = -1;
                return null;
            }
            if (z) {
                j2 = -j2;
            }
            date = new Date(j2);
        }
        if (charAt2 == ',') {
            int i9 = this.f8506bp + i2;
            this.f8506bp = i9;
            this.f8507ch = charAt(i9);
            this.matchStat = 3;
            return date;
        }
        if (charAt2 != '}') {
            this.matchStat = -1;
            return null;
        }
        int i10 = i2 + 1;
        char charAt3 = charAt(this.f8506bp + i2);
        if (charAt3 == ',') {
            this.token = 16;
            int i11 = this.f8506bp + i10;
            this.f8506bp = i11;
            this.f8507ch = charAt(i11);
        } else if (charAt3 == ']') {
            this.token = 15;
            int i12 = this.f8506bp + i10;
            this.f8506bp = i12;
            this.f8507ch = charAt(i12);
        } else if (charAt3 == '}') {
            this.token = 13;
            int i13 = this.f8506bp + i10;
            this.f8506bp = i13;
            this.f8507ch = charAt(i13);
        } else {
            if (charAt3 != 26) {
                this.matchStat = -1;
                return null;
            }
            this.token = 20;
            this.f8506bp = (i10 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return date;
    }

    public BigDecimal scanFieldDecimal(char[] cArr) {
        int i2;
        char charAt;
        JSONLexerBase jSONLexerBase;
        int length;
        int i3;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return null;
        }
        int length2 = cArr.length;
        int i4 = length2 + 1;
        char charAt2 = charAt(this.f8506bp + length2);
        boolean z = charAt2 == '\"';
        if (z) {
            charAt2 = charAt(this.f8506bp + i4);
            i4++;
        }
        if (charAt2 == '-') {
            charAt2 = charAt(this.f8506bp + i4);
            i4++;
        }
        if (charAt2 < '0' || charAt2 > '9') {
            if (charAt2 != 'n' || charAt(this.f8506bp + i4) != 'u' || C1499a.m605a(this.f8506bp, i4, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i4, 2, this) != 'l') {
                this.matchStat = -1;
                return null;
            }
            this.matchStat = 5;
            int i5 = i4 + 3;
            int i6 = i5 + 1;
            char charAt3 = charAt(this.f8506bp + i5);
            if (z && charAt3 == '\"') {
                int i7 = i6 + 1;
                charAt3 = charAt(this.f8506bp + i6);
                i6 = i7;
            }
            while (charAt3 != ',') {
                if (charAt3 == '}') {
                    int i8 = this.f8506bp + i6;
                    this.f8506bp = i8;
                    this.f8507ch = charAt(i8);
                    this.matchStat = 5;
                    this.token = 13;
                    return null;
                }
                if (!isWhitespace(charAt3)) {
                    this.matchStat = -1;
                    return null;
                }
                int i9 = i6 + 1;
                charAt3 = charAt(this.f8506bp + i6);
                i6 = i9;
            }
            int i10 = this.f8506bp + i6;
            this.f8506bp = i10;
            this.f8507ch = charAt(i10);
            this.matchStat = 5;
            this.token = 16;
            return null;
        }
        while (true) {
            i2 = i4 + 1;
            charAt = charAt(this.f8506bp + i4);
            if (charAt < '0' || charAt > '9') {
                break;
            }
            i4 = i2;
        }
        if (charAt == '.') {
            int i11 = i2 + 1;
            char charAt4 = charAt(this.f8506bp + i2);
            if (charAt4 >= '0' && charAt4 <= '9') {
                while (true) {
                    i2 = i11 + 1;
                    charAt = charAt(this.f8506bp + i11);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    i11 = i2;
                }
            } else {
                this.matchStat = -1;
                return null;
            }
        }
        if (charAt == 'e' || charAt == 'E') {
            int i12 = i2 + 1;
            charAt = charAt(this.f8506bp + i2);
            if (charAt == '+' || charAt == '-') {
                int i13 = i12 + 1;
                charAt = charAt(this.f8506bp + i12);
                jSONLexerBase = this;
                i2 = i13;
            } else {
                i2 = i12;
                jSONLexerBase = this;
            }
            while (charAt >= '0' && charAt <= '9') {
                int i14 = i2 + 1;
                charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i2);
                i2 = i14;
            }
        } else {
            jSONLexerBase = this;
        }
        if (!z) {
            int i15 = jSONLexerBase.f8506bp;
            length = cArr.length + i15;
            i3 = ((i15 + i2) - length) - 1;
        } else {
            if (charAt != '\"') {
                jSONLexerBase.matchStat = -1;
                return null;
            }
            int i16 = i2 + 1;
            charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i2);
            int i17 = jSONLexerBase.f8506bp;
            length = cArr.length + i17 + 1;
            i3 = ((i17 + i16) - length) - 2;
            i2 = i16;
        }
        BigDecimal bigDecimal = new BigDecimal(jSONLexerBase.sub_chars(length, i3));
        if (charAt == ',') {
            int i18 = jSONLexerBase.f8506bp + i2;
            jSONLexerBase.f8506bp = i18;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i18);
            jSONLexerBase.matchStat = 3;
            jSONLexerBase.token = 16;
            return bigDecimal;
        }
        if (charAt != '}') {
            jSONLexerBase.matchStat = -1;
            return null;
        }
        int i19 = i2 + 1;
        char charAt5 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i2);
        if (charAt5 == ',') {
            jSONLexerBase.token = 16;
            int i20 = jSONLexerBase.f8506bp + i19;
            jSONLexerBase.f8506bp = i20;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i20);
        } else if (charAt5 == ']') {
            jSONLexerBase.token = 15;
            int i21 = jSONLexerBase.f8506bp + i19;
            jSONLexerBase.f8506bp = i21;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i21);
        } else if (charAt5 == '}') {
            jSONLexerBase.token = 13;
            int i22 = jSONLexerBase.f8506bp + i19;
            jSONLexerBase.f8506bp = i22;
            jSONLexerBase.f8507ch = jSONLexerBase.charAt(i22);
        } else {
            if (charAt5 != 26) {
                jSONLexerBase.matchStat = -1;
                return null;
            }
            jSONLexerBase.token = 20;
            jSONLexerBase.f8506bp = (i19 - 1) + jSONLexerBase.f8506bp;
            jSONLexerBase.f8507ch = JSONLexer.EOI;
        }
        jSONLexerBase.matchStat = 4;
        return bigDecimal;
    }

    public final double scanFieldDouble(char[] cArr) {
        int i2;
        char charAt;
        JSONLexerBase jSONLexerBase;
        int length;
        int i3;
        double parseDouble;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return ShadowDrawableWrapper.COS_45;
        }
        int length2 = cArr.length;
        int i4 = length2 + 1;
        char charAt2 = charAt(this.f8506bp + length2);
        boolean z = charAt2 == '\"';
        if (z) {
            charAt2 = charAt(this.f8506bp + i4);
            i4++;
        }
        boolean z2 = charAt2 == '-';
        if (z2) {
            charAt2 = charAt(this.f8506bp + i4);
            i4++;
        }
        char c2 = '0';
        if (charAt2 >= '0') {
            char c3 = '9';
            if (charAt2 <= '9') {
                long j2 = charAt2 - '0';
                while (true) {
                    i2 = i4 + 1;
                    charAt = charAt(this.f8506bp + i4);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    j2 = (j2 * 10) + (charAt - '0');
                    i4 = i2;
                    z2 = z2;
                }
                boolean z3 = z2;
                long j3 = 1;
                if (charAt == '.') {
                    int i5 = i2 + 1;
                    char charAt3 = charAt(this.f8506bp + i2);
                    if (charAt3 < '0' || charAt3 > '9') {
                        this.matchStat = -1;
                        return ShadowDrawableWrapper.COS_45;
                    }
                    j2 = (j2 * 10) + (charAt3 - '0');
                    long j4 = 10;
                    while (true) {
                        i2 = i5 + 1;
                        charAt = charAt(this.f8506bp + i5);
                        if (charAt < c2 || charAt > c3) {
                            break;
                        }
                        j2 = (j2 * 10) + (charAt - '0');
                        j4 *= 10;
                        i5 = i2;
                        c2 = '0';
                        c3 = '9';
                    }
                    j3 = j4;
                }
                boolean z4 = charAt == 'e' || charAt == 'E';
                if (z4) {
                    int i6 = i2 + 1;
                    charAt = charAt(this.f8506bp + i2);
                    if (charAt == '+' || charAt == '-') {
                        charAt = charAt(this.f8506bp + i6);
                        jSONLexerBase = this;
                        i2 = i6 + 1;
                    } else {
                        jSONLexerBase = this;
                        i2 = i6;
                    }
                    while (charAt >= '0' && charAt <= '9') {
                        charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i2);
                        i2++;
                    }
                } else {
                    jSONLexerBase = this;
                }
                if (!z) {
                    int i7 = jSONLexerBase.f8506bp;
                    length = cArr.length + i7;
                    i3 = ((i7 + i2) - length) - 1;
                } else {
                    if (charAt != '\"') {
                        jSONLexerBase.matchStat = -1;
                        return ShadowDrawableWrapper.COS_45;
                    }
                    int i8 = i2 + 1;
                    charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i2);
                    int i9 = jSONLexerBase.f8506bp;
                    length = cArr.length + i9 + 1;
                    i3 = ((i9 + i8) - length) - 2;
                    i2 = i8;
                }
                if (z4 || i3 >= 17) {
                    parseDouble = Double.parseDouble(jSONLexerBase.subString(length, i3));
                } else {
                    parseDouble = j2 / j3;
                    if (z3) {
                        parseDouble = -parseDouble;
                    }
                }
                if (charAt == ',') {
                    int i10 = jSONLexerBase.f8506bp + i2;
                    jSONLexerBase.f8506bp = i10;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i10);
                    jSONLexerBase.matchStat = 3;
                    jSONLexerBase.token = 16;
                    return parseDouble;
                }
                if (charAt != '}') {
                    jSONLexerBase.matchStat = -1;
                    return ShadowDrawableWrapper.COS_45;
                }
                int i11 = i2 + 1;
                char charAt4 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i2);
                if (charAt4 == ',') {
                    jSONLexerBase.token = 16;
                    int i12 = jSONLexerBase.f8506bp + i11;
                    jSONLexerBase.f8506bp = i12;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i12);
                } else if (charAt4 == ']') {
                    jSONLexerBase.token = 15;
                    int i13 = jSONLexerBase.f8506bp + i11;
                    jSONLexerBase.f8506bp = i13;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i13);
                } else if (charAt4 == '}') {
                    jSONLexerBase.token = 13;
                    int i14 = jSONLexerBase.f8506bp + i11;
                    jSONLexerBase.f8506bp = i14;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i14);
                } else {
                    if (charAt4 != 26) {
                        jSONLexerBase.matchStat = -1;
                        return ShadowDrawableWrapper.COS_45;
                    }
                    jSONLexerBase.token = 20;
                    jSONLexerBase.f8506bp = (i11 - 1) + jSONLexerBase.f8506bp;
                    jSONLexerBase.f8507ch = JSONLexer.EOI;
                }
                jSONLexerBase.matchStat = 4;
                return parseDouble;
            }
        }
        if (charAt2 != 'n' || charAt(this.f8506bp + i4) != 'u' || C1499a.m605a(this.f8506bp, i4, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i4, 2, this) != 'l') {
            this.matchStat = -1;
            return ShadowDrawableWrapper.COS_45;
        }
        this.matchStat = 5;
        int i15 = i4 + 3;
        int i16 = i15 + 1;
        char charAt5 = charAt(this.f8506bp + i15);
        if (z && charAt5 == '\"') {
            charAt5 = charAt(this.f8506bp + i16);
            i16++;
        }
        while (charAt5 != ',') {
            if (charAt5 == '}') {
                int i17 = this.f8506bp + i16;
                this.f8506bp = i17;
                this.f8507ch = charAt(i17);
                this.matchStat = 5;
                this.token = 13;
                return ShadowDrawableWrapper.COS_45;
            }
            if (!isWhitespace(charAt5)) {
                this.matchStat = -1;
                return ShadowDrawableWrapper.COS_45;
            }
            charAt5 = charAt(this.f8506bp + i16);
            i16++;
        }
        int i18 = this.f8506bp + i16;
        this.f8506bp = i18;
        this.f8507ch = charAt(i18);
        this.matchStat = 5;
        this.token = 16;
        return ShadowDrawableWrapper.COS_45;
    }

    public final float scanFieldFloat(char[] cArr) {
        int i2;
        char charAt;
        boolean z;
        long j2;
        int i3;
        JSONLexerBase jSONLexerBase;
        int length;
        int i4;
        float parseFloat;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return 0.0f;
        }
        int length2 = cArr.length;
        int i5 = length2 + 1;
        char charAt2 = charAt(this.f8506bp + length2);
        boolean z2 = charAt2 == '\"';
        if (z2) {
            charAt2 = charAt(this.f8506bp + i5);
            i5++;
        }
        boolean z3 = charAt2 == '-';
        if (z3) {
            charAt2 = charAt(this.f8506bp + i5);
            i5++;
        }
        char c2 = '0';
        if (charAt2 >= '0') {
            char c3 = '9';
            if (charAt2 <= '9') {
                long j3 = charAt2 - '0';
                while (true) {
                    i2 = i5 + 1;
                    charAt = charAt(this.f8506bp + i5);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    j3 = (j3 * 10) + (charAt - '0');
                    i5 = i2;
                }
                if (charAt == '.') {
                    int i6 = i2 + 1;
                    char charAt3 = charAt(this.f8506bp + i2);
                    if (charAt3 >= '0' && charAt3 <= '9') {
                        z = z3;
                        j3 = (j3 * 10) + (charAt3 - '0');
                        j2 = 10;
                        while (true) {
                            i2 = i6 + 1;
                            charAt = charAt(this.f8506bp + i6);
                            if (charAt < c2 || charAt > c3) {
                                break;
                            }
                            j3 = (j3 * 10) + (charAt - '0');
                            j2 *= 10;
                            c3 = '9';
                            i6 = i2;
                            c2 = '0';
                        }
                    } else {
                        this.matchStat = -1;
                        return 0.0f;
                    }
                } else {
                    z = z3;
                    j2 = 1;
                }
                boolean z4 = charAt == 'e' || charAt == 'E';
                if (z4) {
                    int i7 = i2 + 1;
                    charAt = charAt(this.f8506bp + i2);
                    if (charAt == '+' || charAt == '-') {
                        i3 = i7 + 1;
                        charAt = charAt(this.f8506bp + i7);
                        jSONLexerBase = this;
                    } else {
                        jSONLexerBase = this;
                        i3 = i7;
                    }
                    while (charAt >= '0' && charAt <= '9') {
                        charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
                        i3++;
                    }
                } else {
                    i3 = i2;
                    jSONLexerBase = this;
                }
                if (!z2) {
                    int i8 = jSONLexerBase.f8506bp;
                    length = cArr.length + i8;
                    i4 = ((i8 + i3) - length) - 1;
                } else {
                    if (charAt != '\"') {
                        jSONLexerBase.matchStat = -1;
                        return 0.0f;
                    }
                    int i9 = i3 + 1;
                    charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
                    int i10 = jSONLexerBase.f8506bp;
                    length = cArr.length + i10 + 1;
                    i4 = ((i10 + i9) - length) - 2;
                    i3 = i9;
                }
                if (z4 || i4 >= 17) {
                    parseFloat = Float.parseFloat(jSONLexerBase.subString(length, i4));
                } else {
                    parseFloat = (float) (j3 / j2);
                    if (z) {
                        parseFloat = -parseFloat;
                    }
                }
                if (charAt == ',') {
                    int i11 = jSONLexerBase.f8506bp + i3;
                    jSONLexerBase.f8506bp = i11;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i11);
                    jSONLexerBase.matchStat = 3;
                    jSONLexerBase.token = 16;
                    return parseFloat;
                }
                if (charAt != '}') {
                    jSONLexerBase.matchStat = -1;
                    return 0.0f;
                }
                int i12 = i3 + 1;
                char charAt4 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
                if (charAt4 == ',') {
                    jSONLexerBase.token = 16;
                    int i13 = jSONLexerBase.f8506bp + i12;
                    jSONLexerBase.f8506bp = i13;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i13);
                } else if (charAt4 == ']') {
                    jSONLexerBase.token = 15;
                    int i14 = jSONLexerBase.f8506bp + i12;
                    jSONLexerBase.f8506bp = i14;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i14);
                } else if (charAt4 == '}') {
                    jSONLexerBase.token = 13;
                    int i15 = jSONLexerBase.f8506bp + i12;
                    jSONLexerBase.f8506bp = i15;
                    jSONLexerBase.f8507ch = jSONLexerBase.charAt(i15);
                } else {
                    if (charAt4 != 26) {
                        jSONLexerBase.matchStat = -1;
                        return 0.0f;
                    }
                    jSONLexerBase.f8506bp = (i12 - 1) + jSONLexerBase.f8506bp;
                    jSONLexerBase.token = 20;
                    jSONLexerBase.f8507ch = JSONLexer.EOI;
                }
                jSONLexerBase.matchStat = 4;
                return parseFloat;
            }
        }
        if (charAt2 != 'n' || charAt(this.f8506bp + i5) != 'u' || C1499a.m605a(this.f8506bp, i5, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i5, 2, this) != 'l') {
            this.matchStat = -1;
            return 0.0f;
        }
        this.matchStat = 5;
        int i16 = i5 + 3;
        int i17 = i16 + 1;
        char charAt5 = charAt(this.f8506bp + i16);
        if (z2 && charAt5 == '\"') {
            charAt5 = charAt(this.f8506bp + i17);
            i17++;
        }
        while (charAt5 != ',') {
            if (charAt5 == '}') {
                int i18 = this.f8506bp + i17;
                this.f8506bp = i18;
                this.f8507ch = charAt(i18);
                this.matchStat = 5;
                this.token = 13;
                return 0.0f;
            }
            if (!isWhitespace(charAt5)) {
                this.matchStat = -1;
                return 0.0f;
            }
            charAt5 = charAt(this.f8506bp + i17);
            i17++;
        }
        int i19 = this.f8506bp + i17;
        this.f8506bp = i19;
        this.f8507ch = charAt(i19);
        this.matchStat = 5;
        this.token = 16;
        return 0.0f;
    }

    /* JADX WARN: Code restructure failed: missing block: B:108:0x00a5, code lost:
    
        r20.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x00a7, code lost:
    
        return r3;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final float[] scanFieldFloatArray(char[] r21) {
        /*
            Method dump skipped, instructions count: 453
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.scanFieldFloatArray(char[]):float[]");
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x01c2, code lost:
    
        if (r7 == r6.length) goto L102;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x01c4, code lost:
    
        r3 = new float[r7][];
        java.lang.System.arraycopy(r6, 0, r3, 0, r7);
        r6 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x01cd, code lost:
    
        if (r1 != ',') goto L106;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x01cf, code lost:
    
        r21.f8506bp = (r2 - 1) + r21.f8506bp;
        next();
        r21.matchStat = 3;
        r21.token = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x01df, code lost:
    
        return r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x01e4, code lost:
    
        if (r1 != '}') goto L123;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x01e6, code lost:
    
        r5 = r2 + 1;
        r1 = charAt(r21.f8506bp + r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x01f1, code lost:
    
        if (r1 != ',') goto L111;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x01f3, code lost:
    
        r21.token = 16;
        r21.f8506bp = (r5 - 1) + r21.f8506bp;
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0231, code lost:
    
        r21.matchStat = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x0234, code lost:
    
        return r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x0201, code lost:
    
        if (r1 != ']') goto L114;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x0203, code lost:
    
        r21.token = 15;
        r21.f8506bp = (r5 - 1) + r21.f8506bp;
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0211, code lost:
    
        if (r1 != '}') goto L116;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0213, code lost:
    
        r21.token = 13;
        r21.f8506bp = (r5 - 1) + r21.f8506bp;
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x0223, code lost:
    
        if (r1 != 26) goto L121;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0225, code lost:
    
        r21.f8506bp = (r5 - 1) + r21.f8506bp;
        r21.token = 20;
        r21.f8507ch = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x0235, code lost:
    
        r21.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x0238, code lost:
    
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x0239, code lost:
    
        r21.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:125:0x023c, code lost:
    
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x016f, code lost:
    
        r12 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x00b5, code lost:
    
        r21.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x00b7, code lost:
    
        return r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x015a, code lost:
    
        r4 = r17 + 1;
        r3 = charAt(r21.f8506bp + r17);
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x0165, code lost:
    
        if (r1 == r2.length) goto L83;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x0167, code lost:
    
        r5 = new float[r1];
        r12 = 0;
        java.lang.System.arraycopy(r2, 0, r5, 0, r1);
        r2 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0171, code lost:
    
        if (r7 < r6.length) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0173, code lost:
    
        r5 = new float[(r6.length * 3) / 2][];
        java.lang.System.arraycopy(r2, r12, r5, r12, r1);
        r6 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x017e, code lost:
    
        r1 = r7 + 1;
        r6[r7] = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x0184, code lost:
    
        if (r3 != ',') goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x0186, code lost:
    
        r3 = r4 + 1;
        r2 = charAt(r21.f8506bp + r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0192, code lost:
    
        if (r3 != ']') goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x01a1, code lost:
    
        r2 = r3;
        r3 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x0194, code lost:
    
        r7 = r1;
        r1 = charAt(r21.f8506bp + r4);
        r2 = r4 + 1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final float[][] scanFieldFloatArray2(char[] r22) {
        /*
            Method dump skipped, instructions count: 573
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.scanFieldFloatArray2(char[]):float[][]");
    }

    public int scanFieldInt(char[] cArr) {
        int i2;
        char charAt;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return 0;
        }
        int length = cArr.length;
        int i3 = length + 1;
        char charAt2 = charAt(this.f8506bp + length);
        boolean z = charAt2 == '-';
        if (z) {
            charAt2 = charAt(this.f8506bp + i3);
            i3++;
        }
        if (charAt2 < '0' || charAt2 > '9') {
            this.matchStat = -1;
            return 0;
        }
        int i4 = charAt2 - '0';
        while (true) {
            i2 = i3 + 1;
            charAt = charAt(this.f8506bp + i3);
            if (charAt < '0' || charAt > '9') {
                break;
            }
            i4 = (i4 * 10) + (charAt - '0');
            i3 = i2;
        }
        if (charAt == '.') {
            this.matchStat = -1;
            return 0;
        }
        if ((i4 < 0 || i2 > cArr.length + 14) && !(i4 == Integer.MIN_VALUE && i2 == 17 && z)) {
            this.matchStat = -1;
            return 0;
        }
        if (charAt == ',') {
            int i5 = this.f8506bp + i2;
            this.f8506bp = i5;
            this.f8507ch = charAt(i5);
            this.matchStat = 3;
            this.token = 16;
            return z ? -i4 : i4;
        }
        if (charAt != '}') {
            this.matchStat = -1;
            return 0;
        }
        int i6 = i2 + 1;
        char charAt3 = charAt(this.f8506bp + i2);
        if (charAt3 == ',') {
            this.token = 16;
            int i7 = this.f8506bp + i6;
            this.f8506bp = i7;
            this.f8507ch = charAt(i7);
        } else if (charAt3 == ']') {
            this.token = 15;
            int i8 = this.f8506bp + i6;
            this.f8506bp = i8;
            this.f8507ch = charAt(i8);
        } else if (charAt3 == '}') {
            this.token = 13;
            int i9 = this.f8506bp + i6;
            this.f8506bp = i9;
            this.f8507ch = charAt(i9);
        } else {
            if (charAt3 != 26) {
                this.matchStat = -1;
                return 0;
            }
            this.token = 20;
            this.f8506bp = (i6 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return z ? -i4 : i4;
    }

    public final int[] scanFieldIntArray(char[] cArr) {
        boolean z;
        int i2;
        char charAt;
        int i3;
        int i4;
        char charAt2;
        this.matchStat = 0;
        int[] iArr = null;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return null;
        }
        int length = cArr.length;
        int i5 = length + 1;
        if (charAt(this.f8506bp + length) != '[') {
            this.matchStat = -2;
            return null;
        }
        int i6 = i5 + 1;
        char charAt3 = charAt(this.f8506bp + i5);
        int[] iArr2 = new int[16];
        if (charAt3 != ']') {
            int i7 = 0;
            while (true) {
                if (charAt3 == '-') {
                    charAt3 = charAt(this.f8506bp + i6);
                    i6++;
                    z = true;
                } else {
                    z = false;
                }
                if (charAt3 < '0' || charAt3 > '9') {
                    break;
                }
                int i8 = charAt3 - '0';
                while (true) {
                    i2 = i6 + 1;
                    charAt = charAt(this.f8506bp + i6);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    i8 = (i8 * 10) + (charAt - '0');
                    i6 = i2;
                }
                if (i7 >= iArr2.length) {
                    int[] iArr3 = new int[(iArr2.length * 3) / 2];
                    System.arraycopy(iArr2, 0, iArr3, 0, i7);
                    iArr2 = iArr3;
                }
                i3 = i7 + 1;
                if (z) {
                    i8 = -i8;
                }
                iArr2[i7] = i8;
                if (charAt == ',') {
                    char charAt4 = charAt(this.f8506bp + i2);
                    i2++;
                    charAt = charAt4;
                } else if (charAt == ']') {
                    i4 = i2 + 1;
                    charAt2 = charAt(this.f8506bp + i2);
                    break;
                }
                i7 = i3;
                iArr = null;
                charAt3 = charAt;
                i6 = i2;
            }
            int[] iArr4 = iArr;
            this.matchStat = -1;
            return iArr4;
        }
        i4 = i6 + 1;
        charAt2 = charAt(this.f8506bp + i6);
        i3 = 0;
        if (i3 != iArr2.length) {
            int[] iArr5 = new int[i3];
            System.arraycopy(iArr2, 0, iArr5, 0, i3);
            iArr2 = iArr5;
        }
        if (charAt2 == ',') {
            this.f8506bp = (i4 - 1) + this.f8506bp;
            next();
            this.matchStat = 3;
            this.token = 16;
            return iArr2;
        }
        if (charAt2 != '}') {
            this.matchStat = -1;
            return null;
        }
        int i9 = i4 + 1;
        char charAt5 = charAt(this.f8506bp + i4);
        if (charAt5 == ',') {
            this.token = 16;
            this.f8506bp = (i9 - 1) + this.f8506bp;
            next();
        } else if (charAt5 == ']') {
            this.token = 15;
            this.f8506bp = (i9 - 1) + this.f8506bp;
            next();
        } else if (charAt5 == '}') {
            this.token = 13;
            this.f8506bp = (i9 - 1) + this.f8506bp;
            next();
        } else {
            if (charAt5 != 26) {
                this.matchStat = -1;
                return null;
            }
            this.f8506bp = (i9 - 1) + this.f8506bp;
            this.token = 20;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return iArr2;
    }

    public long scanFieldLong(char[] cArr) {
        boolean z;
        int i2;
        char charAt;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return 0L;
        }
        int length = cArr.length;
        int i3 = length + 1;
        char charAt2 = charAt(this.f8506bp + length);
        if (charAt2 == '-') {
            charAt2 = charAt(this.f8506bp + i3);
            i3++;
            z = true;
        } else {
            z = false;
        }
        if (charAt2 < '0' || charAt2 > '9') {
            this.matchStat = -1;
            return 0L;
        }
        long j2 = charAt2 - '0';
        while (true) {
            i2 = i3 + 1;
            charAt = charAt(this.f8506bp + i3);
            if (charAt < '0' || charAt > '9') {
                break;
            }
            j2 = (j2 * 10) + (charAt - '0');
            i3 = i2;
        }
        if (charAt == '.') {
            this.matchStat = -1;
            return 0L;
        }
        if (!(i2 - cArr.length < 21 && (j2 >= 0 || (j2 == Long.MIN_VALUE && z)))) {
            this.matchStat = -1;
            return 0L;
        }
        if (charAt == ',') {
            int i4 = this.f8506bp + i2;
            this.f8506bp = i4;
            this.f8507ch = charAt(i4);
            this.matchStat = 3;
            this.token = 16;
            return z ? -j2 : j2;
        }
        if (charAt != '}') {
            this.matchStat = -1;
            return 0L;
        }
        int i5 = i2 + 1;
        char charAt3 = charAt(this.f8506bp + i2);
        if (charAt3 == ',') {
            this.token = 16;
            int i6 = this.f8506bp + i5;
            this.f8506bp = i6;
            this.f8507ch = charAt(i6);
        } else if (charAt3 == ']') {
            this.token = 15;
            int i7 = this.f8506bp + i5;
            this.f8506bp = i7;
            this.f8507ch = charAt(i7);
        } else if (charAt3 == '}') {
            this.token = 13;
            int i8 = this.f8506bp + i5;
            this.f8506bp = i8;
            this.f8507ch = charAt(i8);
        } else {
            if (charAt3 != 26) {
                this.matchStat = -1;
                return 0L;
            }
            this.token = 20;
            this.f8506bp = (i5 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return z ? -j2 : j2;
    }

    public String scanFieldString(char[] cArr) {
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return stringDefaultValue();
        }
        int length = cArr.length;
        int i2 = length + 1;
        if (charAt(this.f8506bp + length) != '\"') {
            this.matchStat = -1;
            return stringDefaultValue();
        }
        int indexOf = indexOf(Typography.quote, this.f8506bp + cArr.length + 1);
        if (indexOf == -1) {
            throw new JSONException("unclosed str");
        }
        int length2 = this.f8506bp + cArr.length + 1;
        String subString = subString(length2, indexOf - length2);
        if (subString.indexOf(92) != -1) {
            while (true) {
                int i3 = 0;
                for (int i4 = indexOf - 1; i4 >= 0 && charAt(i4) == '\\'; i4--) {
                    i3++;
                }
                if (i3 % 2 == 0) {
                    break;
                }
                indexOf = indexOf(Typography.quote, indexOf + 1);
            }
            int i5 = this.f8506bp;
            int length3 = indexOf - ((cArr.length + i5) + 1);
            subString = readString(sub_chars(i5 + cArr.length + 1, length3), length3);
        }
        int i6 = this.f8506bp;
        int length4 = (indexOf - ((cArr.length + i6) + 1)) + 1 + i2;
        int i7 = length4 + 1;
        char charAt = charAt(i6 + length4);
        if (charAt == ',') {
            int i8 = this.f8506bp + i7;
            this.f8506bp = i8;
            this.f8507ch = charAt(i8);
            this.matchStat = 3;
            return subString;
        }
        if (charAt != '}') {
            this.matchStat = -1;
            return stringDefaultValue();
        }
        int i9 = i7 + 1;
        char charAt2 = charAt(this.f8506bp + i7);
        if (charAt2 == ',') {
            this.token = 16;
            int i10 = this.f8506bp + i9;
            this.f8506bp = i10;
            this.f8507ch = charAt(i10);
        } else if (charAt2 == ']') {
            this.token = 15;
            int i11 = this.f8506bp + i9;
            this.f8506bp = i11;
            this.f8507ch = charAt(i11);
        } else if (charAt2 == '}') {
            this.token = 13;
            int i12 = this.f8506bp + i9;
            this.f8506bp = i12;
            this.f8507ch = charAt(i12);
        } else {
            if (charAt2 != 26) {
                this.matchStat = -1;
                return stringDefaultValue();
            }
            this.token = 20;
            this.f8506bp = (i9 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return subString;
    }

    /* JADX WARN: Code restructure failed: missing block: B:35:0x00f5, code lost:
    
        if (r11 != ',') goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00f7, code lost:
    
        r11 = r10.f8506bp + r5;
        r10.f8506bp = r11;
        r10.f8507ch = charAt(r11);
        r10.matchStat = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0105, code lost:
    
        return r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0108, code lost:
    
        if (r11 != '}') goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x010a, code lost:
    
        r6 = r5 + 1;
        r11 = charAt(r10.f8506bp + r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0113, code lost:
    
        if (r11 != ',') goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0115, code lost:
    
        r10.token = 16;
        r11 = r10.f8506bp + r6;
        r10.f8506bp = r11;
        r10.f8507ch = charAt(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x015a, code lost:
    
        r10.matchStat = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x015d, code lost:
    
        return r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0125, code lost:
    
        if (r11 != ']') goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0127, code lost:
    
        r10.token = 15;
        r11 = r10.f8506bp + r6;
        r10.f8506bp = r11;
        r10.f8507ch = charAt(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0137, code lost:
    
        if (r11 != '}') goto L60;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0139, code lost:
    
        r10.token = 13;
        r11 = r10.f8506bp + r6;
        r10.f8506bp = r11;
        r10.f8507ch = charAt(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x014b, code lost:
    
        if (r11 != 26) goto L65;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x014d, code lost:
    
        r10.f8506bp = (r6 - 1) + r10.f8506bp;
        r10.token = 20;
        r10.f8507ch = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x015e, code lost:
    
        r10.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0160, code lost:
    
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0161, code lost:
    
        r10.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0163, code lost:
    
        return null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x00ea, code lost:
    
        if (r12.size() != 0) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x00ec, code lost:
    
        r5 = r0 + 1;
        r11 = charAt(r10.f8506bp + r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x016b, code lost:
    
        throw new com.alibaba.fastjson.JSONException("illega str");
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.Collection<java.lang.String> scanFieldStringArray(char[] r11, java.lang.Class<?> r12) {
        /*
            Method dump skipped, instructions count: 364
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.scanFieldStringArray(char[], java.lang.Class):java.util.Collection");
    }

    public long scanFieldSymbol(char[] cArr) {
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return 0L;
        }
        int length = cArr.length;
        int i2 = length + 1;
        if (charAt(this.f8506bp + length) != '\"') {
            this.matchStat = -1;
            return 0L;
        }
        long j2 = -3750763034362895579L;
        while (true) {
            int i3 = i2 + 1;
            char charAt = charAt(this.f8506bp + i2);
            if (charAt == '\"') {
                int i4 = i3 + 1;
                char charAt2 = charAt(this.f8506bp + i3);
                if (charAt2 == ',') {
                    int i5 = this.f8506bp + i4;
                    this.f8506bp = i5;
                    this.f8507ch = charAt(i5);
                    this.matchStat = 3;
                    return j2;
                }
                if (charAt2 != '}') {
                    this.matchStat = -1;
                    return 0L;
                }
                int i6 = i4 + 1;
                char charAt3 = charAt(this.f8506bp + i4);
                if (charAt3 == ',') {
                    this.token = 16;
                    int i7 = this.f8506bp + i6;
                    this.f8506bp = i7;
                    this.f8507ch = charAt(i7);
                } else if (charAt3 == ']') {
                    this.token = 15;
                    int i8 = this.f8506bp + i6;
                    this.f8506bp = i8;
                    this.f8507ch = charAt(i8);
                } else if (charAt3 == '}') {
                    this.token = 13;
                    int i9 = this.f8506bp + i6;
                    this.f8506bp = i9;
                    this.f8507ch = charAt(i9);
                } else {
                    if (charAt3 != 26) {
                        this.matchStat = -1;
                        return 0L;
                    }
                    this.token = 20;
                    this.f8506bp = (i6 - 1) + this.f8506bp;
                    this.f8507ch = JSONLexer.EOI;
                }
                this.matchStat = 4;
                return j2;
            }
            j2 = (j2 ^ charAt) * 1099511628211L;
            if (charAt == '\\') {
                this.matchStat = -1;
                return 0L;
            }
            i2 = i3;
        }
    }

    public UUID scanFieldUUID(char[] cArr) {
        char charAt;
        int i2;
        UUID uuid;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        this.matchStat = 0;
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return null;
        }
        int length = cArr.length;
        int i16 = length + 1;
        char charAt2 = charAt(this.f8506bp + length);
        char c2 = 4;
        if (charAt2 != '\"') {
            if (charAt2 == 'n') {
                int i17 = i16 + 1;
                if (charAt(this.f8506bp + i16) == 'u') {
                    int i18 = i17 + 1;
                    if (charAt(this.f8506bp + i17) == 'l') {
                        int i19 = i18 + 1;
                        if (charAt(this.f8506bp + i18) == 'l') {
                            charAt = charAt(this.f8506bp + i19);
                            i2 = i19 + 1;
                            uuid = null;
                        }
                    }
                }
            }
            this.matchStat = -1;
            return null;
        }
        int indexOf = indexOf(Typography.quote, this.f8506bp + cArr.length + 1);
        if (indexOf == -1) {
            throw new JSONException("unclosed str");
        }
        int length2 = this.f8506bp + cArr.length + 1;
        int i20 = indexOf - length2;
        char c3 = 'F';
        char c4 = 'f';
        char c5 = 'A';
        char c6 = '0';
        if (i20 == 36) {
            int i21 = 0;
            long j2 = 0;
            while (i21 < 8) {
                char charAt3 = charAt(length2 + i21);
                if (charAt3 < '0' || charAt3 > '9') {
                    if (charAt3 >= 'a' && charAt3 <= 'f') {
                        i14 = charAt3 - 'a';
                    } else {
                        if (charAt3 < 'A' || charAt3 > c3) {
                            this.matchStat = -2;
                            return null;
                        }
                        i14 = charAt3 - 'A';
                    }
                    i15 = i14 + 10;
                } else {
                    i15 = charAt3 - '0';
                }
                j2 = (j2 << 4) | i15;
                i21++;
                indexOf = indexOf;
                c3 = 'F';
            }
            int i22 = indexOf;
            int i23 = 9;
            int i24 = 13;
            while (i23 < i24) {
                char charAt4 = charAt(length2 + i23);
                if (charAt4 < '0' || charAt4 > '9') {
                    if (charAt4 >= 'a' && charAt4 <= 'f') {
                        i12 = charAt4 - 'a';
                    } else {
                        if (charAt4 < c5 || charAt4 > 'F') {
                            this.matchStat = -2;
                            return null;
                        }
                        i12 = charAt4 - 'A';
                    }
                    i13 = i12 + 10;
                } else {
                    i13 = charAt4 - '0';
                }
                j2 = (j2 << c2) | i13;
                i23++;
                i24 = 13;
                c5 = 'A';
                c2 = 4;
            }
            long j3 = j2;
            for (int i25 = 14; i25 < 18; i25++) {
                char charAt5 = charAt(length2 + i25);
                if (charAt5 < '0' || charAt5 > '9') {
                    if (charAt5 >= 'a' && charAt5 <= 'f') {
                        i10 = charAt5 - 'a';
                    } else {
                        if (charAt5 < 'A' || charAt5 > 'F') {
                            this.matchStat = -2;
                            return null;
                        }
                        i10 = charAt5 - 'A';
                    }
                    i11 = i10 + 10;
                } else {
                    i11 = charAt5 - '0';
                }
                j3 = (j3 << 4) | i11;
            }
            long j4 = 0;
            for (int i26 = 19; i26 < 23; i26++) {
                char charAt6 = charAt(length2 + i26);
                if (charAt6 < '0' || charAt6 > '9') {
                    if (charAt6 >= 'a' && charAt6 <= 'f') {
                        i8 = charAt6 - 'a';
                    } else {
                        if (charAt6 < 'A' || charAt6 > 'F') {
                            this.matchStat = -2;
                            return null;
                        }
                        i8 = charAt6 - 'A';
                    }
                    i9 = i8 + 10;
                } else {
                    i9 = charAt6 - '0';
                }
                j4 = (j4 << 4) | i9;
            }
            int i27 = 24;
            long j5 = j4;
            int i28 = 36;
            while (i27 < i28) {
                char charAt7 = charAt(length2 + i27);
                if (charAt7 < c6 || charAt7 > '9') {
                    if (charAt7 >= 'a' && charAt7 <= c4) {
                        i6 = charAt7 - 'a';
                    } else {
                        if (charAt7 < 'A' || charAt7 > 'F') {
                            this.matchStat = -2;
                            return null;
                        }
                        i6 = charAt7 - 'A';
                    }
                    i7 = i6 + 10;
                } else {
                    i7 = charAt7 - '0';
                }
                j5 = (j5 << 4) | i7;
                i27++;
                i16 = i16;
                i28 = 36;
                c6 = '0';
                c4 = 'f';
            }
            uuid = new UUID(j3, j5);
            int i29 = this.f8506bp;
            int length3 = (i22 - ((cArr.length + i29) + 1)) + 1 + i16;
            i2 = length3 + 1;
            charAt = charAt(i29 + length3);
        } else {
            if (i20 != 32) {
                this.matchStat = -1;
                return null;
            }
            long j6 = 0;
            for (int i30 = 0; i30 < 16; i30++) {
                char charAt8 = charAt(length2 + i30);
                if (charAt8 < '0' || charAt8 > '9') {
                    if (charAt8 >= 'a' && charAt8 <= 'f') {
                        i4 = charAt8 - 'a';
                    } else {
                        if (charAt8 < 'A' || charAt8 > 'F') {
                            this.matchStat = -2;
                            return null;
                        }
                        i4 = charAt8 - 'A';
                    }
                    i5 = i4 + 10;
                } else {
                    i5 = charAt8 - '0';
                }
                j6 = (j6 << 4) | i5;
            }
            int i31 = 16;
            long j7 = 0;
            for (int i32 = 32; i31 < i32; i32 = 32) {
                char charAt9 = charAt(length2 + i31);
                if (charAt9 >= '0' && charAt9 <= '9') {
                    i3 = charAt9 - '0';
                } else if (charAt9 >= 'a' && charAt9 <= 'f') {
                    i3 = (charAt9 - 'a') + 10;
                } else {
                    if (charAt9 < 'A' || charAt9 > 'F') {
                        this.matchStat = -2;
                        return null;
                    }
                    i3 = (charAt9 - 'A') + 10;
                    j7 = (j7 << 4) | i3;
                    i31++;
                }
                j7 = (j7 << 4) | i3;
                i31++;
            }
            uuid = new UUID(j6, j7);
            int i33 = this.f8506bp;
            int length4 = (indexOf - ((cArr.length + i33) + 1)) + 1 + i16;
            i2 = length4 + 1;
            charAt = charAt(i33 + length4);
        }
        if (charAt == ',') {
            int i34 = this.f8506bp + i2;
            this.f8506bp = i34;
            this.f8507ch = charAt(i34);
            this.matchStat = 3;
            return uuid;
        }
        if (charAt != '}') {
            this.matchStat = -1;
            return null;
        }
        int i35 = i2 + 1;
        char charAt10 = charAt(this.f8506bp + i2);
        if (charAt10 == ',') {
            this.token = 16;
            int i36 = this.f8506bp + i35;
            this.f8506bp = i36;
            this.f8507ch = charAt(i36);
        } else if (charAt10 == ']') {
            this.token = 15;
            int i37 = this.f8506bp + i35;
            this.f8506bp = i37;
            this.f8507ch = charAt(i37);
        } else if (charAt10 == '}') {
            this.token = 13;
            int i38 = this.f8506bp + i35;
            this.f8506bp = i38;
            this.f8507ch = charAt(i38);
        } else {
            if (charAt10 != 26) {
                this.matchStat = -1;
                return null;
            }
            this.token = 20;
            this.f8506bp = (i35 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return uuid;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final float scanFloat(char c2) {
        int i2;
        int i3;
        char charAt;
        boolean z;
        JSONLexerBase jSONLexerBase;
        boolean z2;
        long j2;
        char c3;
        char c4;
        int i4;
        int i5;
        int i6;
        float parseFloat;
        boolean z3;
        char c5;
        this.matchStat = 0;
        char charAt2 = charAt(this.f8506bp + 0);
        boolean z4 = charAt2 == '\"';
        if (z4) {
            charAt2 = charAt(this.f8506bp + 1);
            i2 = 2;
        } else {
            i2 = 1;
        }
        boolean z5 = charAt2 == '-';
        if (z5) {
            charAt2 = charAt(this.f8506bp + i2);
            i2++;
        }
        if (charAt2 < '0' || charAt2 > '9') {
            boolean z6 = z4;
            if (charAt2 != 'n' || charAt(this.f8506bp + i2) != 'u' || C1499a.m605a(this.f8506bp, i2, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i2, 2, this) != 'l') {
                this.matchStat = -1;
                return 0.0f;
            }
            this.matchStat = 5;
            int i7 = i2 + 3;
            int i8 = i7 + 1;
            char charAt3 = charAt(this.f8506bp + i7);
            if (z6 && charAt3 == '\"') {
                int i9 = i8 + 1;
                charAt3 = charAt(this.f8506bp + i8);
                i8 = i9;
            }
            while (charAt3 != ',') {
                if (charAt3 == ']') {
                    int i10 = this.f8506bp + i8;
                    this.f8506bp = i10;
                    this.f8507ch = charAt(i10);
                    this.matchStat = 5;
                    this.token = 15;
                    return 0.0f;
                }
                if (!isWhitespace(charAt3)) {
                    this.matchStat = -1;
                    return 0.0f;
                }
                int i11 = i8 + 1;
                charAt3 = charAt(this.f8506bp + i8);
                i8 = i11;
            }
            int i12 = this.f8506bp + i8;
            this.f8506bp = i12;
            this.f8507ch = charAt(i12);
            this.matchStat = 5;
            this.token = 16;
            return 0.0f;
        }
        long j3 = charAt2 - '0';
        while (true) {
            i3 = i2 + 1;
            charAt = charAt(this.f8506bp + i2);
            if (charAt < '0' || charAt > '9') {
                break;
            }
            j3 = (j3 * 10) + (charAt - '0');
            i2 = i3;
        }
        long j4 = 1;
        if (charAt == '.') {
            int i13 = i3 + 1;
            char charAt4 = charAt(this.f8506bp + i3);
            if (charAt4 >= '0' && charAt4 <= '9') {
                z = z4;
                j3 = (j3 * 10) + (charAt4 - '0');
                j4 = 10;
                while (true) {
                    i3 = i13 + 1;
                    charAt = charAt(this.f8506bp + i13);
                    if (charAt < '0' || charAt > '9') {
                        break;
                    }
                    j3 = (j3 * 10) + (charAt - '0');
                    j4 *= 10;
                    i13 = i3;
                }
            } else {
                this.matchStat = -1;
                return 0.0f;
            }
        } else {
            z = z4;
        }
        boolean z7 = charAt == 'e' || charAt == 'E';
        if (z7) {
            int i14 = i3 + 1;
            charAt = charAt(this.f8506bp + i3);
            if (charAt == '+' || charAt == '-') {
                int i15 = i14 + 1;
                char charAt5 = charAt(this.f8506bp + i14);
                jSONLexerBase = this;
                z3 = z7;
                c5 = Typography.quote;
                i3 = i15;
                c4 = c2;
                charAt = charAt5;
            } else {
                jSONLexerBase = this;
                i3 = i14;
                c5 = Typography.quote;
                z3 = z7;
                c4 = c2;
            }
            while (charAt >= '0' && charAt <= '9') {
                int i16 = i3 + 1;
                char charAt6 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
                i3 = i16;
                c4 = c4;
                charAt = charAt6;
            }
            z2 = z3;
            j2 = j4;
            c3 = c5;
        } else {
            jSONLexerBase = this;
            z2 = z7;
            j2 = j4;
            c3 = Typography.quote;
            c4 = c2;
        }
        if (!z) {
            int i17 = jSONLexerBase.f8506bp;
            i4 = ((i17 + i3) - i17) - 1;
            int i18 = i3;
            i5 = i17;
            i6 = i18;
        } else {
            if (charAt != c3) {
                jSONLexerBase.matchStat = -1;
                return 0.0f;
            }
            i6 = i3 + 1;
            charAt = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i3);
            int i19 = jSONLexerBase.f8506bp;
            i5 = i19 + 1;
            i4 = ((i19 + i6) - i5) - 2;
        }
        if (z2 || i4 >= 17) {
            parseFloat = Float.parseFloat(jSONLexerBase.subString(i5, i4));
        } else {
            parseFloat = (float) (j3 / j2);
            if (z5) {
                parseFloat = -parseFloat;
            }
        }
        if (charAt != c4) {
            jSONLexerBase.matchStat = -1;
            return parseFloat;
        }
        int i20 = jSONLexerBase.f8506bp + i6;
        jSONLexerBase.f8506bp = i20;
        jSONLexerBase.f8507ch = jSONLexerBase.charAt(i20);
        jSONLexerBase.matchStat = 3;
        jSONLexerBase.token = 16;
        return parseFloat;
    }

    public final void scanHex() {
        char next;
        if (this.f8507ch != 'x') {
            StringBuilder m586H = C1499a.m586H("illegal state. ");
            m586H.append(this.f8507ch);
            throw new JSONException(m586H.toString());
        }
        next();
        if (this.f8507ch != '\'') {
            StringBuilder m586H2 = C1499a.m586H("illegal state. ");
            m586H2.append(this.f8507ch);
            throw new JSONException(m586H2.toString());
        }
        this.f8508np = this.f8506bp;
        next();
        if (this.f8507ch == '\'') {
            next();
            this.token = 26;
            return;
        }
        while (true) {
            next = next();
            if ((next < '0' || next > '9') && (next < 'A' || next > 'F')) {
                break;
            } else {
                this.f8509sp++;
            }
        }
        if (next == '\'') {
            this.f8509sp++;
            next();
            this.token = 26;
        } else {
            throw new JSONException("illegal state. " + next);
        }
    }

    public final void scanIdent() {
        this.f8508np = this.f8506bp - 1;
        this.hasSpecial = false;
        do {
            this.f8509sp++;
            next();
        } while (Character.isLetterOrDigit(this.f8507ch));
        String stringVal = stringVal();
        if ("null".equalsIgnoreCase(stringVal)) {
            this.token = 8;
            return;
        }
        if (BloggerOrderBean.order_new.equals(stringVal)) {
            this.token = 9;
            return;
        }
        if ("true".equals(stringVal)) {
            this.token = 6;
            return;
        }
        if ("false".equals(stringVal)) {
            this.token = 7;
            return;
        }
        if ("undefined".equals(stringVal)) {
            this.token = 23;
            return;
        }
        if ("Set".equals(stringVal)) {
            this.token = 21;
        } else if ("TreeSet".equals(stringVal)) {
            this.token = 22;
        } else {
            this.token = 18;
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public int scanInt(char c2) {
        int i2;
        int i3;
        char charAt;
        this.matchStat = 0;
        char charAt2 = charAt(this.f8506bp + 0);
        boolean z = charAt2 == '\"';
        if (z) {
            charAt2 = charAt(this.f8506bp + 1);
            i2 = 2;
        } else {
            i2 = 1;
        }
        boolean z2 = charAt2 == '-';
        if (z2) {
            charAt2 = charAt(this.f8506bp + i2);
            i2++;
        }
        if (charAt2 >= '0' && charAt2 <= '9') {
            int i4 = charAt2 - '0';
            while (true) {
                i3 = i2 + 1;
                charAt = charAt(this.f8506bp + i2);
                if (charAt < '0' || charAt > '9') {
                    break;
                }
                i4 = (i4 * 10) + (charAt - '0');
                i2 = i3;
            }
            if (charAt == '.') {
                this.matchStat = -1;
                return 0;
            }
            if (i4 < 0) {
                this.matchStat = -1;
                return 0;
            }
            while (charAt != c2) {
                if (!isWhitespace(charAt)) {
                    this.matchStat = -1;
                    return z2 ? -i4 : i4;
                }
                char charAt3 = charAt(this.f8506bp + i3);
                i3++;
                charAt = charAt3;
            }
            int i5 = this.f8506bp + i3;
            this.f8506bp = i5;
            this.f8507ch = charAt(i5);
            this.matchStat = 3;
            this.token = 16;
            return z2 ? -i4 : i4;
        }
        if (charAt2 != 'n' || charAt(this.f8506bp + i2) != 'u' || C1499a.m605a(this.f8506bp, i2, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i2, 2, this) != 'l') {
            this.matchStat = -1;
            return 0;
        }
        this.matchStat = 5;
        int i6 = i2 + 3;
        int i7 = i6 + 1;
        char charAt4 = charAt(this.f8506bp + i6);
        if (z && charAt4 == '\"') {
            charAt4 = charAt(this.f8506bp + i7);
            i7++;
        }
        while (charAt4 != ',') {
            if (charAt4 == ']') {
                int i8 = this.f8506bp + i7;
                this.f8506bp = i8;
                this.f8507ch = charAt(i8);
                this.matchStat = 5;
                this.token = 15;
                return 0;
            }
            if (!isWhitespace(charAt4)) {
                this.matchStat = -1;
                return 0;
            }
            charAt4 = charAt(this.f8506bp + i7);
            i7++;
        }
        int i9 = this.f8506bp + i7;
        this.f8506bp = i9;
        this.f8507ch = charAt(i9);
        this.matchStat = 5;
        this.token = 16;
        return 0;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public long scanLong(char c2) {
        int i2;
        JSONLexerBase jSONLexerBase;
        int i3;
        int i4;
        char charAt;
        this.matchStat = 0;
        char charAt2 = charAt(this.f8506bp + 0);
        boolean z = charAt2 == '\"';
        if (z) {
            charAt2 = charAt(this.f8506bp + 1);
            i2 = 2;
        } else {
            i2 = 1;
        }
        boolean z2 = charAt2 == '-';
        if (z2) {
            charAt2 = charAt(this.f8506bp + i2);
            i2++;
        }
        if (charAt2 >= '0' && charAt2 <= '9') {
            long j2 = charAt2 - '0';
            while (true) {
                i4 = i2 + 1;
                charAt = charAt(this.f8506bp + i2);
                if (charAt < '0' || charAt > '9') {
                    break;
                }
                j2 = (j2 * 10) + (charAt - '0');
                i2 = i4;
            }
            if (charAt == '.') {
                this.matchStat = -1;
                return 0L;
            }
            if (!(j2 >= 0 || (j2 == Long.MIN_VALUE && z2))) {
                throw new NumberFormatException(subString(this.f8506bp, i4 - 1));
            }
            if (z) {
                if (charAt != '\"') {
                    this.matchStat = -1;
                    return 0L;
                }
                charAt = charAt(this.f8506bp + i4);
                i4++;
            }
            while (charAt != c2) {
                if (!isWhitespace(charAt)) {
                    this.matchStat = -1;
                    return j2;
                }
                charAt = charAt(this.f8506bp + i4);
                i4++;
            }
            int i5 = this.f8506bp + i4;
            this.f8506bp = i5;
            this.f8507ch = charAt(i5);
            this.matchStat = 3;
            this.token = 16;
            return z2 ? -j2 : j2;
        }
        if (charAt2 != 'n' || charAt(this.f8506bp + i2) != 'u' || C1499a.m605a(this.f8506bp, i2, 1, this) != 'l' || C1499a.m605a(this.f8506bp, i2, 2, this) != 'l') {
            this.matchStat = -1;
            return 0L;
        }
        this.matchStat = 5;
        int i6 = i2 + 3;
        int i7 = i6 + 1;
        char charAt3 = charAt(this.f8506bp + i6);
        if (z && charAt3 == '\"') {
            char charAt4 = charAt(this.f8506bp + i7);
            i7++;
            i3 = 16;
            charAt3 = charAt4;
            jSONLexerBase = this;
        } else {
            jSONLexerBase = this;
            i3 = 16;
        }
        while (charAt3 != ',') {
            if (charAt3 == ']') {
                int i8 = jSONLexerBase.f8506bp + i7;
                jSONLexerBase.f8506bp = i8;
                jSONLexerBase.f8507ch = jSONLexerBase.charAt(i8);
                jSONLexerBase.matchStat = 5;
                jSONLexerBase.token = 15;
                return 0L;
            }
            if (!isWhitespace(charAt3)) {
                jSONLexerBase.matchStat = -1;
                return 0L;
            }
            charAt3 = jSONLexerBase.charAt(jSONLexerBase.f8506bp + i7);
            i7++;
        }
        int i9 = jSONLexerBase.f8506bp + i7;
        jSONLexerBase.f8506bp = i9;
        jSONLexerBase.f8507ch = jSONLexerBase.charAt(i9);
        jSONLexerBase.matchStat = 5;
        jSONLexerBase.token = i3;
        return 0L;
    }

    public final void scanNullOrNew() {
        scanNullOrNew(true);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00ca  */
    @Override // com.alibaba.fastjson.parser.JSONLexer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void scanNumber() {
        /*
            Method dump skipped, instructions count: 206
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.scanNumber():void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:93:0x0170, code lost:
    
        throw new com.alibaba.fastjson.JSONException("invalid escape character \\x" + r1 + r2);
     */
    @Override // com.alibaba.fastjson.parser.JSONLexer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void scanString() {
        /*
            Method dump skipped, instructions count: 476
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.scanString():void");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public void scanStringArray(Collection<String> collection, char c2) {
        int i2;
        char charAt;
        int i3;
        char charAt2;
        this.matchStat = 0;
        char charAt3 = charAt(this.f8506bp + 0);
        char c3 = 'u';
        char c4 = 'n';
        if (charAt3 == 'n' && charAt(this.f8506bp + 1) == 'u' && C1499a.m605a(this.f8506bp, 1, 1, this) == 'l' && C1499a.m605a(this.f8506bp, 1, 2, this) == 'l' && C1499a.m605a(this.f8506bp, 1, 3, this) == c2) {
            int i4 = this.f8506bp + 5;
            this.f8506bp = i4;
            this.f8507ch = charAt(i4);
            this.matchStat = 5;
            return;
        }
        if (charAt3 != '[') {
            this.matchStat = -1;
            return;
        }
        char charAt4 = charAt(this.f8506bp + 1);
        int i5 = 2;
        while (true) {
            if (charAt4 == c4 && charAt(this.f8506bp + i5) == c3 && C1499a.m605a(this.f8506bp, i5, 1, this) == 'l' && C1499a.m605a(this.f8506bp, i5, 2, this) == 'l') {
                int i6 = i5 + 3;
                i2 = i6 + 1;
                charAt = charAt(this.f8506bp + i6);
                collection.add(null);
            } else {
                if (charAt4 == ']' && collection.size() == 0) {
                    i3 = i5 + 1;
                    charAt2 = charAt(this.f8506bp + i5);
                    break;
                }
                if (charAt4 != '\"') {
                    this.matchStat = -1;
                    return;
                }
                int i7 = this.f8506bp + i5;
                int indexOf = indexOf(Typography.quote, i7);
                if (indexOf == -1) {
                    throw new JSONException("unclosed str");
                }
                String subString = subString(this.f8506bp + i5, indexOf - i7);
                if (subString.indexOf(92) != -1) {
                    while (true) {
                        int i8 = 0;
                        for (int i9 = indexOf - 1; i9 >= 0 && charAt(i9) == '\\'; i9--) {
                            i8++;
                        }
                        if (i8 % 2 == 0) {
                            break;
                        } else {
                            indexOf = indexOf(Typography.quote, indexOf + 1);
                        }
                    }
                    int i10 = indexOf - i7;
                    subString = readString(sub_chars(this.f8506bp + i5, i10), i10);
                }
                int i11 = this.f8506bp;
                int i12 = (indexOf - (i11 + i5)) + 1 + i5;
                i2 = i12 + 1;
                charAt = charAt(i11 + i12);
                collection.add(subString);
            }
            if (charAt == ',') {
                i5 = i2 + 1;
                charAt4 = charAt(this.f8506bp + i2);
                c3 = 'u';
                c4 = 'n';
            } else if (charAt != ']') {
                this.matchStat = -1;
                return;
            } else {
                i3 = i2 + 1;
                charAt2 = charAt(this.f8506bp + i2);
            }
        }
        if (charAt2 != c2) {
            this.matchStat = -1;
            return;
        }
        int i13 = this.f8506bp + i3;
        this.f8506bp = i13;
        this.f8507ch = charAt(i13);
        this.matchStat = 3;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String scanSymbol(SymbolTable symbolTable) {
        skipWhitespace();
        char c2 = this.f8507ch;
        if (c2 == '\"') {
            return scanSymbol(symbolTable, Typography.quote);
        }
        if (c2 == '\'') {
            if (isEnabled(Feature.AllowSingleQuotes)) {
                return scanSymbol(symbolTable, '\'');
            }
            throw new JSONException("syntax error");
        }
        if (c2 == '}') {
            next();
            this.token = 13;
            return null;
        }
        if (c2 == ',') {
            next();
            this.token = 16;
            return null;
        }
        if (c2 == 26) {
            this.token = 20;
            return null;
        }
        if (isEnabled(Feature.AllowUnQuotedFieldNames)) {
            return scanSymbolUnQuoted(symbolTable);
        }
        throw new JSONException("syntax error");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String scanSymbolUnQuoted(SymbolTable symbolTable) {
        if (this.token == 1 && this.pos == 0 && this.f8506bp == 1) {
            this.f8506bp = 0;
        }
        boolean[] zArr = IOUtils.firstIdentifierFlags;
        int i2 = this.f8507ch;
        if (!(i2 >= zArr.length || zArr[i2])) {
            StringBuilder m586H = C1499a.m586H("illegal identifier : ");
            m586H.append(this.f8507ch);
            m586H.append(info());
            throw new JSONException(m586H.toString());
        }
        boolean[] zArr2 = IOUtils.identifierFlags;
        this.f8508np = this.f8506bp;
        this.f8509sp = 1;
        while (true) {
            char next = next();
            if (next < zArr2.length && !zArr2[next]) {
                break;
            }
            i2 = (i2 * 31) + next;
            this.f8509sp++;
        }
        this.f8507ch = charAt(this.f8506bp);
        this.token = 18;
        if (this.f8509sp == 4 && i2 == 3392903 && charAt(this.f8508np) == 'n' && charAt(this.f8508np + 1) == 'u' && charAt(this.f8508np + 2) == 'l' && charAt(this.f8508np + 3) == 'l') {
            return null;
        }
        return symbolTable == null ? subString(this.f8508np, this.f8509sp) : addSymbol(this.f8508np, this.f8509sp, i2, symbolTable);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public String scanSymbolWithSeperator(SymbolTable symbolTable, char c2) {
        int i2 = 0;
        this.matchStat = 0;
        char charAt = charAt(this.f8506bp + 0);
        if (charAt == 'n') {
            if (charAt(this.f8506bp + 1) != 'u' || C1499a.m605a(this.f8506bp, 1, 1, this) != 'l' || C1499a.m605a(this.f8506bp, 1, 2, this) != 'l') {
                this.matchStat = -1;
                return null;
            }
            if (charAt(this.f8506bp + 4) != c2) {
                this.matchStat = -1;
                return null;
            }
            int i3 = this.f8506bp + 5;
            this.f8506bp = i3;
            this.f8507ch = charAt(i3);
            this.matchStat = 3;
            return null;
        }
        if (charAt != '\"') {
            this.matchStat = -1;
            return null;
        }
        int i4 = 1;
        while (true) {
            int i5 = i4 + 1;
            char charAt2 = charAt(this.f8506bp + i4);
            if (charAt2 == '\"') {
                int i6 = this.f8506bp;
                int i7 = i6 + 0 + 1;
                String addSymbol = addSymbol(i7, ((i6 + i5) - i7) - 1, i2, symbolTable);
                int i8 = i5 + 1;
                char charAt3 = charAt(this.f8506bp + i5);
                while (charAt3 != c2) {
                    if (!isWhitespace(charAt3)) {
                        this.matchStat = -1;
                        return addSymbol;
                    }
                    charAt3 = charAt(this.f8506bp + i8);
                    i8++;
                }
                int i9 = this.f8506bp + i8;
                this.f8506bp = i9;
                this.f8507ch = charAt(i9);
                this.matchStat = 3;
                return addSymbol;
            }
            i2 = (i2 * 31) + charAt2;
            if (charAt2 == '\\') {
                this.matchStat = -1;
                return null;
            }
            i4 = i5;
        }
    }

    public final void scanTrue() {
        if (this.f8507ch != 't') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.f8507ch != 'r') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.f8507ch != 'u') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.f8507ch != 'e') {
            throw new JSONException("error parse true");
        }
        next();
        char c2 = this.f8507ch;
        if (c2 != ' ' && c2 != ',' && c2 != '}' && c2 != ']' && c2 != '\n' && c2 != '\r' && c2 != '\t' && c2 != 26 && c2 != '\f' && c2 != '\b' && c2 != ':' && c2 != '/') {
            throw new JSONException("scan true error");
        }
        this.token = 6;
    }

    public final int scanType(String str) {
        this.matchStat = 0;
        char[] cArr = typeFieldName;
        if (!charArrayCompare(cArr)) {
            return -2;
        }
        int length = this.f8506bp + cArr.length;
        int length2 = str.length();
        for (int i2 = 0; i2 < length2; i2++) {
            if (str.charAt(i2) != charAt(length + i2)) {
                return -1;
            }
        }
        int i3 = length + length2;
        if (charAt(i3) != '\"') {
            return -1;
        }
        int i4 = i3 + 1;
        char charAt = charAt(i4);
        this.f8507ch = charAt;
        if (charAt == ',') {
            int i5 = i4 + 1;
            this.f8507ch = charAt(i5);
            this.f8506bp = i5;
            this.token = 16;
            return 3;
        }
        if (charAt == '}') {
            i4++;
            char charAt2 = charAt(i4);
            this.f8507ch = charAt2;
            if (charAt2 == ',') {
                this.token = 16;
                i4++;
                this.f8507ch = charAt(i4);
            } else if (charAt2 == ']') {
                this.token = 15;
                i4++;
                this.f8507ch = charAt(i4);
            } else if (charAt2 == '}') {
                this.token = 13;
                i4++;
                this.f8507ch = charAt(i4);
            } else {
                if (charAt2 != 26) {
                    return -1;
                }
                this.token = 20;
            }
            this.matchStat = 4;
        }
        this.f8506bp = i4;
        return this.matchStat;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public String scanTypeName(SymbolTable symbolTable) {
        return null;
    }

    public UUID scanUUID(char c2) {
        int i2;
        char charAt;
        UUID uuid;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        this.matchStat = 0;
        char charAt2 = charAt(this.f8506bp + 0);
        if (charAt2 == '\"') {
            int indexOf = indexOf(Typography.quote, this.f8506bp + 1);
            if (indexOf == -1) {
                throw new JSONException("unclosed str");
            }
            int i16 = this.f8506bp + 1;
            int i17 = indexOf - i16;
            char c3 = 'F';
            char c4 = 'f';
            char c5 = '9';
            char c6 = 'A';
            char c7 = 'a';
            if (i17 == 36) {
                int i18 = 0;
                long j2 = 0;
                while (i18 < 8) {
                    char charAt3 = charAt(i16 + i18);
                    if (charAt3 < '0' || charAt3 > '9') {
                        if (charAt3 >= 'a' && charAt3 <= 'f') {
                            i14 = charAt3 - 'a';
                        } else {
                            if (charAt3 < c6 || charAt3 > c3) {
                                this.matchStat = -2;
                                return null;
                            }
                            i14 = charAt3 - 'A';
                        }
                        i15 = i14 + 10;
                    } else {
                        i15 = charAt3 - '0';
                    }
                    j2 = (j2 << 4) | i15;
                    i18++;
                    c6 = 'A';
                    c3 = 'F';
                }
                int i19 = 9;
                while (i19 < 13) {
                    char charAt4 = charAt(i16 + i19);
                    if (charAt4 < '0' || charAt4 > '9') {
                        if (charAt4 >= 'a' && charAt4 <= c4) {
                            i12 = charAt4 - 'a';
                        } else {
                            if (charAt4 < 'A' || charAt4 > 'F') {
                                this.matchStat = -2;
                                return null;
                            }
                            i12 = charAt4 - 'A';
                        }
                        i13 = i12 + 10;
                    } else {
                        i13 = charAt4 - '0';
                    }
                    j2 = (j2 << 4) | i13;
                    i19++;
                    indexOf = indexOf;
                    c4 = 'f';
                }
                int i20 = indexOf;
                int i21 = 14;
                long j3 = j2;
                while (i21 < 18) {
                    char charAt5 = charAt(i16 + i21);
                    if (charAt5 < '0' || charAt5 > '9') {
                        if (charAt5 >= c7 && charAt5 <= 'f') {
                            i10 = charAt5 - 'a';
                        } else {
                            if (charAt5 < 'A' || charAt5 > 'F') {
                                this.matchStat = -2;
                                return null;
                            }
                            i10 = charAt5 - 'A';
                        }
                        i11 = i10 + 10;
                    } else {
                        i11 = charAt5 - '0';
                    }
                    j3 = (j3 << 4) | i11;
                    i21++;
                    c7 = 'a';
                }
                int i22 = 19;
                long j4 = 0;
                while (i22 < 23) {
                    char charAt6 = charAt(i16 + i22);
                    if (charAt6 < '0' || charAt6 > c5) {
                        if (charAt6 >= 'a' && charAt6 <= 'f') {
                            i8 = charAt6 - 'a';
                        } else {
                            if (charAt6 < 'A' || charAt6 > 'F') {
                                this.matchStat = -2;
                                return null;
                            }
                            i8 = charAt6 - 'A';
                        }
                        i9 = i8 + 10;
                    } else {
                        i9 = charAt6 - '0';
                    }
                    j4 = (j4 << 4) | i9;
                    i22++;
                    j3 = j3;
                    c5 = '9';
                }
                long j5 = j3;
                long j6 = j4;
                for (int i23 = 24; i23 < 36; i23++) {
                    char charAt7 = charAt(i16 + i23);
                    if (charAt7 < '0' || charAt7 > '9') {
                        if (charAt7 >= 'a' && charAt7 <= 'f') {
                            i6 = charAt7 - 'a';
                        } else {
                            if (charAt7 < 'A' || charAt7 > 'F') {
                                this.matchStat = -2;
                                return null;
                            }
                            i6 = charAt7 - 'A';
                        }
                        i7 = i6 + 10;
                    } else {
                        i7 = charAt7 - '0';
                    }
                    j6 = (j6 << 4) | i7;
                }
                uuid = new UUID(j5, j6);
                int i24 = this.f8506bp;
                int i25 = (i20 - (i24 + 1)) + 1 + 1;
                i2 = i25 + 1;
                charAt = charAt(i24 + i25);
            } else {
                if (i17 != 32) {
                    this.matchStat = -1;
                    return null;
                }
                long j7 = 0;
                for (int i26 = 0; i26 < 16; i26++) {
                    char charAt8 = charAt(i16 + i26);
                    if (charAt8 < '0' || charAt8 > '9') {
                        if (charAt8 >= 'a' && charAt8 <= 'f') {
                            i4 = charAt8 - 'a';
                        } else {
                            if (charAt8 < 'A' || charAt8 > 'F') {
                                this.matchStat = -2;
                                return null;
                            }
                            i4 = charAt8 - 'A';
                        }
                        i5 = i4 + 10;
                    } else {
                        i5 = charAt8 - '0';
                    }
                    j7 = (j7 << 4) | i5;
                }
                int i27 = 16;
                long j8 = 0;
                for (int i28 = 32; i27 < i28; i28 = 32) {
                    char charAt9 = charAt(i16 + i27);
                    if (charAt9 >= '0' && charAt9 <= '9') {
                        i3 = charAt9 - '0';
                    } else if (charAt9 >= 'a' && charAt9 <= 'f') {
                        i3 = (charAt9 - 'a') + 10;
                    } else {
                        if (charAt9 < 'A' || charAt9 > 'F') {
                            this.matchStat = -2;
                            return null;
                        }
                        i3 = (charAt9 - 'A') + 10;
                    }
                    j8 = (j8 << 4) | i3;
                    i27++;
                }
                uuid = new UUID(j7, j8);
                int i29 = this.f8506bp;
                int i30 = (indexOf - (i29 + 1)) + 1 + 1;
                i2 = i30 + 1;
                charAt = charAt(i29 + i30);
            }
        } else {
            if (charAt2 != 'n' || charAt(this.f8506bp + 1) != 'u' || charAt(this.f8506bp + 2) != 'l' || charAt(this.f8506bp + 3) != 'l') {
                this.matchStat = -1;
                return null;
            }
            i2 = 5;
            charAt = charAt(this.f8506bp + 4);
            uuid = null;
        }
        if (charAt == ',') {
            int i31 = this.f8506bp + i2;
            this.f8506bp = i31;
            this.f8507ch = charAt(i31);
            this.matchStat = 3;
            return uuid;
        }
        if (charAt != ']') {
            this.matchStat = -1;
            return null;
        }
        int i32 = i2 + 1;
        char charAt10 = charAt(this.f8506bp + i2);
        if (charAt10 == ',') {
            this.token = 16;
            int i33 = this.f8506bp + i32;
            this.f8506bp = i33;
            this.f8507ch = charAt(i33);
        } else if (charAt10 == ']') {
            this.token = 15;
            int i34 = this.f8506bp + i32;
            this.f8506bp = i34;
            this.f8507ch = charAt(i34);
        } else if (charAt10 == '}') {
            this.token = 13;
            int i35 = this.f8506bp + i32;
            this.f8506bp = i35;
            this.f8507ch = charAt(i35);
        } else {
            if (charAt10 != 26) {
                this.matchStat = -1;
                return null;
            }
            this.token = 20;
            this.f8506bp = (i32 - 1) + this.f8506bp;
            this.f8507ch = JSONLexer.EOI;
        }
        this.matchStat = 4;
        return uuid;
    }

    public boolean seekArrayToItem(int i2) {
        throw new UnsupportedOperationException();
    }

    public int seekObjectToField(long j2, boolean z) {
        throw new UnsupportedOperationException();
    }

    public int seekObjectToFieldDeepScan(long j2) {
        throw new UnsupportedOperationException();
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public void setLocale(Locale locale) {
        this.locale = locale;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public void setTimeZone(TimeZone timeZone) {
        this.timeZone = timeZone;
    }

    public void setToken(int i2) {
        this.token = i2;
    }

    public void skipArray() {
        throw new UnsupportedOperationException();
    }

    public void skipComment() {
        char c2;
        next();
        char c3 = this.f8507ch;
        if (c3 == '/') {
            do {
                next();
                c2 = this.f8507ch;
                if (c2 == '\n') {
                    next();
                    return;
                }
            } while (c2 != 26);
            return;
        }
        if (c3 != '*') {
            throw new JSONException("invalid comment");
        }
        next();
        while (true) {
            char c4 = this.f8507ch;
            if (c4 == 26) {
                return;
            }
            if (c4 == '*') {
                next();
                if (this.f8507ch == '/') {
                    next();
                    return;
                }
            } else {
                next();
            }
        }
    }

    public void skipObject() {
        throw new UnsupportedOperationException();
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void skipWhitespace() {
        while (true) {
            char c2 = this.f8507ch;
            if (c2 > '/') {
                return;
            }
            if (c2 == ' ' || c2 == '\r' || c2 == '\n' || c2 == '\t' || c2 == '\f' || c2 == '\b') {
                next();
            } else if (c2 != '/') {
                return;
            } else {
                skipComment();
            }
        }
    }

    public final String stringDefaultValue() {
        return this.stringDefaultValue;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract String stringVal();

    public abstract String subString(int i2, int i3);

    public abstract char[] sub_chars(int i2, int i3);

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int token() {
        return this.token;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String tokenName() {
        return JSONToken.name(this.token);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final boolean isEnabled(int i2) {
        return (i2 & this.features) != 0;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextTokenWithColon(int i2) {
        nextTokenWithChar(':');
    }

    public final void scanNullOrNew(boolean z) {
        if (this.f8507ch != 'n') {
            throw new JSONException("error parse null or new");
        }
        next();
        char c2 = this.f8507ch;
        if (c2 != 'u') {
            if (c2 != 'e') {
                throw new JSONException("error parse new");
            }
            next();
            if (this.f8507ch != 'w') {
                throw new JSONException("error parse new");
            }
            next();
            char c3 = this.f8507ch;
            if (c3 != ' ' && c3 != ',' && c3 != '}' && c3 != ']' && c3 != '\n' && c3 != '\r' && c3 != '\t' && c3 != 26 && c3 != '\f' && c3 != '\b') {
                throw new JSONException("scan new error");
            }
            this.token = 9;
            return;
        }
        next();
        if (this.f8507ch != 'l') {
            throw new JSONException("error parse null");
        }
        next();
        if (this.f8507ch != 'l') {
            throw new JSONException("error parse null");
        }
        next();
        char c4 = this.f8507ch;
        if (c4 != ' ' && c4 != ',' && c4 != '}' && c4 != ']' && c4 != '\n' && c4 != '\r' && c4 != '\t' && c4 != 26 && ((c4 != ':' || !z) && c4 != '\f' && c4 != '\b')) {
            throw new JSONException("scan null error");
        }
        this.token = 8;
    }

    public int seekObjectToField(long[] jArr) {
        throw new UnsupportedOperationException();
    }

    public void skipObject(boolean z) {
        throw new UnsupportedOperationException();
    }

    public final boolean isEnabled(int i2, int i3) {
        return ((this.features & i3) == 0 && (i2 & i3) == 0) ? false : true;
    }

    public int matchField(long j2) {
        throw new UnsupportedOperationException();
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String scanSymbol(SymbolTable symbolTable, char c2) {
        String addSymbol;
        this.f8508np = this.f8506bp;
        this.f8509sp = 0;
        boolean z = false;
        int i2 = 0;
        while (true) {
            char next = next();
            if (next == c2) {
                this.token = 4;
                if (!z) {
                    int i3 = this.f8508np;
                    addSymbol = addSymbol(i3 == -1 ? 0 : i3 + 1, this.f8509sp, i2, symbolTable);
                } else {
                    addSymbol = symbolTable.addSymbol(this.sbuf, 0, this.f8509sp, i2);
                }
                this.f8509sp = 0;
                next();
                return addSymbol;
            }
            if (next == 26) {
                throw new JSONException("unclosed.str");
            }
            if (next == '\\') {
                if (!z) {
                    int i4 = this.f8509sp;
                    char[] cArr = this.sbuf;
                    if (i4 >= cArr.length) {
                        int length = cArr.length * 2;
                        if (i4 <= length) {
                            i4 = length;
                        }
                        char[] cArr2 = new char[i4];
                        System.arraycopy(cArr, 0, cArr2, 0, cArr.length);
                        this.sbuf = cArr2;
                    }
                    arrayCopy(this.f8508np + 1, this.sbuf, 0, this.f8509sp);
                    z = true;
                }
                char next2 = next();
                if (next2 == '\"') {
                    i2 = (i2 * 31) + 34;
                    putChar(Typography.quote);
                } else if (next2 != '\'') {
                    if (next2 != 'F') {
                        if (next2 == '\\') {
                            i2 = (i2 * 31) + 92;
                            putChar('\\');
                        } else if (next2 == 'b') {
                            i2 = (i2 * 31) + 8;
                            putChar('\b');
                        } else if (next2 != 'f') {
                            if (next2 == 'n') {
                                i2 = (i2 * 31) + 10;
                                putChar('\n');
                            } else if (next2 == 'r') {
                                i2 = (i2 * 31) + 13;
                                putChar('\r');
                            } else if (next2 != 'x') {
                                switch (next2) {
                                    case '/':
                                        i2 = (i2 * 31) + 47;
                                        putChar('/');
                                        break;
                                    case '0':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 0);
                                        break;
                                    case '1':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 1);
                                        break;
                                    case '2':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 2);
                                        break;
                                    case '3':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 3);
                                        break;
                                    case '4':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 4);
                                        break;
                                    case '5':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 5);
                                        break;
                                    case '6':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 6);
                                        break;
                                    case '7':
                                        i2 = (i2 * 31) + next2;
                                        putChar((char) 7);
                                        break;
                                    default:
                                        switch (next2) {
                                            case 't':
                                                i2 = (i2 * 31) + 9;
                                                putChar('\t');
                                                break;
                                            case 'u':
                                                int parseInt = Integer.parseInt(new String(new char[]{next(), next(), next(), next()}), 16);
                                                i2 = (i2 * 31) + parseInt;
                                                putChar((char) parseInt);
                                                break;
                                            case 'v':
                                                i2 = (i2 * 31) + 11;
                                                putChar((char) 11);
                                                break;
                                            default:
                                                this.f8507ch = next2;
                                                throw new JSONException("unclosed.str.lit");
                                        }
                                }
                            } else {
                                char next3 = next();
                                this.f8507ch = next3;
                                char next4 = next();
                                this.f8507ch = next4;
                                int[] iArr = digits;
                                char c3 = (char) ((iArr[next3] * 16) + iArr[next4]);
                                i2 = (i2 * 31) + c3;
                                putChar(c3);
                            }
                        }
                    }
                    i2 = (i2 * 31) + 12;
                    putChar('\f');
                } else {
                    i2 = (i2 * 31) + 39;
                    putChar('\'');
                }
            } else {
                i2 = (i2 * 31) + next;
                if (!z) {
                    this.f8509sp++;
                } else {
                    int i5 = this.f8509sp;
                    char[] cArr3 = this.sbuf;
                    if (i5 == cArr3.length) {
                        putChar(next);
                    } else {
                        this.f8509sp = i5 + 1;
                        cArr3[i5] = next;
                    }
                }
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextToken(int i2) {
        this.f8509sp = 0;
        while (true) {
            if (i2 == 2) {
                char c2 = this.f8507ch;
                if (c2 >= '0' && c2 <= '9') {
                    this.pos = this.f8506bp;
                    scanNumber();
                    return;
                }
                if (c2 == '\"') {
                    this.pos = this.f8506bp;
                    scanString();
                    return;
                } else if (c2 == '[') {
                    this.token = 14;
                    next();
                    return;
                } else if (c2 == '{') {
                    this.token = 12;
                    next();
                    return;
                }
            } else if (i2 == 4) {
                char c3 = this.f8507ch;
                if (c3 == '\"') {
                    this.pos = this.f8506bp;
                    scanString();
                    return;
                }
                if (c3 >= '0' && c3 <= '9') {
                    this.pos = this.f8506bp;
                    scanNumber();
                    return;
                } else if (c3 == '[') {
                    this.token = 14;
                    next();
                    return;
                } else if (c3 == '{') {
                    this.token = 12;
                    next();
                    return;
                }
            } else if (i2 == 12) {
                char c4 = this.f8507ch;
                if (c4 == '{') {
                    this.token = 12;
                    next();
                    return;
                } else if (c4 == '[') {
                    this.token = 14;
                    next();
                    return;
                }
            } else if (i2 != 18) {
                if (i2 != 20) {
                    switch (i2) {
                        case 14:
                            char c5 = this.f8507ch;
                            if (c5 != '[') {
                                if (c5 == '{') {
                                    this.token = 12;
                                    next();
                                    break;
                                }
                            } else {
                                this.token = 14;
                                next();
                                break;
                            }
                            break;
                        case 15:
                            if (this.f8507ch == ']') {
                                this.token = 15;
                                next();
                                break;
                            }
                            break;
                        case 16:
                            char c6 = this.f8507ch;
                            if (c6 != ',') {
                                if (c6 != '}') {
                                    if (c6 != ']') {
                                        if (c6 != 26) {
                                            if (c6 == 'n') {
                                                scanNullOrNew(false);
                                                break;
                                            }
                                        } else {
                                            this.token = 20;
                                            break;
                                        }
                                    } else {
                                        this.token = 15;
                                        next();
                                        break;
                                    }
                                } else {
                                    this.token = 13;
                                    next();
                                    break;
                                }
                            } else {
                                this.token = 16;
                                next();
                                break;
                            }
                            break;
                    }
                    return;
                }
                if (this.f8507ch == 26) {
                    this.token = 20;
                    return;
                }
            } else {
                nextIdent();
                return;
            }
            char c7 = this.f8507ch;
            if (c7 != ' ' && c7 != '\n' && c7 != '\r' && c7 != '\t' && c7 != '\f' && c7 != '\b') {
                nextToken();
                return;
            }
            next();
        }
    }

    public String[] scanFieldStringArray(char[] cArr, int i2, SymbolTable symbolTable) {
        throw new UnsupportedOperationException();
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public String scanString(char c2) {
        this.matchStat = 0;
        char charAt = charAt(this.f8506bp + 0);
        if (charAt == 'n') {
            if (charAt(this.f8506bp + 1) == 'u' && C1499a.m605a(this.f8506bp, 1, 1, this) == 'l' && C1499a.m605a(this.f8506bp, 1, 2, this) == 'l') {
                if (charAt(this.f8506bp + 4) == c2) {
                    int i2 = this.f8506bp + 5;
                    this.f8506bp = i2;
                    this.f8507ch = charAt(i2);
                    this.matchStat = 3;
                    return null;
                }
                this.matchStat = -1;
                return null;
            }
            this.matchStat = -1;
            return null;
        }
        int i3 = 1;
        while (charAt != '\"') {
            if (isWhitespace(charAt)) {
                charAt = charAt(this.f8506bp + i3);
                i3++;
            } else {
                this.matchStat = -1;
                return stringDefaultValue();
            }
        }
        int i4 = this.f8506bp + i3;
        int indexOf = indexOf(Typography.quote, i4);
        if (indexOf != -1) {
            String subString = subString(this.f8506bp + i3, indexOf - i4);
            if (subString.indexOf(92) != -1) {
                while (true) {
                    int i5 = 0;
                    for (int i6 = indexOf - 1; i6 >= 0 && charAt(i6) == '\\'; i6--) {
                        i5++;
                    }
                    if (i5 % 2 == 0) {
                        break;
                    }
                    indexOf = indexOf(Typography.quote, indexOf + 1);
                }
                int i7 = indexOf - i4;
                subString = readString(sub_chars(this.f8506bp + 1, i7), i7);
            }
            int i8 = (indexOf - i4) + 1 + i3;
            int i9 = i8 + 1;
            char charAt2 = charAt(this.f8506bp + i8);
            while (charAt2 != c2) {
                if (!isWhitespace(charAt2)) {
                    if (charAt2 == ']') {
                        int i10 = this.f8506bp + i9;
                        this.f8506bp = i10;
                        this.f8507ch = charAt(i10);
                        this.matchStat = -1;
                    }
                    return subString;
                }
                charAt2 = charAt(this.f8506bp + i9);
                i9++;
            }
            int i11 = this.f8506bp + i9;
            this.f8506bp = i11;
            this.f8507ch = charAt(i11);
            this.matchStat = 3;
            this.token = 16;
            return subString;
        }
        throw new JSONException("unclosed str");
    }
}
