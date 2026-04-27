package com.alibaba.fastjson.parser;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.util.IOUtils;
import com.google.android.exoplayer2.C;
import java.io.Closeable;
import java.lang.ref.SoftReference;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import kotlin.text.Typography;

/* JADX INFO: loaded from: classes.dex */
public abstract class JSONLexerBase implements JSONLexer, Closeable {
    private static final Map<String, Integer> DEFAULT_KEYWORDS;
    protected static final int INT_MULTMIN_RADIX_TEN = -214748364;
    protected static final int INT_N_MULTMAX_RADIX_TEN = -214748364;
    protected static final long MULTMIN_RADIX_TEN = -922337203685477580L;
    protected static final long N_MULTMAX_RADIX_TEN = -922337203685477580L;
    private static final ThreadLocal<SoftReference<char[]>> SBUF_REF_LOCAL;
    protected static final int[] digits;
    protected static final char[] typeFieldName;
    protected static boolean[] whitespaceFlags;
    protected int bp;
    protected char ch;
    protected int eofPos;
    protected boolean hasSpecial;
    protected int np;
    protected int pos;
    protected char[] sbuf;
    protected int sp;
    protected int token;
    protected int features = JSON.DEFAULT_PARSER_FEATURE;
    protected Calendar calendar = null;
    public int matchStat = 0;
    protected Map<String, Integer> keywods = DEFAULT_KEYWORDS;

    public abstract String addSymbol(int i, int i2, int i3, SymbolTable symbolTable);

    protected abstract void arrayCopy(int i, char[] cArr, int i2, int i3);

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract byte[] bytesValue();

    public abstract char charAt(int i);

    protected abstract void copyTo(int i, int i2, char[] cArr);

    public abstract int indexOf(char c, int i);

    public abstract boolean isEOF();

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract char next();

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract String numberString();

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public abstract String stringVal();

    public abstract String subString(int i, int i2);

    static {
        Map<String, Integer> map = new HashMap<>();
        map.put("null", 8);
        map.put("new", 9);
        map.put("true", 6);
        map.put("false", 7);
        map.put("undefined", 23);
        DEFAULT_KEYWORDS = map;
        SBUF_REF_LOCAL = new ThreadLocal<>();
        typeFieldName = ("\"" + JSON.DEFAULT_TYPE_KEY + "\":\"").toCharArray();
        boolean[] zArr = new boolean[256];
        whitespaceFlags = zArr;
        zArr[32] = true;
        zArr[10] = true;
        zArr[13] = true;
        zArr[9] = true;
        zArr[12] = true;
        zArr[8] = true;
        digits = new int[103];
        for (int i = 48; i <= 57; i++) {
            digits[i] = i - 48;
        }
        for (int i2 = 97; i2 <= 102; i2++) {
            digits[i2] = (i2 - 97) + 10;
        }
        for (int i3 = 65; i3 <= 70; i3++) {
            digits[i3] = (i3 - 65) + 10;
        }
    }

    protected void lexError(String key, Object... args) {
        this.token = 1;
    }

    public JSONLexerBase() {
        SoftReference<char[]> sbufRef = SBUF_REF_LOCAL.get();
        if (sbufRef != null) {
            this.sbuf = sbufRef.get();
            SBUF_REF_LOCAL.set(null);
        }
        if (this.sbuf == null) {
            this.sbuf = new char[64];
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextToken() {
        this.sp = 0;
        while (true) {
            this.pos = this.bp;
            char c = this.ch;
            if (c == '\"') {
                scanString();
                return;
            }
            if (c == ',') {
                next();
                this.token = 16;
                return;
            }
            if (c >= '0' && c <= '9') {
                scanNumber();
                return;
            }
            char c2 = this.ch;
            if (c2 == '-') {
                scanNumber();
                return;
            }
            if (c2 != '\f' && c2 != '\r' && c2 != ' ') {
                if (c2 == ':') {
                    next();
                    this.token = 17;
                    return;
                }
                if (c2 == '[') {
                    next();
                    this.token = 14;
                    return;
                }
                if (c2 == ']') {
                    next();
                    this.token = 15;
                    return;
                }
                if (c2 == 'f') {
                    scanFalse();
                    return;
                }
                if (c2 == 'n') {
                    scanNullOrNew();
                    return;
                }
                if (c2 == '{') {
                    next();
                    this.token = 12;
                    return;
                }
                if (c2 == '}') {
                    next();
                    this.token = 13;
                    return;
                }
                if (c2 == 'S') {
                    scanSet();
                    return;
                }
                if (c2 == 'T') {
                    scanTreeSet();
                    return;
                }
                if (c2 == 't') {
                    scanTrue();
                    return;
                }
                if (c2 != 'u') {
                    switch (c2) {
                        case '\b':
                        case '\t':
                        case '\n':
                            break;
                        default:
                            switch (c2) {
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
                                default:
                                    if (isEOF()) {
                                        if (this.token == 20) {
                                            throw new JSONException("EOF error");
                                        }
                                        this.token = 20;
                                        int i = this.eofPos;
                                        this.bp = i;
                                        this.pos = i;
                                        return;
                                    }
                                    lexError("illegal.char", String.valueOf((int) this.ch));
                                    next();
                                    return;
                            }
                    }
                } else {
                    scanUndefined();
                    return;
                }
            }
            next();
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0073 A[SYNTHETIC] */
    @Override // com.alibaba.fastjson.parser.JSONLexer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void nextToken(int r10) {
        /*
            Method dump skipped, instruction units count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONLexerBase.nextToken(int):void");
    }

    public final void nextIdent() {
        while (isWhitespace(this.ch)) {
            next();
        }
        char c = this.ch;
        if (c == '_' || Character.isLetter(c)) {
            scanIdent();
        } else {
            nextToken();
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextTokenWithColon() {
        nextTokenWithChar(':');
    }

    public final void nextTokenWithChar(char expect) {
        this.sp = 0;
        while (true) {
            char c = this.ch;
            if (c == expect) {
                next();
                nextToken();
                return;
            }
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == '\b') {
                next();
            } else {
                throw new JSONException("not match " + expect + " - " + this.ch);
            }
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int token() {
        return this.token;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String tokenName() {
        return JSONToken.name(this.token);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int pos() {
        return this.pos;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int getBufferPosition() {
        return this.bp;
    }

    public final String stringDefaultValue() {
        if (isEnabled(Feature.InitStringFieldAsEmpty)) {
            return "";
        }
        return null;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final Number integerValue() throws NumberFormatException {
        long limit;
        long result = 0;
        boolean negative = false;
        if (this.np == -1) {
            this.np = 0;
        }
        int i = this.np;
        int max = this.np + this.sp;
        char type = ' ';
        char cCharAt = charAt(max - 1);
        if (cCharAt == 'B') {
            max--;
            type = 'B';
        } else if (cCharAt == 'L') {
            max--;
            type = 'L';
        } else if (cCharAt == 'S') {
            max--;
            type = 'S';
        }
        if (charAt(this.np) == '-') {
            negative = true;
            limit = Long.MIN_VALUE;
            i++;
        } else {
            limit = C.TIME_UNSET;
        }
        if (i < max) {
            result = -digits[charAt(i)];
            i++;
        }
        while (i < max) {
            int i2 = i + 1;
            int digit = digits[charAt(i)];
            if (result < -922337203685477580L) {
                return new BigInteger(numberString());
            }
            long result2 = result * 10;
            if (result2 < ((long) digit) + limit) {
                return new BigInteger(numberString());
            }
            result = result2 - ((long) digit);
            i = i2;
        }
        if (negative) {
            if (i <= this.np + 1) {
                throw new NumberFormatException(numberString());
            }
            if (result >= -2147483648L && type != 'L') {
                if (type == 'S') {
                    return Short.valueOf((short) result);
                }
                if (type == 'B') {
                    return Byte.valueOf((byte) result);
                }
                return Integer.valueOf((int) result);
            }
            return Long.valueOf(result);
        }
        long result3 = -result;
        if (result3 <= 2147483647L && type != 'L') {
            if (type == 'S') {
                return Short.valueOf((short) result3);
            }
            if (type == 'B') {
                return Byte.valueOf((byte) result3);
            }
            return Integer.valueOf((int) result3);
        }
        return Long.valueOf(result3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void nextTokenWithColon(int expect) {
        nextTokenWithChar(':');
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public float floatValue() {
        return Float.parseFloat(numberString());
    }

    public double doubleValue() {
        return Double.parseDouble(numberString());
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public void config(Feature feature, boolean state) {
        this.features = Feature.config(this.features, feature, state);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final boolean isEnabled(Feature feature) {
        return Feature.isEnabled(this.features, feature);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final char getCurrent() {
        return this.ch;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String scanSymbol(SymbolTable symbolTable) {
        skipWhitespace();
        char c = this.ch;
        if (c == '\"') {
            return scanSymbol(symbolTable, Typography.quote);
        }
        if (c == '\'') {
            if (!isEnabled(Feature.AllowSingleQuotes)) {
                throw new JSONException("syntax error");
            }
            return scanSymbol(symbolTable, '\'');
        }
        if (c == '}') {
            next();
            this.token = 13;
            return null;
        }
        if (c == ',') {
            next();
            this.token = 16;
            return null;
        }
        if (c == 26) {
            this.token = 20;
            return null;
        }
        if (!isEnabled(Feature.AllowUnQuotedFieldNames)) {
            throw new JSONException("syntax error");
        }
        return scanSymbolUnQuoted(symbolTable);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String scanSymbol(SymbolTable symbolTable, char c) {
        String strAddSymbol;
        int i;
        this.np = this.bp;
        this.sp = 0;
        boolean z = false;
        int i2 = 0;
        while (true) {
            char next = next();
            if (next != c) {
                if (next == 26) {
                    throw new JSONException("unclosed.str");
                }
                if (next == '\\') {
                    if (!z) {
                        int i3 = this.sp;
                        char[] cArr = this.sbuf;
                        if (i3 >= cArr.length) {
                            int length = cArr.length * 2;
                            if (i3 <= length) {
                                i3 = length;
                            }
                            char[] cArr2 = new char[i3];
                            char[] cArr3 = this.sbuf;
                            System.arraycopy(cArr3, 0, cArr2, 0, cArr3.length);
                            this.sbuf = cArr2;
                        }
                        arrayCopy(this.np + 1, this.sbuf, 0, this.sp);
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
                                                    int i4 = Integer.parseInt(new String(new char[]{next(), next(), next(), next()}), 16);
                                                    i2 = (i2 * 31) + i4;
                                                    putChar((char) i4);
                                                    break;
                                                case 'v':
                                                    i2 = (i2 * 31) + 11;
                                                    putChar((char) 11);
                                                    break;
                                                default:
                                                    this.ch = next2;
                                                    throw new JSONException("unclosed.str.lit");
                                            }
                                            break;
                                    }
                                } else {
                                    char next3 = next();
                                    this.ch = next3;
                                    char next4 = next();
                                    this.ch = next4;
                                    int[] iArr = digits;
                                    char c2 = (char) ((iArr[next3] * 16) + iArr[next4]);
                                    i2 = (i2 * 31) + c2;
                                    putChar(c2);
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
                        this.sp++;
                    } else {
                        int i5 = this.sp;
                        char[] cArr4 = this.sbuf;
                        if (i5 == cArr4.length) {
                            putChar(next);
                        } else {
                            this.sp = i5 + 1;
                            cArr4[i5] = next;
                        }
                    }
                }
            } else {
                this.token = 4;
                if (z) {
                    strAddSymbol = symbolTable.addSymbol(this.sbuf, 0, this.sp, i2);
                } else {
                    int i6 = this.np;
                    if (i6 == -1) {
                        i = 0;
                    } else {
                        i = i6 + 1;
                    }
                    strAddSymbol = addSymbol(i, this.sp, i2, symbolTable);
                }
                this.sp = 0;
                next();
                return strAddSymbol;
            }
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void resetStringPosition() {
        this.sp = 0;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final String scanSymbolUnQuoted(SymbolTable symbolTable) {
        boolean[] firstIdentifierFlags = IOUtils.firstIdentifierFlags;
        char first = this.ch;
        boolean firstFlag = this.ch >= firstIdentifierFlags.length || firstIdentifierFlags[first];
        if (!firstFlag) {
            throw new JSONException("illegal identifier : " + this.ch);
        }
        boolean[] identifierFlags = IOUtils.identifierFlags;
        int hash = first;
        this.np = this.bp;
        this.sp = 1;
        while (true) {
            char chLocal = next();
            if (chLocal < identifierFlags.length && !identifierFlags[chLocal]) {
                break;
            }
            int NULL_HASH = hash * 31;
            hash = NULL_HASH + chLocal;
            this.sp++;
        }
        this.ch = charAt(this.bp);
        this.token = 18;
        if (this.sp == 4 && hash == 3392903 && charAt(this.np) == 'n' && charAt(this.np + 1) == 'u' && charAt(this.np + 2) == 'l' && charAt(this.np + 3) == 'l') {
            return null;
        }
        return addSymbol(this.np, this.sp, hash, symbolTable);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void scanString() {
        this.np = this.bp;
        this.hasSpecial = false;
        while (true) {
            char next = next();
            if (next != '\"') {
                if (next == 26) {
                    throw new JSONException("unclosed string : " + next);
                }
                if (next == '\\') {
                    if (!this.hasSpecial) {
                        this.hasSpecial = true;
                        int i = this.sp;
                        char[] cArr = this.sbuf;
                        if (i >= cArr.length) {
                            int length = cArr.length * 2;
                            if (i <= length) {
                                i = length;
                            }
                            char[] cArr2 = new char[i];
                            char[] cArr3 = this.sbuf;
                            System.arraycopy(cArr3, 0, cArr2, 0, cArr3.length);
                            this.sbuf = cArr2;
                        }
                        copyTo(this.np + 1, this.sp, this.sbuf);
                    }
                    char next2 = next();
                    if (next2 == '\"') {
                        putChar(Typography.quote);
                    } else if (next2 != '\'') {
                        if (next2 != 'F') {
                            if (next2 == '\\') {
                                putChar('\\');
                            } else if (next2 == 'b') {
                                putChar('\b');
                            } else if (next2 != 'f') {
                                if (next2 == 'n') {
                                    putChar('\n');
                                } else if (next2 == 'r') {
                                    putChar('\r');
                                } else if (next2 != 'x') {
                                    switch (next2) {
                                        case '/':
                                            putChar('/');
                                            break;
                                        case '0':
                                            putChar((char) 0);
                                            break;
                                        case '1':
                                            putChar((char) 1);
                                            break;
                                        case '2':
                                            putChar((char) 2);
                                            break;
                                        case '3':
                                            putChar((char) 3);
                                            break;
                                        case '4':
                                            putChar((char) 4);
                                            break;
                                        case '5':
                                            putChar((char) 5);
                                            break;
                                        case '6':
                                            putChar((char) 6);
                                            break;
                                        case '7':
                                            putChar((char) 7);
                                            break;
                                        default:
                                            switch (next2) {
                                                case 't':
                                                    putChar('\t');
                                                    break;
                                                case 'u':
                                                    putChar((char) Integer.parseInt(new String(new char[]{next(), next(), next(), next()}), 16));
                                                    break;
                                                case 'v':
                                                    putChar((char) 11);
                                                    break;
                                                default:
                                                    this.ch = next2;
                                                    throw new JSONException("unclosed string : " + next2);
                                            }
                                            break;
                                    }
                                } else {
                                    char next3 = next();
                                    char next4 = next();
                                    int[] iArr = digits;
                                    putChar((char) ((iArr[next3] * 16) + iArr[next4]));
                                }
                            }
                        }
                        putChar('\f');
                    } else {
                        putChar('\'');
                    }
                } else if (!this.hasSpecial) {
                    this.sp++;
                } else {
                    int i2 = this.sp;
                    char[] cArr4 = this.sbuf;
                    if (i2 == cArr4.length) {
                        putChar(next);
                    } else {
                        this.sp = i2 + 1;
                        cArr4[i2] = next;
                    }
                }
            } else {
                this.token = 4;
                this.ch = next();
                return;
            }
        }
    }

    public Calendar getCalendar() {
        return this.calendar;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final int intValue() {
        int limit;
        if (this.np == -1) {
            this.np = 0;
        }
        int result = 0;
        boolean negative = false;
        int i = this.np;
        int i2 = this.np;
        int max = this.sp + i2;
        if (charAt(i2) == '-') {
            negative = true;
            limit = Integer.MIN_VALUE;
            i++;
        } else {
            limit = -2147483647;
        }
        if (i < max) {
            result = -digits[charAt(i)];
            i++;
        }
        while (i < max) {
            int i3 = i + 1;
            char chLocal = charAt(i);
            if (chLocal != 'L' && chLocal != 'S' && chLocal != 'B') {
                int digit = digits[chLocal];
                if (result < -214748364) {
                    throw new NumberFormatException(numberString());
                }
                int result2 = result * 10;
                if (result2 < limit + digit) {
                    throw new NumberFormatException(numberString());
                }
                result = result2 - digit;
                i = i3;
            } else {
                i = i3;
                break;
            }
        }
        if (negative) {
            if (i > this.np + 1) {
                return result;
            }
            throw new NumberFormatException(numberString());
        }
        return -result;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.sbuf.length <= 8192) {
            SBUF_REF_LOCAL.set(new SoftReference<>(this.sbuf));
        }
        this.sbuf = null;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final boolean isRef() {
        return this.sp == 4 && charAt(this.np + 1) == '$' && charAt(this.np + 2) == 'r' && charAt(this.np + 3) == 'e' && charAt(this.np + 4) == 'f';
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public String scanString(char expectNextChar) {
        this.matchStat = 0;
        int offset = 0 + 1;
        char chLocal = charAt(this.bp + 0);
        if (chLocal == 'n') {
            if (charAt(this.bp + offset) == 'u' && charAt(this.bp + offset + 1) == 'l' && charAt(this.bp + offset + 2) == 'l') {
                int offset2 = offset + 3;
                int offset3 = offset2 + 1;
                if (charAt(this.bp + offset2) == expectNextChar) {
                    this.bp += offset3 - 1;
                    next();
                    this.matchStat = 3;
                    return null;
                }
                this.matchStat = -1;
                return null;
            }
            this.matchStat = -1;
            return null;
        }
        if (chLocal != '\"') {
            this.matchStat = -1;
            return stringDefaultValue();
        }
        boolean hasSpecial = false;
        int startIndex = this.bp + 1;
        int endIndex = indexOf(Typography.quote, startIndex);
        if (endIndex == -1) {
            throw new JSONException("unclosed str");
        }
        String stringVal = subString(this.bp + 1, endIndex - startIndex);
        int i = this.bp + 1;
        while (true) {
            if (i >= endIndex) {
                break;
            }
            if (charAt(i) != '\\') {
                i++;
            } else {
                hasSpecial = true;
                break;
            }
        }
        if (hasSpecial) {
            this.matchStat = -1;
            return stringDefaultValue();
        }
        int i2 = this.bp;
        int offset4 = offset + (endIndex - (i2 + 1)) + 1;
        int offset5 = offset4 + 1;
        if (charAt(i2 + offset4) == expectNextChar) {
            this.bp += offset5 - 1;
            next();
            this.matchStat = 3;
            return stringVal;
        }
        this.matchStat = -1;
        return stringVal;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public Enum<?> scanEnum(Class<?> enumClass, SymbolTable symbolTable, char serperator) {
        String name = scanSymbolWithSeperator(symbolTable, serperator);
        if (name == null) {
            return null;
        }
        return Enum.valueOf(enumClass, name);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public String scanSymbolWithSeperator(SymbolTable symbolTable, char serperator) {
        this.matchStat = 0;
        int offset = 0 + 1;
        char chLocal = charAt(this.bp + 0);
        if (chLocal == 'n') {
            if (charAt(this.bp + offset) == 'u' && charAt(this.bp + offset + 1) == 'l' && charAt(this.bp + offset + 2) == 'l') {
                int offset2 = offset + 3;
                int offset3 = offset2 + 1;
                if (charAt(this.bp + offset2) == serperator) {
                    this.bp += offset3 - 1;
                    next();
                    this.matchStat = 3;
                    return null;
                }
                this.matchStat = -1;
                return null;
            }
            this.matchStat = -1;
            return null;
        }
        if (chLocal != '\"') {
            this.matchStat = -1;
            return null;
        }
        int hash = 0;
        while (true) {
            int offset4 = offset + 1;
            char chLocal2 = charAt(this.bp + offset);
            if (chLocal2 == '\"') {
                int i = this.bp;
                int start = i + 0 + 1;
                int len = ((i + offset4) - start) - 1;
                String strVal = addSymbol(start, len, hash, symbolTable);
                int offset5 = offset4 + 1;
                if (charAt(this.bp + offset4) == serperator) {
                    this.bp += offset5 - 1;
                    next();
                    this.matchStat = 3;
                    return strVal;
                }
                this.matchStat = -1;
                return strVal;
            }
            hash = (hash * 31) + chLocal2;
            if (chLocal2 != '\\') {
                offset = offset4;
            } else {
                this.matchStat = -1;
                return null;
            }
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public int scanInt(char expectNext) {
        int offset;
        char chLocal;
        this.matchStat = 0;
        int offset2 = 0 + 1;
        char chLocal2 = charAt(this.bp + 0);
        if (chLocal2 >= '0' && chLocal2 <= '9') {
            int value = digits[chLocal2];
            while (true) {
                offset = offset2 + 1;
                chLocal = charAt(this.bp + offset2);
                if (chLocal < '0' || chLocal > '9') {
                    break;
                }
                value = (value * 10) + digits[chLocal];
                offset2 = offset;
            }
            if (chLocal == '.') {
                this.matchStat = -1;
                return 0;
            }
            if (value < 0) {
                this.matchStat = -1;
                return 0;
            }
            if (chLocal == expectNext) {
                this.bp += offset - 1;
                next();
                this.matchStat = 3;
                this.token = 16;
                return value;
            }
            this.matchStat = -1;
            return value;
        }
        this.matchStat = -1;
        return 0;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public long scanLong(char expectNextChar) {
        int offset;
        char chLocal;
        this.matchStat = 0;
        int offset2 = 0 + 1;
        char chLocal2 = charAt(this.bp + 0);
        if (chLocal2 >= '0' && chLocal2 <= '9') {
            long value = digits[chLocal2];
            while (true) {
                offset = offset2 + 1;
                chLocal = charAt(this.bp + offset2);
                if (chLocal < '0' || chLocal > '9') {
                    break;
                }
                value = (10 * value) + ((long) digits[chLocal]);
                offset2 = offset;
            }
            if (chLocal == '.') {
                this.matchStat = -1;
                return 0L;
            }
            if (value < 0) {
                this.matchStat = -1;
                return 0L;
            }
            if (chLocal == expectNextChar) {
                this.bp += offset - 1;
                next();
                this.matchStat = 3;
                this.token = 16;
                return value;
            }
            this.matchStat = -1;
            return value;
        }
        this.matchStat = -1;
        return 0L;
    }

    public final void scanTrue() {
        if (this.ch != 't') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'r') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'u') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse true");
        }
        next();
        char c = this.ch;
        if (c == ' ' || c == ',' || c == '}' || c == ']' || c == '\n' || c == '\r' || c == '\t' || c == 26 || c == '\f' || c == '\b' || c == ':') {
            this.token = 6;
            return;
        }
        throw new JSONException("scan true error");
    }

    public final void scanTreeSet() {
        if (this.ch != 'T') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'r') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'S') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 't') {
            throw new JSONException("error parse true");
        }
        next();
        char c = this.ch;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == '\b' || c == '[' || c == '(') {
            this.token = 22;
            return;
        }
        throw new JSONException("scan set error");
    }

    public final void scanNullOrNew() {
        if (this.ch != 'n') {
            throw new JSONException("error parse null or new");
        }
        next();
        char c = this.ch;
        if (c == 'u') {
            next();
            if (this.ch != 'l') {
                throw new JSONException("error parse true");
            }
            next();
            if (this.ch != 'l') {
                throw new JSONException("error parse true");
            }
            next();
            char c2 = this.ch;
            if (c2 == ' ' || c2 == ',' || c2 == '}' || c2 == ']' || c2 == '\n' || c2 == '\r' || c2 == '\t' || c2 == 26 || c2 == '\f' || c2 == '\b') {
                this.token = 8;
                return;
            }
            throw new JSONException("scan true error");
        }
        if (c != 'e') {
            throw new JSONException("error parse e");
        }
        next();
        if (this.ch != 'w') {
            throw new JSONException("error parse w");
        }
        next();
        char c3 = this.ch;
        if (c3 == ' ' || c3 == ',' || c3 == '}' || c3 == ']' || c3 == '\n' || c3 == '\r' || c3 == '\t' || c3 == 26 || c3 == '\f' || c3 == '\b') {
            this.token = 9;
            return;
        }
        throw new JSONException("scan true error");
    }

    public final void scanUndefined() {
        if (this.ch != 'u') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'n') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'd') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'f') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'i') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'n') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'd') {
            throw new JSONException("error parse false");
        }
        next();
        char c = this.ch;
        if (c == ' ' || c == ',' || c == '}' || c == ']' || c == '\n' || c == '\r' || c == '\t' || c == 26 || c == '\f' || c == '\b') {
            this.token = 23;
            return;
        }
        throw new JSONException("scan false error");
    }

    public final void scanFalse() {
        if (this.ch != 'f') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'a') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'l') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 's') {
            throw new JSONException("error parse false");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse false");
        }
        next();
        char c = this.ch;
        if (c == ' ' || c == ',' || c == '}' || c == ']' || c == '\n' || c == '\r' || c == '\t' || c == 26 || c == '\f' || c == '\b' || c == ':') {
            this.token = 7;
            return;
        }
        throw new JSONException("scan false error");
    }

    public final void scanIdent() {
        this.np = this.bp - 1;
        this.hasSpecial = false;
        do {
            this.sp++;
            next();
        } while (Character.isLetterOrDigit(this.ch));
        String ident = stringVal();
        Integer tok = getKeyword(ident);
        if (tok != null) {
            this.token = tok.intValue();
        } else {
            this.token = 18;
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final boolean isBlankInput() {
        int i = 0;
        while (true) {
            char chLocal = charAt(i);
            if (chLocal != 26) {
                if (isWhitespace(chLocal)) {
                    i++;
                } else {
                    return false;
                }
            } else {
                return true;
            }
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void skipWhitespace() {
        while (true) {
            char c = this.ch;
            boolean[] zArr = whitespaceFlags;
            if (c < zArr.length && zArr[c]) {
                next();
            } else {
                return;
            }
        }
    }

    private final void scanStringSingleQuote() {
        this.np = this.bp;
        this.hasSpecial = false;
        while (true) {
            char next = next();
            if (next != '\'') {
                if (next == 26) {
                    throw new JSONException("unclosed single-quote string");
                }
                if (next == '\\') {
                    if (!this.hasSpecial) {
                        this.hasSpecial = true;
                        int i = this.sp;
                        char[] cArr = this.sbuf;
                        if (i > cArr.length) {
                            char[] cArr2 = new char[i * 2];
                            System.arraycopy(cArr, 0, cArr2, 0, cArr.length);
                            this.sbuf = cArr2;
                        }
                        copyTo(this.np + 1, this.sp, this.sbuf);
                    }
                    char next2 = next();
                    if (next2 == '\"') {
                        putChar(Typography.quote);
                    } else if (next2 != '\'') {
                        if (next2 != 'F') {
                            if (next2 == '\\') {
                                putChar('\\');
                            } else if (next2 == 'b') {
                                putChar('\b');
                            } else if (next2 != 'f') {
                                if (next2 == 'n') {
                                    putChar('\n');
                                } else if (next2 == 'r') {
                                    putChar('\r');
                                } else if (next2 != 'x') {
                                    switch (next2) {
                                        case '/':
                                            putChar('/');
                                            break;
                                        case '0':
                                            putChar((char) 0);
                                            break;
                                        case '1':
                                            putChar((char) 1);
                                            break;
                                        case '2':
                                            putChar((char) 2);
                                            break;
                                        case '3':
                                            putChar((char) 3);
                                            break;
                                        case '4':
                                            putChar((char) 4);
                                            break;
                                        case '5':
                                            putChar((char) 5);
                                            break;
                                        case '6':
                                            putChar((char) 6);
                                            break;
                                        case '7':
                                            putChar((char) 7);
                                            break;
                                        default:
                                            switch (next2) {
                                                case 't':
                                                    putChar('\t');
                                                    break;
                                                case 'u':
                                                    putChar((char) Integer.parseInt(new String(new char[]{next(), next(), next(), next()}), 16));
                                                    break;
                                                case 'v':
                                                    putChar((char) 11);
                                                    break;
                                                default:
                                                    this.ch = next2;
                                                    throw new JSONException("unclosed single-quote string");
                                            }
                                            break;
                                    }
                                } else {
                                    char next3 = next();
                                    char next4 = next();
                                    int[] iArr = digits;
                                    putChar((char) ((iArr[next3] * 16) + iArr[next4]));
                                }
                            }
                        }
                        putChar('\f');
                    } else {
                        putChar('\'');
                    }
                } else if (!this.hasSpecial) {
                    this.sp++;
                } else {
                    int i2 = this.sp;
                    char[] cArr3 = this.sbuf;
                    if (i2 == cArr3.length) {
                        putChar(next);
                    } else {
                        this.sp = i2 + 1;
                        cArr3[i2] = next;
                    }
                }
            } else {
                this.token = 4;
                next();
                return;
            }
        }
    }

    public final void scanSet() {
        if (this.ch != 'S') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 'e') {
            throw new JSONException("error parse true");
        }
        next();
        if (this.ch != 't') {
            throw new JSONException("error parse true");
        }
        next();
        char c = this.ch;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' || c == '\b' || c == '[' || c == '(') {
            this.token = 21;
            return;
        }
        throw new JSONException("scan set error");
    }

    protected final void putChar(char ch) {
        int i = this.sp;
        char[] cArr = this.sbuf;
        if (i == cArr.length) {
            char[] newsbuf = new char[cArr.length * 2];
            System.arraycopy(cArr, 0, newsbuf, 0, cArr.length);
            this.sbuf = newsbuf;
        }
        char[] newsbuf2 = this.sbuf;
        int i2 = this.sp;
        this.sp = i2 + 1;
        newsbuf2[i2] = ch;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final void scanNumber() {
        this.np = this.bp;
        if (this.ch == '-') {
            this.sp++;
            next();
        }
        while (true) {
            char c = this.ch;
            if (c < '0' || c > '9') {
                break;
            }
            this.sp++;
            next();
        }
        boolean isDouble = false;
        if (this.ch == '.') {
            this.sp++;
            next();
            isDouble = true;
            while (true) {
                char c2 = this.ch;
                if (c2 < '0' || c2 > '9') {
                    break;
                }
                this.sp++;
                next();
            }
        }
        char c3 = this.ch;
        if (c3 == 'L' || c3 == 'S' || c3 == 'B') {
            this.sp++;
            next();
        } else if (c3 == 'F' || c3 == 'D') {
            this.sp++;
            next();
            isDouble = true;
        } else if (c3 == 'e' || c3 == 'E') {
            this.sp++;
            next();
            char c4 = this.ch;
            if (c4 == '+' || c4 == '-') {
                this.sp++;
                next();
            }
            while (true) {
                char c5 = this.ch;
                if (c5 < '0' || c5 > '9') {
                    break;
                }
                this.sp++;
                next();
            }
            char c6 = this.ch;
            if (c6 == 'D' || c6 == 'F') {
                this.sp++;
                next();
            }
            isDouble = true;
        }
        if (isDouble) {
            this.token = 3;
        } else {
            this.token = 2;
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final long longValue() throws NumberFormatException {
        long limit;
        long result = 0;
        boolean negative = false;
        int i = this.np;
        int i2 = this.np;
        int max = this.sp + i2;
        if (charAt(i2) == '-') {
            negative = true;
            limit = Long.MIN_VALUE;
            i++;
        } else {
            limit = C.TIME_UNSET;
        }
        if (i < max) {
            result = -digits[charAt(i)];
            i++;
        }
        while (i < max) {
            int i3 = i + 1;
            char chLocal = charAt(i);
            if (chLocal != 'L' && chLocal != 'S' && chLocal != 'B') {
                int digit = digits[chLocal];
                if (result < -922337203685477580L) {
                    throw new NumberFormatException(numberString());
                }
                long result2 = result * 10;
                if (result2 < ((long) digit) + limit) {
                    throw new NumberFormatException(numberString());
                }
                result = result2 - ((long) digit);
                i = i3;
            } else {
                i = i3;
                break;
            }
        }
        if (negative) {
            if (i > this.np + 1) {
                return result;
            }
            throw new NumberFormatException(numberString());
        }
        return -result;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final Number decimalValue(boolean decimal) {
        char chLocal = charAt((this.np + this.sp) - 1);
        if (chLocal == 'F') {
            return Float.valueOf(Float.parseFloat(numberString()));
        }
        if (chLocal == 'D') {
            return Double.valueOf(Double.parseDouble(numberString()));
        }
        if (decimal) {
            return decimalValue();
        }
        return Double.valueOf(doubleValue());
    }

    @Override // com.alibaba.fastjson.parser.JSONLexer
    public final BigDecimal decimalValue() {
        return new BigDecimal(numberString());
    }

    public static final boolean isWhitespace(char ch) {
        return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\f' || ch == '\b';
    }

    public Integer getKeyword(String key) {
        return this.keywods.get(key);
    }
}
