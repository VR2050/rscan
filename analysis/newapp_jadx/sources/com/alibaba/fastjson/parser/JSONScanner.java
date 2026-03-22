package com.alibaba.fastjson.parser;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.util.ASMUtils;
import com.alibaba.fastjson.util.IOUtils;
import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Date;
import java.util.SimpleTimeZone;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class JSONScanner extends JSONLexerBase {
    private final int len;
    private final String text;

    public JSONScanner(String str) {
        this(str, JSON.DEFAULT_PARSER_FEATURE);
    }

    public static boolean charArrayCompare(String str, int i2, char[] cArr) {
        int length = cArr.length;
        if (length + i2 > str.length()) {
            return false;
        }
        for (int i3 = 0; i3 < length; i3++) {
            if (cArr[i3] != str.charAt(i2 + i3)) {
                return false;
            }
        }
        return true;
    }

    public static boolean checkDate(char c2, char c3, char c4, char c5, char c6, char c7, int i2, int i3) {
        if (c2 >= '0' && c2 <= '9' && c3 >= '0' && c3 <= '9' && c4 >= '0' && c4 <= '9' && c5 >= '0' && c5 <= '9') {
            if (c6 == '0') {
                if (c7 < '1' || c7 > '9') {
                    return false;
                }
            } else if (c6 != '1' || (c7 != '0' && c7 != '1' && c7 != '2')) {
                return false;
            }
            if (i2 == 48) {
                return i3 >= 49 && i3 <= 57;
            }
            if (i2 != 49 && i2 != 50) {
                return i2 == 51 && (i3 == 48 || i3 == 49);
            }
            if (i3 >= 48 && i3 <= 57) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x001d, code lost:
    
        if (r6 <= '4') goto L18;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean checkTime(char r5, char r6, char r7, char r8, char r9, char r10) {
        /*
            r4 = this;
            r0 = 57
            r1 = 0
            r2 = 48
            if (r5 != r2) goto Lc
            if (r6 < r2) goto Lb
            if (r6 <= r0) goto L20
        Lb:
            return r1
        Lc:
            r3 = 49
            if (r5 != r3) goto L15
            if (r6 < r2) goto L14
            if (r6 <= r0) goto L20
        L14:
            return r1
        L15:
            r3 = 50
            if (r5 != r3) goto L42
            if (r6 < r2) goto L42
            r5 = 52
            if (r6 <= r5) goto L20
            goto L42
        L20:
            r5 = 53
            r6 = 54
            if (r7 < r2) goto L2d
            if (r7 > r5) goto L2d
            if (r8 < r2) goto L2c
            if (r8 <= r0) goto L32
        L2c:
            return r1
        L2d:
            if (r7 != r6) goto L42
            if (r8 == r2) goto L32
            return r1
        L32:
            if (r9 < r2) goto L3b
            if (r9 > r5) goto L3b
            if (r10 < r2) goto L3a
            if (r10 <= r0) goto L40
        L3a:
            return r1
        L3b:
            if (r9 != r6) goto L42
            if (r10 == r2) goto L40
            return r1
        L40:
            r5 = 1
            return r5
        L42:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.checkTime(char, char, char, char, char, char):boolean");
    }

    private void setCalendar(char c2, char c3, char c4, char c5, char c6, char c7, char c8, char c9) {
        Calendar calendar = Calendar.getInstance(this.timeZone, this.locale);
        this.calendar = calendar;
        int i2 = c5 - '0';
        calendar.set(1, i2 + ((c4 - '0') * 10) + ((c3 - '0') * 100) + ((c2 - '0') * 1000));
        this.calendar.set(2, ((c7 - '0') + ((c6 - '0') * 10)) - 1);
        this.calendar.set(5, (c9 - '0') + ((c8 - '0') * 10));
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final String addSymbol(int i2, int i3, int i4, SymbolTable symbolTable) {
        return symbolTable.addSymbol(this.text, i2, i3, i4);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void arrayCopy(int i2, char[] cArr, int i3, int i4) {
        this.text.getChars(i2, i4 + i2, cArr, i3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public byte[] bytesValue() {
        if (this.token != 26) {
            return !this.hasSpecial ? IOUtils.decodeBase64(this.text, this.f8508np + 1, this.f8509sp) : IOUtils.decodeBase64(new String(this.sbuf, 0, this.f8509sp));
        }
        int i2 = this.f8508np + 1;
        int i3 = this.f8509sp;
        if (i3 % 2 != 0) {
            throw new JSONException(C1499a.m626l("illegal state. ", i3));
        }
        int i4 = i3 / 2;
        byte[] bArr = new byte[i4];
        for (int i5 = 0; i5 < i4; i5++) {
            int i6 = (i5 * 2) + i2;
            char charAt = this.text.charAt(i6);
            char charAt2 = this.text.charAt(i6 + 1);
            char c2 = '0';
            int i7 = charAt - (charAt <= '9' ? '0' : '7');
            if (charAt2 > '9') {
                c2 = '7';
            }
            bArr[i5] = (byte) ((i7 << 4) | (charAt2 - c2));
        }
        return bArr;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final char charAt(int i2) {
        return i2 >= this.len ? JSONLexer.EOI : this.text.charAt(i2);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void copyTo(int i2, int i3, char[] cArr) {
        this.text.getChars(i2, i3 + i2, cArr, 0);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final BigDecimal decimalValue() {
        char charAt = charAt((this.f8508np + this.f8509sp) - 1);
        int i2 = this.f8509sp;
        if (charAt == 'L' || charAt == 'S' || charAt == 'B' || charAt == 'F' || charAt == 'D') {
            i2--;
        }
        int i3 = this.f8508np;
        char[] cArr = this.sbuf;
        if (i2 < cArr.length) {
            this.text.getChars(i3, i3 + i2, cArr, 0);
            return new BigDecimal(this.sbuf, 0, i2);
        }
        char[] cArr2 = new char[i2];
        this.text.getChars(i3, i2 + i3, cArr2, 0);
        return new BigDecimal(cArr2);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final int indexOf(char c2, int i2) {
        return this.text.indexOf(c2, i2);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public String info() {
        StringBuilder sb = new StringBuilder();
        int i2 = 0;
        int i3 = 1;
        int i4 = 1;
        while (i2 < this.f8506bp) {
            if (this.text.charAt(i2) == '\n') {
                i3++;
                i4 = 1;
            }
            i2++;
            i4++;
        }
        sb.append("pos ");
        sb.append(this.f8506bp);
        sb.append(", line ");
        sb.append(i3);
        sb.append(", column ");
        sb.append(i4);
        if (this.text.length() < 65535) {
            sb.append(this.text);
        } else {
            sb.append(this.text.substring(0, 65535));
        }
        return sb.toString();
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public boolean isEOF() {
        int i2 = this.f8506bp;
        int i3 = this.len;
        if (i2 != i3) {
            return this.f8507ch == 26 && i2 + 1 >= i3;
        }
        return true;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public boolean matchField2(char[] cArr) {
        while (JSONLexerBase.isWhitespace(this.f8507ch)) {
            next();
        }
        if (!charArrayCompare(cArr)) {
            this.matchStat = -2;
            return false;
        }
        int length = this.f8506bp + cArr.length;
        int i2 = length + 1;
        char charAt = this.text.charAt(length);
        while (JSONLexerBase.isWhitespace(charAt)) {
            charAt = this.text.charAt(i2);
            i2++;
        }
        if (charAt != ':') {
            this.matchStat = -2;
            return false;
        }
        this.f8506bp = i2;
        this.f8507ch = charAt(i2);
        return true;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final char next() {
        int i2 = this.f8506bp + 1;
        this.f8506bp = i2;
        char charAt = i2 >= this.len ? JSONLexer.EOI : this.text.charAt(i2);
        this.f8507ch = charAt;
        return charAt;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final String numberString() {
        char charAt = charAt((this.f8508np + this.f8509sp) - 1);
        int i2 = this.f8509sp;
        if (charAt == 'L' || charAt == 'S' || charAt == 'B' || charAt == 'F' || charAt == 'D') {
            i2--;
        }
        return subString(this.f8508np, i2);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public Date scanDate(char c2) {
        char c3;
        long j2;
        Date date;
        int i2;
        boolean z = false;
        this.matchStat = 0;
        int i3 = this.f8506bp;
        char c4 = this.f8507ch;
        int i4 = i3 + 1;
        char charAt = charAt(i3);
        if (charAt == '\"') {
            int indexOf = indexOf(Typography.quote, i4);
            if (indexOf == -1) {
                throw new JSONException("unclosed str");
            }
            this.f8506bp = i4;
            if (!scanISO8601DateIfMatch(false, indexOf - i4)) {
                this.f8506bp = i3;
                this.f8507ch = c4;
                this.matchStat = -1;
                return null;
            }
            date = this.calendar.getTime();
            c3 = charAt(indexOf + 1);
            this.f8506bp = i3;
            while (c3 != ',' && c3 != ']') {
                if (!JSONLexerBase.isWhitespace(c3)) {
                    this.f8506bp = i3;
                    this.f8507ch = c4;
                    this.matchStat = -1;
                    return null;
                }
                indexOf++;
                c3 = charAt(indexOf + 1);
            }
            this.f8506bp = indexOf + 1;
            this.f8507ch = c3;
        } else {
            char c5 = '9';
            char c6 = '0';
            if (charAt != '-' && (charAt < '0' || charAt > '9')) {
                if (charAt == 'n') {
                    int i5 = i4 + 1;
                    if (charAt(i4) == 'u') {
                        int i6 = i5 + 1;
                        if (charAt(i5) == 'l') {
                            int i7 = i6 + 1;
                            if (charAt(i6) == 'l') {
                                c3 = charAt(i7);
                                this.f8506bp = i7;
                                date = null;
                            }
                        }
                    }
                }
                this.f8506bp = i3;
                this.f8507ch = c4;
                this.matchStat = -1;
                return null;
            }
            if (charAt == '-') {
                charAt = charAt(i4);
                i4++;
                z = true;
            }
            if (charAt < '0' || charAt > '9') {
                c3 = charAt;
                j2 = 0;
            } else {
                j2 = charAt - '0';
                while (true) {
                    i2 = i4 + 1;
                    c3 = charAt(i4);
                    if (c3 < c6 || c3 > c5) {
                        break;
                    }
                    j2 = (j2 * 10) + (c3 - '0');
                    i4 = i2;
                    c5 = '9';
                    c6 = '0';
                }
                if (c3 == ',' || c3 == ']') {
                    this.f8506bp = i2 - 1;
                }
            }
            if (j2 < 0) {
                this.f8506bp = i3;
                this.f8507ch = c4;
                this.matchStat = -1;
                return null;
            }
            if (z) {
                j2 = -j2;
            }
            date = new Date(j2);
        }
        if (c3 == ',') {
            int i8 = this.f8506bp + 1;
            this.f8506bp = i8;
            this.f8507ch = charAt(i8);
            this.matchStat = 3;
            return date;
        }
        int i9 = this.f8506bp + 1;
        this.f8506bp = i9;
        char charAt2 = charAt(i9);
        if (charAt2 == ',') {
            this.token = 16;
            int i10 = this.f8506bp + 1;
            this.f8506bp = i10;
            this.f8507ch = charAt(i10);
        } else if (charAt2 == ']') {
            this.token = 15;
            int i11 = this.f8506bp + 1;
            this.f8506bp = i11;
            this.f8507ch = charAt(i11);
        } else if (charAt2 == '}') {
            this.token = 13;
            int i12 = this.f8506bp + 1;
            this.f8506bp = i12;
            this.f8507ch = charAt(i12);
        } else {
            if (charAt2 != 26) {
                this.f8506bp = i3;
                this.f8507ch = c4;
                this.matchStat = -1;
                return null;
            }
            this.f8507ch = JSONLexer.EOI;
            this.token = 20;
        }
        this.matchStat = 4;
        return date;
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00c0  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:46:0x00c4 -> B:42:0x00b4). Please report as a decompilation issue!!! */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public double scanDouble(char r22) {
        /*
            Method dump skipped, instructions count: 391
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanDouble(char):double");
    }

    /* JADX WARN: Code restructure failed: missing block: B:61:0x0152, code lost:
    
        return r2;
     */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00f3 A[SYNTHETIC] */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean scanFieldBoolean(char[] r11) {
        /*
            Method dump skipped, instructions count: 386
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanFieldBoolean(char[]):boolean");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public Date scanFieldDate(char[] cArr) {
        char c2;
        long j2;
        char c3;
        Date date;
        int i2;
        boolean z = false;
        this.matchStat = 0;
        int i3 = this.f8506bp;
        char c4 = this.f8507ch;
        if (!charArrayCompare(this.text, i3, cArr)) {
            this.matchStat = -2;
            return null;
        }
        int length = this.f8506bp + cArr.length;
        int i4 = length + 1;
        char charAt = charAt(length);
        if (charAt == '\"') {
            int indexOf = indexOf(Typography.quote, i4);
            if (indexOf == -1) {
                throw new JSONException("unclosed str");
            }
            this.f8506bp = i4;
            if (!scanISO8601DateIfMatch(false, indexOf - i4)) {
                this.f8506bp = i3;
                this.matchStat = -1;
                return null;
            }
            date = this.calendar.getTime();
            c3 = charAt(indexOf + 1);
            this.f8506bp = i3;
            while (c3 != ',' && c3 != '}') {
                if (!JSONLexerBase.isWhitespace(c3)) {
                    this.matchStat = -1;
                    return null;
                }
                indexOf++;
                c3 = charAt(indexOf + 1);
            }
            this.f8506bp = indexOf + 1;
            this.f8507ch = c3;
        } else {
            char c5 = '9';
            char c6 = '0';
            if (charAt != '-' && (charAt < '0' || charAt > '9')) {
                this.matchStat = -1;
                return null;
            }
            if (charAt == '-') {
                charAt = charAt(i4);
                i4++;
                z = true;
            }
            if (charAt < '0' || charAt > '9') {
                c2 = charAt;
                j2 = 0;
            } else {
                j2 = charAt - '0';
                while (true) {
                    i2 = i4 + 1;
                    c2 = charAt(i4);
                    if (c2 < c6 || c2 > c5) {
                        break;
                    }
                    j2 = (j2 * 10) + (c2 - '0');
                    i4 = i2;
                    c5 = '9';
                    c6 = '0';
                }
                if (c2 == ',' || c2 == '}') {
                    this.f8506bp = i2 - 1;
                }
            }
            if (j2 < 0) {
                this.matchStat = -1;
                return null;
            }
            if (z) {
                j2 = -j2;
            }
            c3 = c2;
            date = new Date(j2);
        }
        if (c3 == ',') {
            int i5 = this.f8506bp + 1;
            this.f8506bp = i5;
            this.f8507ch = charAt(i5);
            this.matchStat = 3;
            this.token = 16;
            return date;
        }
        int i6 = this.f8506bp + 1;
        this.f8506bp = i6;
        char charAt2 = charAt(i6);
        if (charAt2 == ',') {
            this.token = 16;
            int i7 = this.f8506bp + 1;
            this.f8506bp = i7;
            this.f8507ch = charAt(i7);
        } else if (charAt2 == ']') {
            this.token = 15;
            int i8 = this.f8506bp + 1;
            this.f8506bp = i8;
            this.f8507ch = charAt(i8);
        } else if (charAt2 == '}') {
            this.token = 13;
            int i9 = this.f8506bp + 1;
            this.f8506bp = i9;
            this.f8507ch = charAt(i9);
        } else {
            if (charAt2 != 26) {
                this.f8506bp = i3;
                this.f8507ch = c4;
                this.matchStat = -1;
                return null;
            }
            this.token = 20;
        }
        this.matchStat = 4;
        return date;
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0065, code lost:
    
        if (r15 != '.') goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0067, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0069, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x006a, code lost:
    
        if (r3 >= 0) goto L38;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x006c, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x006e, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x006f, code lost:
    
        if (r6 == false) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0071, code lost:
    
        if (r15 == '\"') goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0073, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0075, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0076, code lost:
    
        r15 = r11 + 1;
        r4 = charAt(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x007c, code lost:
    
        r11 = r15;
        r15 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0082, code lost:
    
        if (r15 == ',') goto L86;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0084, code lost:
    
        if (r15 != '}') goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x008b, code lost:
    
        if (com.alibaba.fastjson.parser.JSONLexerBase.isWhitespace(r15) == false) goto L88;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x008d, code lost:
    
        r15 = r11 + 1;
        r4 = charAt(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x007c, code lost:
    
        r11 = r15;
        r15 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0094, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0096, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0097, code lost:
    
        r11 = r11 - 1;
        r14.f8506bp = r11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x009c, code lost:
    
        if (r15 != ',') goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x009e, code lost:
    
        r11 = r11 + 1;
        r14.f8506bp = r11;
        r14.f8507ch = charAt(r11);
        r14.matchStat = 3;
        r14.token = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00ac, code lost:
    
        if (r7 == false) goto L95;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x00af, code lost:
    
        return -r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:?, code lost:
    
        return r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00b0, code lost:
    
        if (r15 != '}') goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x00b2, code lost:
    
        r14.f8506bp = r11;
        r11 = r11 + 1;
        r14.f8506bp = r11;
        r15 = charAt(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x00bb, code lost:
    
        if (r15 != ',') goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x00cd, code lost:
    
        if (r15 != ']') goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x00df, code lost:
    
        if (r15 != '}') goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x00f3, code lost:
    
        if (r15 != 26) goto L72;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x0101, code lost:
    
        if (com.alibaba.fastjson.parser.JSONLexerBase.isWhitespace(r15) == false) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x0103, code lost:
    
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
        r15 = charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x010d, code lost:
    
        r14.f8506bp = r1;
        r14.f8507ch = r2;
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0113, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x00f5, code lost:
    
        r14.token = 20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x00f9, code lost:
    
        r14.matchStat = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x00e1, code lost:
    
        r14.token = 13;
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
        r14.f8507ch = charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x00cf, code lost:
    
        r14.token = 15;
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
        r14.f8507ch = charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x00bd, code lost:
    
        r14.token = 16;
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
        r14.f8507ch = charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0114, code lost:
    
        if (r7 == false) goto L96;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0117, code lost:
    
        return -r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:?, code lost:
    
        return r3;
     */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int scanFieldInt(char[] r15) {
        /*
            Method dump skipped, instructions count: 283
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanFieldInt(char[]):int");
    }

    /* JADX WARN: Code restructure failed: missing block: B:71:0x0112, code lost:
    
        r20.matchStat = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x0115, code lost:
    
        if (r11 == false) goto L95;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0118, code lost:
    
        return -r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:?, code lost:
    
        return r2;
     */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long scanFieldLong(char[] r21) {
        /*
            Method dump skipped, instructions count: 336
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanFieldLong(char[]):long");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public String scanFieldString(char[] cArr) {
        this.matchStat = 0;
        int i2 = this.f8506bp;
        char c2 = this.f8507ch;
        while (!charArrayCompare(this.text, this.f8506bp, cArr)) {
            if (!JSONLexerBase.isWhitespace(this.f8507ch)) {
                this.matchStat = -2;
                return stringDefaultValue();
            }
            next();
            while (JSONLexerBase.isWhitespace(this.f8507ch)) {
                next();
            }
        }
        int length = this.f8506bp + cArr.length;
        int i3 = length + 1;
        char charAt = charAt(length);
        int i4 = 0;
        if (charAt != '\"') {
            while (JSONLexerBase.isWhitespace(charAt)) {
                i4++;
                int i5 = i3 + 1;
                char charAt2 = charAt(i3);
                i3 = i5;
                charAt = charAt2;
            }
            if (charAt != '\"') {
                this.matchStat = -1;
                return stringDefaultValue();
            }
        }
        int indexOf = indexOf(Typography.quote, i3);
        if (indexOf == -1) {
            throw new JSONException("unclosed str");
        }
        String subString = subString(i3, indexOf - i3);
        if (subString.indexOf(92) != -1) {
            while (true) {
                int i6 = 0;
                for (int i7 = indexOf - 1; i7 >= 0 && charAt(i7) == '\\'; i7--) {
                    i6++;
                }
                if (i6 % 2 == 0) {
                    break;
                }
                indexOf = indexOf(Typography.quote, indexOf + 1);
            }
            int i8 = this.f8506bp;
            int length2 = indexOf - (((cArr.length + i8) + 1) + i4);
            subString = JSONLexerBase.readString(sub_chars(i8 + cArr.length + 1 + i4, length2), length2);
        }
        char charAt3 = charAt(indexOf + 1);
        while (charAt3 != ',' && charAt3 != '}') {
            if (!JSONLexerBase.isWhitespace(charAt3)) {
                this.matchStat = -1;
                return stringDefaultValue();
            }
            indexOf++;
            charAt3 = charAt(indexOf + 1);
        }
        int i9 = indexOf + 1;
        this.f8506bp = i9;
        this.f8507ch = charAt3;
        if (charAt3 == ',') {
            int i10 = i9 + 1;
            this.f8506bp = i10;
            this.f8507ch = charAt(i10);
            this.matchStat = 3;
            return subString;
        }
        int i11 = i9 + 1;
        this.f8506bp = i11;
        char charAt4 = charAt(i11);
        if (charAt4 == ',') {
            this.token = 16;
            int i12 = this.f8506bp + 1;
            this.f8506bp = i12;
            this.f8507ch = charAt(i12);
        } else if (charAt4 == ']') {
            this.token = 15;
            int i13 = this.f8506bp + 1;
            this.f8506bp = i13;
            this.f8507ch = charAt(i13);
        } else if (charAt4 == '}') {
            this.token = 13;
            int i14 = this.f8506bp + 1;
            this.f8506bp = i14;
            this.f8507ch = charAt(i14);
        } else {
            if (charAt4 != 26) {
                this.f8506bp = i2;
                this.f8507ch = c2;
                this.matchStat = -1;
                return stringDefaultValue();
            }
            this.token = 20;
        }
        this.matchStat = 4;
        return subString;
    }

    /* JADX WARN: Code restructure failed: missing block: B:89:0x00db, code lost:
    
        if (r9 != ']') goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x00e1, code lost:
    
        if (r3.size() != 0) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x00e3, code lost:
    
        r2 = r1 + 1;
        r1 = charAt(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x00ed, code lost:
    
        r17.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x00f0, code lost:
    
        return null;
     */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.util.Collection<java.lang.String> scanFieldStringArray(char[] r18, java.lang.Class<?> r19) {
        /*
            Method dump skipped, instructions count: 415
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanFieldStringArray(char[], java.lang.Class):java.util.Collection");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public long scanFieldSymbol(char[] cArr) {
        this.matchStat = 0;
        while (!charArrayCompare(this.text, this.f8506bp, cArr)) {
            if (!JSONLexerBase.isWhitespace(this.f8507ch)) {
                this.matchStat = -2;
                return 0L;
            }
            next();
            while (JSONLexerBase.isWhitespace(this.f8507ch)) {
                next();
            }
        }
        int length = this.f8506bp + cArr.length;
        int i2 = length + 1;
        char charAt = charAt(length);
        if (charAt != '\"') {
            while (JSONLexerBase.isWhitespace(charAt)) {
                charAt = charAt(i2);
                i2++;
            }
            if (charAt != '\"') {
                this.matchStat = -1;
                return 0L;
            }
        }
        long j2 = -3750763034362895579L;
        while (true) {
            int i3 = i2 + 1;
            char charAt2 = charAt(i2);
            if (charAt2 == '\"') {
                this.f8506bp = i3;
                char charAt3 = charAt(i3);
                this.f8507ch = charAt3;
                while (charAt3 != ',') {
                    if (charAt3 == '}') {
                        next();
                        skipWhitespace();
                        char current = getCurrent();
                        if (current == ',') {
                            this.token = 16;
                            int i4 = this.f8506bp + 1;
                            this.f8506bp = i4;
                            this.f8507ch = charAt(i4);
                        } else if (current == ']') {
                            this.token = 15;
                            int i5 = this.f8506bp + 1;
                            this.f8506bp = i5;
                            this.f8507ch = charAt(i5);
                        } else if (current == '}') {
                            this.token = 13;
                            int i6 = this.f8506bp + 1;
                            this.f8506bp = i6;
                            this.f8507ch = charAt(i6);
                        } else {
                            if (current != 26) {
                                this.matchStat = -1;
                                return 0L;
                            }
                            this.token = 20;
                        }
                        this.matchStat = 4;
                        return j2;
                    }
                    if (!JSONLexerBase.isWhitespace(charAt3)) {
                        this.matchStat = -1;
                        return 0L;
                    }
                    int i7 = this.f8506bp + 1;
                    this.f8506bp = i7;
                    charAt3 = charAt(i7);
                }
                int i8 = this.f8506bp + 1;
                this.f8506bp = i8;
                this.f8507ch = charAt(i8);
                this.matchStat = 3;
                return j2;
            }
            if (i3 > this.len) {
                this.matchStat = -1;
                return 0L;
            }
            j2 = (j2 ^ charAt2) * 1099511628211L;
            i2 = i3;
        }
    }

    public boolean scanISO8601DateIfMatch() {
        return scanISO8601DateIfMatch(true);
    }

    /* JADX WARN: Code restructure failed: missing block: B:33:0x007a, code lost:
    
        if (r2 != '.') goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x007c, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007e, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x007f, code lost:
    
        if (r5 == false) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0081, code lost:
    
        if (r2 == '\"') goto L39;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0083, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0085, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0086, code lost:
    
        r2 = charAt(r11);
        r11 = r11 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x008d, code lost:
    
        if (r3 >= 0) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x008f, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0091, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0092, code lost:
    
        if (r2 != r15) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00a9, code lost:
    
        if (com.alibaba.fastjson.parser.JSONLexerBase.isWhitespace(r2) == false) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00ab, code lost:
    
        r2 = charAt(r11);
        r11 = r11 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x00b3, code lost:
    
        r14.matchStat = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00b5, code lost:
    
        if (r6 == false) goto L91;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00b8, code lost:
    
        return -r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:?, code lost:
    
        return r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0094, code lost:
    
        r14.f8506bp = r11;
        r14.f8507ch = charAt(r11);
        r14.matchStat = 3;
        r14.token = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x00a1, code lost:
    
        if (r6 == false) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00a4, code lost:
    
        return -r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:?, code lost:
    
        return r3;
     */
    /* JADX WARN: Removed duplicated region for block: B:76:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0103  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:76:0x011c -> B:65:0x00ed). Please report as a decompilation issue!!! */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int scanInt(char r15) {
        /*
            Method dump skipped, instructions count: 297
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanInt(char):int");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public long scanLong(char c2) {
        int i2;
        char charAt;
        boolean z = false;
        this.matchStat = 0;
        int i3 = this.f8506bp;
        int i4 = i3 + 1;
        char charAt2 = charAt(i3);
        boolean z2 = charAt2 == '\"';
        if (z2) {
            int i5 = i4 + 1;
            char charAt3 = charAt(i4);
            i4 = i5;
            charAt2 = charAt3;
        }
        boolean z3 = charAt2 == '-';
        if (z3) {
            int i6 = i4 + 1;
            char charAt4 = charAt(i4);
            i4 = i6;
            charAt2 = charAt4;
        }
        char c3 = '0';
        if (charAt2 >= '0' && charAt2 <= '9') {
            long j2 = charAt2 - '0';
            while (true) {
                i2 = i4 + 1;
                charAt = charAt(i4);
                if (charAt < c3 || charAt > '9') {
                    break;
                }
                j2 = (j2 * 10) + (charAt - '0');
                i4 = i2;
                c3 = '0';
            }
            if (charAt == '.') {
                this.matchStat = -1;
                return 0L;
            }
            if (z2) {
                if (charAt != '\"') {
                    this.matchStat = -1;
                    return 0L;
                }
                charAt = charAt(i2);
                i2++;
            }
            if (j2 >= 0 || (j2 == Long.MIN_VALUE && z3)) {
                z = true;
            }
            if (!z) {
                this.matchStat = -1;
                return 0L;
            }
            while (charAt != c2) {
                if (!JSONLexerBase.isWhitespace(charAt)) {
                    this.matchStat = -1;
                    return j2;
                }
                charAt = charAt(i2);
                i2++;
            }
            this.f8506bp = i2;
            this.f8507ch = charAt(i2);
            this.matchStat = 3;
            this.token = 16;
            return z3 ? -j2 : j2;
        }
        if (charAt2 == 'n') {
            int i7 = i4 + 1;
            if (charAt(i4) == 'u') {
                int i8 = i7 + 1;
                if (charAt(i7) == 'l') {
                    int i9 = i8 + 1;
                    if (charAt(i8) == 'l') {
                        this.matchStat = 5;
                        int i10 = i9 + 1;
                        char charAt5 = charAt(i9);
                        if (z2 && charAt5 == '\"') {
                            int i11 = i10 + 1;
                            char charAt6 = charAt(i10);
                            i10 = i11;
                            charAt5 = charAt6;
                        }
                        while (charAt5 != ',') {
                            if (charAt5 == ']') {
                                this.f8506bp = i10;
                                this.f8507ch = charAt(i10);
                                this.matchStat = 5;
                                this.token = 15;
                                return 0L;
                            }
                            if (!JSONLexerBase.isWhitespace(charAt5)) {
                                this.matchStat = -1;
                                return 0L;
                            }
                            int i12 = i10 + 1;
                            char charAt7 = charAt(i10);
                            i10 = i12;
                            charAt5 = charAt7;
                        }
                        this.f8506bp = i10;
                        this.f8507ch = charAt(i10);
                        this.matchStat = 5;
                        this.token = 16;
                        return 0L;
                    }
                }
            }
        }
        this.matchStat = -1;
        return 0L;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public String scanTypeName(SymbolTable symbolTable) {
        int indexOf;
        if (!this.text.startsWith("\"@type\":\"", this.f8506bp) || (indexOf = this.text.indexOf(34, this.f8506bp + 9)) == -1) {
            return null;
        }
        int i2 = this.f8506bp + 9;
        this.f8506bp = i2;
        int i3 = 0;
        while (i2 < indexOf) {
            i3 = (i3 * 31) + this.text.charAt(i2);
            i2++;
        }
        int i4 = this.f8506bp;
        String addSymbol = addSymbol(i4, indexOf - i4, i3, symbolTable);
        char charAt = this.text.charAt(indexOf + 1);
        if (charAt != ',' && charAt != ']') {
            return null;
        }
        int i5 = indexOf + 2;
        this.f8506bp = i5;
        this.f8507ch = this.text.charAt(i5);
        return addSymbol;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public boolean seekArrayToItem(int i2) {
        if (i2 < 0) {
            throw new IllegalArgumentException(C1499a.m626l("index must > 0, but ", i2));
        }
        int i3 = this.token;
        if (i3 == 20) {
            return false;
        }
        if (i3 != 14) {
            throw new UnsupportedOperationException();
        }
        int i4 = 0;
        while (true) {
            boolean z = true;
            if (i4 >= i2) {
                nextToken();
                return true;
            }
            skipWhitespace();
            char c2 = this.f8507ch;
            if (c2 == '\"' || c2 == '\'') {
                skipString();
                char c3 = this.f8507ch;
                if (c3 != ',') {
                    if (c3 != ']') {
                        throw new JSONException("illegal json.");
                    }
                    next();
                    nextToken(16);
                    return false;
                }
                next();
            } else {
                if (c2 == '{') {
                    next();
                    this.token = 12;
                    skipObject(false);
                } else if (c2 == '[') {
                    next();
                    this.token = 14;
                    skipArray(false);
                } else {
                    int i5 = this.f8506bp + 1;
                    while (true) {
                        if (i5 >= this.text.length()) {
                            z = false;
                            break;
                        }
                        char charAt = this.text.charAt(i5);
                        if (charAt == ',') {
                            int i6 = i5 + 1;
                            this.f8506bp = i6;
                            this.f8507ch = charAt(i6);
                            break;
                        }
                        if (charAt == ']') {
                            int i7 = i5 + 1;
                            this.f8506bp = i7;
                            this.f8507ch = charAt(i7);
                            nextToken();
                            return false;
                        }
                        i5++;
                    }
                    if (!z) {
                        throw new JSONException("illegal json.");
                    }
                }
                int i8 = this.token;
                if (i8 != 16) {
                    if (i8 == 15) {
                        return false;
                    }
                    throw new UnsupportedOperationException();
                }
            }
            i4++;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x01e7, code lost:
    
        if (r17.f8507ch != 'u') goto L141;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x01e9, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x01ee, code lost:
    
        if (r17.f8507ch != 'e') goto L141;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x01f0, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x01f3, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x01f5, code lost:
    
        if (r1 == ',') goto L145;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x01f7, code lost:
    
        if (r1 == '}') goto L145;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x01f9, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x01fe, code lost:
    
        if (r17.f8507ch != ',') goto L256;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0200, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0209, code lost:
    
        if (r1 != 'n') goto L164;
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x020b, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x0210, code lost:
    
        if (r17.f8507ch != 'u') goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0212, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0217, code lost:
    
        if (r17.f8507ch != 'l') goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x0219, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x021e, code lost:
    
        if (r17.f8507ch != 'l') goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0220, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x0223, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x0225, code lost:
    
        if (r1 == ',') goto L161;
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x0227, code lost:
    
        if (r1 == '}') goto L161;
     */
    /* JADX WARN: Code restructure failed: missing block: B:125:0x0229, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x022e, code lost:
    
        if (r17.f8507ch != ',') goto L258;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x0230, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x0237, code lost:
    
        if (r1 != 'f') goto L182;
     */
    /* JADX WARN: Code restructure failed: missing block: B:133:0x0239, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x0240, code lost:
    
        if (r17.f8507ch != 'a') goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:135:0x0242, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x0247, code lost:
    
        if (r17.f8507ch != 'l') goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x0249, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:138:0x0250, code lost:
    
        if (r17.f8507ch != 's') goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x0252, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x0257, code lost:
    
        if (r17.f8507ch != 'e') goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x0259, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x025c, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:143:0x025e, code lost:
    
        if (r1 == ',') goto L179;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x0260, code lost:
    
        if (r1 == '}') goto L179;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x0262, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x0267, code lost:
    
        if (r17.f8507ch != ',') goto L260;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x0269, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x026e, code lost:
    
        if (r1 != '{') goto L195;
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x0270, code lost:
    
        r1 = r17.f8506bp + 1;
        r17.f8506bp = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x027b, code lost:
    
        if (r1 < r17.text.length()) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:154:0x027d, code lost:
    
        r1 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x0286, code lost:
    
        r17.f8507ch = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x0288, code lost:
    
        if (r20 == false) goto L191;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x028d, code lost:
    
        skipObject(false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x0292, code lost:
    
        if (r17.token != 13) goto L262;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x0294, code lost:
    
        return -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x028a, code lost:
    
        r17.token = 12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x028c, code lost:
    
        return 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x0280, code lost:
    
        r1 = r17.text.charAt(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0297, code lost:
    
        if (r1 != '[') goto L249;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x0299, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x029c, code lost:
    
        if (r20 == false) goto L201;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x02a4, code lost:
    
        skipArray(false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x02a9, code lost:
    
        if (r17.token != 13) goto L263;
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x02ab, code lost:
    
        return -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x029e, code lost:
    
        r17.token = 14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x02a3, code lost:
    
        return 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:180:0x02b1, code lost:
    
        throw new java.lang.UnsupportedOperationException();
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x02b2, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:182:0x02b5, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x02b7, code lost:
    
        if (r1 < '0') goto L268;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x02b9, code lost:
    
        if (r1 > '9') goto L269;
     */
    /* JADX WARN: Code restructure failed: missing block: B:185:0x02bb, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x02c1, code lost:
    
        if (r1 != '.') goto L218;
     */
    /* JADX WARN: Code restructure failed: missing block: B:189:0x02c3, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x02c6, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:191:0x02c8, code lost:
    
        if (r1 < '0') goto L270;
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x02ca, code lost:
    
        if (r1 > '9') goto L271;
     */
    /* JADX WARN: Code restructure failed: missing block: B:193:0x02cc, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:196:0x02d0, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x02d4, code lost:
    
        if (r1 == 'E') goto L221;
     */
    /* JADX WARN: Code restructure failed: missing block: B:198:0x02d6, code lost:
    
        if (r1 != 'e') goto L229;
     */
    /* JADX WARN: Code restructure failed: missing block: B:200:0x02f0, code lost:
    
        if (r17.f8507ch == ',') goto L232;
     */
    /* JADX WARN: Code restructure failed: missing block: B:201:0x02f2, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:203:0x02f7, code lost:
    
        if (r17.f8507ch != ',') goto L264;
     */
    /* JADX WARN: Code restructure failed: missing block: B:204:0x02f9, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:207:0x02d8, code lost:
    
        next();
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:208:0x02dd, code lost:
    
        if (r1 == '-') goto L224;
     */
    /* JADX WARN: Code restructure failed: missing block: B:209:0x02df, code lost:
    
        if (r1 != '+') goto L274;
     */
    /* JADX WARN: Code restructure failed: missing block: B:211:0x02e4, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:212:0x02e6, code lost:
    
        if (r1 < '0') goto L272;
     */
    /* JADX WARN: Code restructure failed: missing block: B:213:0x02e8, code lost:
    
        if (r1 > '9') goto L273;
     */
    /* JADX WARN: Code restructure failed: missing block: B:214:0x02ea, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:217:0x02e1, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:219:0x0169, code lost:
    
        r1 = r17.text.charAt(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:221:0x0303, code lost:
    
        r2 = p005b.p131d.p132a.p133a.C1499a.m586H("illegal json, ");
        r2.append(info());
     */
    /* JADX WARN: Code restructure failed: missing block: B:222:0x0319, code lost:
    
        throw new com.alibaba.fastjson.JSONException(r2.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:225:0x00c1, code lost:
    
        if (r17.f8507ch == ':') goto L50;
     */
    /* JADX WARN: Code restructure failed: missing block: B:226:0x00c3, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x00c8, code lost:
    
        if (r17.f8507ch != ':') goto L275;
     */
    /* JADX WARN: Code restructure failed: missing block: B:229:0x00ca, code lost:
    
        r2 = r17.f8506bp + 1;
        r17.f8506bp = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:230:0x00d5, code lost:
    
        if (r2 < r17.text.length()) goto L55;
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x00d7, code lost:
    
        r2 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x00e0, code lost:
    
        r17.f8507ch = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x00e2, code lost:
    
        if (r2 != ',') goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:234:0x00e4, code lost:
    
        r1 = r17.f8506bp + 1;
        r17.f8506bp = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:235:0x00ef, code lost:
    
        if (r1 < r17.text.length()) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:236:0x00f1, code lost:
    
        r1 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:237:0x00fa, code lost:
    
        r17.f8507ch = r1;
        r17.token = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:238:?, code lost:
    
        return 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:239:0x00f4, code lost:
    
        r1 = r17.text.charAt(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:241:0x0101, code lost:
    
        if (r2 != ']') goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:242:0x0103, code lost:
    
        r1 = r17.f8506bp + 1;
        r17.f8506bp = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:243:0x010e, code lost:
    
        if (r1 < r17.text.length()) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:244:0x0110, code lost:
    
        r1 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:245:0x0119, code lost:
    
        r17.f8507ch = r1;
        r17.token = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:246:?, code lost:
    
        return 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:247:0x0113, code lost:
    
        r1 = r17.text.charAt(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:248:0x011e, code lost:
    
        if (r2 != '}') goto L76;
     */
    /* JADX WARN: Code restructure failed: missing block: B:249:0x0120, code lost:
    
        r1 = r17.f8506bp + 1;
        r17.f8506bp = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:250:0x012b, code lost:
    
        if (r1 < r17.text.length()) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:251:0x012d, code lost:
    
        r1 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:252:0x0136, code lost:
    
        r17.f8507ch = r1;
        r17.token = 13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:253:?, code lost:
    
        return 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:254:0x0130, code lost:
    
        r1 = r17.text.charAt(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:255:0x013b, code lost:
    
        if (r2 < '0') goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:256:0x013d, code lost:
    
        if (r2 > '9') goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:257:0x013f, code lost:
    
        r17.f8509sp = 0;
        r17.pos = r17.f8506bp;
        scanNumber();
     */
    /* JADX WARN: Code restructure failed: missing block: B:258:?, code lost:
    
        return 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:259:0x0149, code lost:
    
        nextToken(2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:260:0x014c, code lost:
    
        return 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:261:0x00da, code lost:
    
        r2 = r17.text.charAt(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:262:?, code lost:
    
        return 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x00bd, code lost:
    
        if (r8 != r18) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0150, code lost:
    
        if (r17.f8507ch == ':') goto L85;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0152, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0157, code lost:
    
        if (r17.f8507ch != ':') goto L245;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0159, code lost:
    
        r1 = r17.f8506bp + 1;
        r17.f8506bp = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0164, code lost:
    
        if (r1 < r17.text.length()) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0166, code lost:
    
        r1 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x016f, code lost:
    
        r17.f8507ch = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0179, code lost:
    
        if (r1 == '\"') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x017d, code lost:
    
        if (r1 == '\'') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x017f, code lost:
    
        if (r1 == '{') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0181, code lost:
    
        if (r1 == '[') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0183, code lost:
    
        if (r1 == '0') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0187, code lost:
    
        if (r1 == '1') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x018b, code lost:
    
        if (r1 == '2') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x018f, code lost:
    
        if (r1 == '3') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0193, code lost:
    
        if (r1 == '4') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0197, code lost:
    
        if (r1 == '5') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x019b, code lost:
    
        if (r1 == '6') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x019f, code lost:
    
        if (r1 == '7') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x01a3, code lost:
    
        if (r1 == '8') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x01a5, code lost:
    
        if (r1 == '9') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x01a7, code lost:
    
        if (r1 == '+') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x01a9, code lost:
    
        if (r1 == '-') goto L118;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x01ab, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x01ae, code lost:
    
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x01b2, code lost:
    
        if (r1 == '-') goto L206;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x01b4, code lost:
    
        if (r1 == '+') goto L206;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x01b6, code lost:
    
        if (r1 < '0') goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01b8, code lost:
    
        if (r1 > '9') goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x01bc, code lost:
    
        if (r1 != '\"') goto L132;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x01be, code lost:
    
        skipString();
        r1 = r17.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01c3, code lost:
    
        if (r1 == ',') goto L129;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x01c5, code lost:
    
        if (r1 == '}') goto L129;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x01c7, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x01cc, code lost:
    
        if (r17.f8507ch != ',') goto L254;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x01ce, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x01d7, code lost:
    
        if (r1 != 't') goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x01d9, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x01e0, code lost:
    
        if (r17.f8507ch != 'r') goto L141;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x01e2, code lost:
    
        next();
     */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int seekObjectToField(long r18, boolean r20) {
        /*
            Method dump skipped, instructions count: 805
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.seekObjectToField(long, boolean):int");
    }

    public void setTime(char c2, char c3, char c4, char c5, char c6, char c7) {
        this.calendar.set(11, (c3 - '0') + ((c2 - '0') * 10));
        this.calendar.set(12, (c5 - '0') + ((c4 - '0') * 10));
        this.calendar.set(13, (c7 - '0') + ((c6 - '0') * 10));
    }

    public void setTimeZone(char c2, char c3, char c4) {
        setTimeZone(c2, c3, c4, '0', '0');
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void skipArray() {
        skipArray(false);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void skipObject() {
        skipObject(false);
    }

    public final void skipString() {
        if (this.f8507ch != '\"') {
            throw new UnsupportedOperationException();
        }
        int i2 = this.f8506bp;
        while (true) {
            i2++;
            if (i2 >= this.text.length()) {
                throw new JSONException("unclosed str");
            }
            char charAt = this.text.charAt(i2);
            if (charAt == '\\') {
                if (i2 < this.len - 1) {
                    i2++;
                }
            } else if (charAt == '\"') {
                String str = this.text;
                int i3 = i2 + 1;
                this.f8506bp = i3;
                this.f8507ch = str.charAt(i3);
                return;
            }
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final String stringVal() {
        return !this.hasSpecial ? subString(this.f8508np + 1, this.f8509sp) : new String(this.sbuf, 0, this.f8509sp);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final String subString(int i2, int i3) {
        if (!ASMUtils.IS_ANDROID) {
            return this.text.substring(i2, i3 + i2);
        }
        char[] cArr = this.sbuf;
        if (i3 < cArr.length) {
            this.text.getChars(i2, i2 + i3, cArr, 0);
            return new String(this.sbuf, 0, i3);
        }
        char[] cArr2 = new char[i3];
        this.text.getChars(i2, i3 + i2, cArr2, 0);
        return new String(cArr2);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final char[] sub_chars(int i2, int i3) {
        if (ASMUtils.IS_ANDROID) {
            char[] cArr = this.sbuf;
            if (i3 < cArr.length) {
                this.text.getChars(i2, i3 + i2, cArr, 0);
                return this.sbuf;
            }
        }
        char[] cArr2 = new char[i3];
        this.text.getChars(i2, i3 + i2, cArr2, 0);
        return cArr2;
    }

    public JSONScanner(String str, int i2) {
        super(i2);
        this.text = str;
        this.len = str.length();
        this.f8506bp = -1;
        next();
        if (this.f8507ch == 65279) {
            next();
        }
    }

    public boolean scanISO8601DateIfMatch(boolean z) {
        return scanISO8601DateIfMatch(z, this.len - this.f8506bp);
    }

    public void setTimeZone(char c2, char c3, char c4, char c5, char c6) {
        int i2 = (((c6 - '0') + ((c5 - '0') * 10)) * 60 * 1000) + (((c4 - '0') + ((c3 - '0') * 10)) * 3600 * 1000);
        if (c2 == '-') {
            i2 = -i2;
        }
        if (this.calendar.getTimeZone().getRawOffset() != i2) {
            this.calendar.setTimeZone(new SimpleTimeZone(i2, Integer.toString(i2)));
        }
    }

    public final void skipArray(boolean z) {
        int i2 = this.f8506bp;
        boolean z2 = false;
        int i3 = 0;
        while (i2 < this.text.length()) {
            char charAt = this.text.charAt(i2);
            if (charAt == '\\') {
                if (i2 >= this.len - 1) {
                    this.f8507ch = charAt;
                    this.f8506bp = i2;
                    StringBuilder m586H = C1499a.m586H("illegal str, ");
                    m586H.append(info());
                    throw new JSONException(m586H.toString());
                }
                i2++;
            } else if (charAt == '\"') {
                z2 = !z2;
            } else if (charAt != '[') {
                char c2 = JSONLexer.EOI;
                if (charAt == '{' && z) {
                    int i4 = this.f8506bp + 1;
                    this.f8506bp = i4;
                    if (i4 < this.text.length()) {
                        c2 = this.text.charAt(i4);
                    }
                    this.f8507ch = c2;
                    skipObject(z);
                } else if (charAt == ']' && !z2 && i3 - 1 == -1) {
                    int i5 = i2 + 1;
                    this.f8506bp = i5;
                    if (i5 == this.text.length()) {
                        this.f8507ch = JSONLexer.EOI;
                        this.token = 20;
                        return;
                    } else {
                        this.f8507ch = this.text.charAt(this.f8506bp);
                        nextToken(16);
                        return;
                    }
                }
            } else if (!z2) {
                i3++;
            }
            i2++;
        }
        if (i2 != this.text.length()) {
            return;
        }
        StringBuilder m586H2 = C1499a.m586H("illegal str, ");
        m586H2.append(info());
        throw new JSONException(m586H2.toString());
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void skipObject(boolean z) {
        int i2 = this.f8506bp;
        boolean z2 = false;
        int i3 = 0;
        while (i2 < this.text.length()) {
            char charAt = this.text.charAt(i2);
            if (charAt == '\\') {
                if (i2 >= this.len - 1) {
                    this.f8507ch = charAt;
                    this.f8506bp = i2;
                    StringBuilder m586H = C1499a.m586H("illegal str, ");
                    m586H.append(info());
                    throw new JSONException(m586H.toString());
                }
                i2++;
            } else if (charAt == '\"') {
                z2 = !z2;
            } else if (charAt == '{') {
                if (!z2) {
                    i3++;
                }
            } else if (charAt == '}' && !z2 && i3 - 1 == -1) {
                int i4 = i2 + 1;
                this.f8506bp = i4;
                int length = this.text.length();
                char c2 = JSONLexer.EOI;
                if (i4 == length) {
                    this.f8507ch = JSONLexer.EOI;
                    this.token = 20;
                    return;
                }
                char charAt2 = this.text.charAt(this.f8506bp);
                this.f8507ch = charAt2;
                if (charAt2 == ',') {
                    this.token = 16;
                    int i5 = this.f8506bp + 1;
                    this.f8506bp = i5;
                    if (i5 < this.text.length()) {
                        c2 = this.text.charAt(i5);
                    }
                    this.f8507ch = c2;
                    return;
                }
                if (charAt2 == '}') {
                    this.token = 13;
                    next();
                    return;
                } else if (charAt2 != ']') {
                    nextToken(16);
                    return;
                } else {
                    this.token = 15;
                    next();
                    return;
                }
            }
            i2++;
        }
        for (int i6 = 0; i6 < this.f8506bp; i6++) {
            if (i6 < this.text.length() && this.text.charAt(i6) == ' ') {
                i2++;
            }
        }
        if (i2 != this.text.length()) {
            return;
        }
        StringBuilder m586H2 = C1499a.m586H("illegal str, ");
        m586H2.append(info());
        throw new JSONException(m586H2.toString());
    }

    /* JADX WARN: Removed duplicated region for block: B:68:0x01e0 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01e2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean scanISO8601DateIfMatch(boolean r27, int r28) {
        /*
            Method dump skipped, instructions count: 1718
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.scanISO8601DateIfMatch(boolean, int):boolean");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final boolean charArrayCompare(char[] cArr) {
        return charArrayCompare(this.text, this.f8506bp, cArr);
    }

    public JSONScanner(char[] cArr, int i2) {
        this(cArr, i2, JSON.DEFAULT_PARSER_FEATURE);
    }

    public JSONScanner(char[] cArr, int i2, int i3) {
        this(new String(cArr, 0, i2), i3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public String[] scanFieldStringArray(char[] cArr, int i2, SymbolTable symbolTable) {
        int i3;
        char c2;
        int i4 = this.f8506bp;
        char c3 = this.f8507ch;
        while (JSONLexerBase.isWhitespace(this.f8507ch)) {
            next();
        }
        if (cArr != null) {
            this.matchStat = 0;
            if (!charArrayCompare(cArr)) {
                this.matchStat = -2;
                return null;
            }
            int length = this.f8506bp + cArr.length;
            int i5 = length + 1;
            char charAt = this.text.charAt(length);
            while (JSONLexerBase.isWhitespace(charAt)) {
                charAt = this.text.charAt(i5);
                i5++;
            }
            if (charAt == ':') {
                i3 = i5 + 1;
                c2 = this.text.charAt(i5);
                while (JSONLexerBase.isWhitespace(c2)) {
                    c2 = this.text.charAt(i3);
                    i3++;
                }
            } else {
                this.matchStat = -1;
                return null;
            }
        } else {
            i3 = this.f8506bp + 1;
            c2 = this.f8507ch;
        }
        if (c2 == '[') {
            this.f8506bp = i3;
            this.f8507ch = this.text.charAt(i3);
            String[] strArr = i2 >= 0 ? new String[i2] : new String[4];
            int i6 = 0;
            while (true) {
                if (JSONLexerBase.isWhitespace(this.f8507ch)) {
                    next();
                } else {
                    if (this.f8507ch != '\"') {
                        this.f8506bp = i4;
                        this.f8507ch = c3;
                        this.matchStat = -1;
                        return null;
                    }
                    String scanSymbol = scanSymbol(symbolTable, Typography.quote);
                    if (i6 == strArr.length) {
                        String[] strArr2 = new String[strArr.length + (strArr.length >> 1) + 1];
                        System.arraycopy(strArr, 0, strArr2, 0, strArr.length);
                        strArr = strArr2;
                    }
                    int i7 = i6 + 1;
                    strArr[i6] = scanSymbol;
                    while (JSONLexerBase.isWhitespace(this.f8507ch)) {
                        next();
                    }
                    if (this.f8507ch == ',') {
                        next();
                        i6 = i7;
                    } else {
                        if (strArr.length != i7) {
                            String[] strArr3 = new String[i7];
                            System.arraycopy(strArr, 0, strArr3, 0, i7);
                            strArr = strArr3;
                        }
                        while (JSONLexerBase.isWhitespace(this.f8507ch)) {
                            next();
                        }
                        if (this.f8507ch == ']') {
                            next();
                            return strArr;
                        }
                        this.f8506bp = i4;
                        this.f8507ch = c3;
                        this.matchStat = -1;
                        return null;
                    }
                }
            }
        } else {
            if (c2 == 'n' && this.text.startsWith("ull", this.f8506bp + 1)) {
                int i8 = this.f8506bp + 4;
                this.f8506bp = i8;
                this.f8507ch = this.text.charAt(i8);
                return null;
            }
            this.matchStat = -1;
            return null;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x0219, code lost:
    
        r0 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x021d, code lost:
    
        if (r0 == 'E') goto L159;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x0221, code lost:
    
        if (r0 != 'e') goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x023b, code lost:
    
        if (r14.f8507ch == ',') goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x023d, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x0242, code lost:
    
        if (r14.f8507ch != ',') goto L196;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0244, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0223, code lost:
    
        next();
        r0 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x0228, code lost:
    
        if (r0 == '-') goto L162;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x022a, code lost:
    
        if (r0 != '+') goto L213;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x022f, code lost:
    
        r0 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x0231, code lost:
    
        if (r0 < '0') goto L211;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x0233, code lost:
    
        if (r0 > '9') goto L212;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0235, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x022c, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x01b6, code lost:
    
        if (r3 != '\"') goto L184;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x01cd, code lost:
    
        if (r3 != '{') goto L192;
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x01eb, code lost:
    
        if (r3 != '[') goto L194;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x01ed, code lost:
    
        next();
        skipArray(false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x01fa, code lost:
    
        throw new java.lang.UnsupportedOperationException();
     */
    /* JADX WARN: Code restructure failed: missing block: B:138:0x01cf, code lost:
    
        r2 = r14.f8506bp + 1;
        r14.f8506bp = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x01db, code lost:
    
        if (r2 < r14.text.length()) goto L137;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x01de, code lost:
    
        r4 = r14.text.charAt(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x01e4, code lost:
    
        r14.f8507ch = r4;
        skipObject(false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x01b8, code lost:
    
        skipString();
        r0 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x01bd, code lost:
    
        if (r0 == ',') goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x01bf, code lost:
    
        if (r0 == '}') goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x01c1, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x01c6, code lost:
    
        if (r14.f8507ch != ',') goto L200;
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x01c8, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x0166, code lost:
    
        r3 = r14.text.charAt(r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x0249, code lost:
    
        r0 = p005b.p131d.p132a.p133a.C1499a.m586H("illegal json, ");
        r0.append(info());
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x025f, code lost:
    
        throw new com.alibaba.fastjson.JSONException(r0.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x00b8, code lost:
    
        if (r14.f8507ch == ':') goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x00ba, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x00bf, code lost:
    
        if (r14.f8507ch != ':') goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x00c1, code lost:
    
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x00cd, code lost:
    
        if (r15 < r14.text.length()) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x00cf, code lost:
    
        r15 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x00d8, code lost:
    
        r14.f8507ch = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x00da, code lost:
    
        if (r15 != ',') goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x00dc, code lost:
    
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x00e8, code lost:
    
        if (r15 < r14.text.length()) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x00eb, code lost:
    
        r4 = r14.text.charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x00f1, code lost:
    
        r14.f8507ch = r4;
        r14.token = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x00f8, code lost:
    
        if (r15 != ']') goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x00fa, code lost:
    
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:179:0x0106, code lost:
    
        if (r15 < r14.text.length()) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:180:0x0109, code lost:
    
        r4 = r14.text.charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x010f, code lost:
    
        r14.f8507ch = r4;
        r14.token = 15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:182:0x0116, code lost:
    
        if (r15 != '}') goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x0118, code lost:
    
        r15 = r14.f8506bp + 1;
        r14.f8506bp = r15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x0124, code lost:
    
        if (r15 < r14.text.length()) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:185:0x0127, code lost:
    
        r4 = r14.text.charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x012d, code lost:
    
        r14.f8507ch = r4;
        r14.token = 13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:187:0x0134, code lost:
    
        if (r15 < '0') goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x0136, code lost:
    
        if (r15 > '9') goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:189:0x0138, code lost:
    
        r14.f8509sp = 0;
        r14.pos = r14.f8506bp;
        scanNumber();
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x0142, code lost:
    
        nextToken(2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:191:0x00d2, code lost:
    
        r15 = r14.text.charAt(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x0146, code lost:
    
        r14.matchStat = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:193:0x0149, code lost:
    
        return r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:195:0x00ab, code lost:
    
        r8 = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x009c, code lost:
    
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x009f, code lost:
    
        if (r8 >= r15.length) goto L206;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00a5, code lost:
    
        if (r6 != r15[r8]) goto L44;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00a8, code lost:
    
        r8 = r8 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x00b4, code lost:
    
        if (r8 == (-1)) goto L83;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x014c, code lost:
    
        if (r14.f8507ch == ':') goto L86;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x014e, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0153, code lost:
    
        if (r14.f8507ch != ':') goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0155, code lost:
    
        r3 = r14.f8506bp + 1;
        r14.f8506bp = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0161, code lost:
    
        if (r3 < r14.text.length()) goto L91;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x0163, code lost:
    
        r3 = com.alibaba.fastjson.parser.JSONLexer.EOI;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x016c, code lost:
    
        r14.f8507ch = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0176, code lost:
    
        if (r3 == '\"') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x017a, code lost:
    
        if (r3 == '\'') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x017c, code lost:
    
        if (r3 == '{') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x017e, code lost:
    
        if (r3 == '[') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0180, code lost:
    
        if (r3 == '0') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0184, code lost:
    
        if (r3 == '1') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x0188, code lost:
    
        if (r3 == '2') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x018c, code lost:
    
        if (r3 == '3') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0190, code lost:
    
        if (r3 == '4') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0194, code lost:
    
        if (r3 == '5') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0198, code lost:
    
        if (r3 == '6') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x019c, code lost:
    
        if (r3 == '7') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x01a0, code lost:
    
        if (r3 == '8') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x01a2, code lost:
    
        if (r3 == '9') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x01a4, code lost:
    
        if (r3 == '+') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x01a6, code lost:
    
        if (r3 == '-') goto L119;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x01a8, code lost:
    
        skipWhitespace();
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x01ab, code lost:
    
        r3 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x01ad, code lost:
    
        if (r3 == '-') goto L179;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x01af, code lost:
    
        if (r3 == '+') goto L180;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x01b1, code lost:
    
        if (r3 < '0') goto L189;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01b3, code lost:
    
        if (r3 > '9') goto L190;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x01fb, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01fe, code lost:
    
        r0 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0200, code lost:
    
        if (r0 < '0') goto L207;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0202, code lost:
    
        if (r0 > '9') goto L208;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0204, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x020a, code lost:
    
        if (r0 != '.') goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x020c, code lost:
    
        next();
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x020f, code lost:
    
        r0 = r14.f8507ch;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0211, code lost:
    
        if (r0 < '0') goto L209;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x0213, code lost:
    
        if (r0 > '9') goto L210;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0215, code lost:
    
        next();
     */
    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int seekObjectToField(long[] r15) {
        /*
            Method dump skipped, instructions count: 614
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.parser.JSONScanner.seekObjectToField(long[]):int");
    }
}
