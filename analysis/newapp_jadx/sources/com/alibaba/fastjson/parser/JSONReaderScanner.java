package com.alibaba.fastjson.parser;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.util.IOUtils;
import java.io.CharArrayReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigDecimal;

/* loaded from: classes.dex */
public final class JSONReaderScanner extends JSONLexerBase {
    private static final ThreadLocal<char[]> BUF_LOCAL = new ThreadLocal<>();
    private char[] buf;
    private int bufLength;
    private Reader reader;

    public JSONReaderScanner(String str) {
        this(str, JSON.DEFAULT_PARSER_FEATURE);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final String addSymbol(int i2, int i3, int i4, SymbolTable symbolTable) {
        return symbolTable.addSymbol(this.buf, i2, i3, i4);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void arrayCopy(int i2, char[] cArr, int i3, int i4) {
        System.arraycopy(this.buf, i2, cArr, i3, i4);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public byte[] bytesValue() {
        if (this.token != 26) {
            return IOUtils.decodeBase64(this.buf, this.f8508np + 1, this.f8509sp);
        }
        throw new JSONException("TODO");
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final boolean charArrayCompare(char[] cArr) {
        for (int i2 = 0; i2 < cArr.length; i2++) {
            if (charAt(this.f8506bp + i2) != cArr[i2]) {
                return false;
            }
        }
        return true;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final char charAt(int i2) {
        int i3 = this.bufLength;
        if (i2 >= i3) {
            if (i3 == -1) {
                return i2 < this.f8509sp ? this.buf[i2] : JSONLexer.EOI;
            }
            int i4 = this.f8506bp;
            if (i4 == 0) {
                char[] cArr = this.buf;
                int length = (cArr.length * 3) / 2;
                char[] cArr2 = new char[length];
                System.arraycopy(cArr, i4, cArr2, 0, i3);
                int i5 = this.bufLength;
                try {
                    this.bufLength += this.reader.read(cArr2, i5, length - i5);
                    this.buf = cArr2;
                } catch (IOException e2) {
                    throw new JSONException(e2.getMessage(), e2);
                }
            } else {
                int i6 = i3 - i4;
                if (i6 > 0) {
                    char[] cArr3 = this.buf;
                    System.arraycopy(cArr3, i4, cArr3, 0, i6);
                }
                try {
                    Reader reader = this.reader;
                    char[] cArr4 = this.buf;
                    int read = reader.read(cArr4, i6, cArr4.length - i6);
                    this.bufLength = read;
                    if (read == 0) {
                        throw new JSONException("illegal state, textLength is zero");
                    }
                    if (read == -1) {
                        return JSONLexer.EOI;
                    }
                    this.bufLength = read + i6;
                    int i7 = this.f8506bp;
                    i2 -= i7;
                    this.f8508np -= i7;
                    this.f8506bp = 0;
                } catch (IOException e3) {
                    throw new JSONException(e3.getMessage(), e3);
                }
            }
        }
        return this.buf[i2];
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        super.close();
        char[] cArr = this.buf;
        if (cArr.length <= 65536) {
            BUF_LOCAL.set(cArr);
        }
        this.buf = null;
        IOUtils.close(this.reader);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final void copyTo(int i2, int i3, char[] cArr) {
        System.arraycopy(this.buf, i2, cArr, 0, i3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final BigDecimal decimalValue() {
        int i2 = this.f8508np;
        if (i2 == -1) {
            i2 = 0;
        }
        char charAt = charAt((this.f8509sp + i2) - 1);
        int i3 = this.f8509sp;
        if (charAt == 'L' || charAt == 'S' || charAt == 'B' || charAt == 'F' || charAt == 'D') {
            i3--;
        }
        return new BigDecimal(this.buf, i2, i3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final int indexOf(char c2, int i2) {
        int i3 = i2 - this.f8506bp;
        while (true) {
            char charAt = charAt(this.f8506bp + i3);
            if (c2 == charAt) {
                return i3 + this.f8506bp;
            }
            if (charAt == 26) {
                return -1;
            }
            i3++;
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final boolean isBlankInput() {
        int i2 = 0;
        while (true) {
            char c2 = this.buf[i2];
            if (c2 == 26) {
                this.token = 20;
                return true;
            }
            if (!JSONLexerBase.isWhitespace(c2)) {
                return false;
            }
            i2++;
        }
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public boolean isEOF() {
        if (this.bufLength == -1) {
            return true;
        }
        int i2 = this.f8506bp;
        char[] cArr = this.buf;
        if (i2 != cArr.length) {
            return this.f8507ch == 26 && i2 + 1 >= cArr.length;
        }
        return true;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final char next() {
        int i2 = this.f8506bp + 1;
        this.f8506bp = i2;
        int i3 = this.bufLength;
        if (i2 >= i3) {
            if (i3 == -1) {
                return JSONLexer.EOI;
            }
            int i4 = this.f8509sp;
            if (i4 > 0) {
                int i5 = i3 - i4;
                if (this.f8507ch == '\"' && i5 > 0) {
                    i5--;
                }
                char[] cArr = this.buf;
                System.arraycopy(cArr, i5, cArr, 0, i4);
            }
            this.f8508np = -1;
            int i6 = this.f8509sp;
            this.f8506bp = i6;
            try {
                char[] cArr2 = this.buf;
                int length = cArr2.length - i6;
                if (length == 0) {
                    char[] cArr3 = new char[cArr2.length * 2];
                    System.arraycopy(cArr2, 0, cArr3, 0, cArr2.length);
                    this.buf = cArr3;
                    length = cArr3.length - i6;
                }
                int read = this.reader.read(this.buf, this.f8506bp, length);
                this.bufLength = read;
                if (read == 0) {
                    throw new JSONException("illegal stat, textLength is zero");
                }
                if (read == -1) {
                    this.f8507ch = JSONLexer.EOI;
                    return JSONLexer.EOI;
                }
                this.bufLength = read + this.f8506bp;
                i2 = i6;
            } catch (IOException e2) {
                throw new JSONException(e2.getMessage(), e2);
            }
        }
        char c2 = this.buf[i2];
        this.f8507ch = c2;
        return c2;
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final String numberString() {
        int i2 = this.f8508np;
        if (i2 == -1) {
            i2 = 0;
        }
        char charAt = charAt((this.f8509sp + i2) - 1);
        int i3 = this.f8509sp;
        if (charAt == 'L' || charAt == 'S' || charAt == 'B' || charAt == 'F' || charAt == 'D') {
            i3--;
        }
        return new String(this.buf, i2, i3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase, com.alibaba.fastjson.parser.JSONLexer
    public final String stringVal() {
        if (this.hasSpecial) {
            return new String(this.sbuf, 0, this.f8509sp);
        }
        int i2 = this.f8508np + 1;
        if (i2 < 0) {
            throw new IllegalStateException();
        }
        if (i2 <= this.buf.length - this.f8509sp) {
            return new String(this.buf, i2, this.f8509sp);
        }
        throw new IllegalStateException();
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final String subString(int i2, int i3) {
        if (i3 >= 0) {
            return new String(this.buf, i2, i3);
        }
        throw new StringIndexOutOfBoundsException(i3);
    }

    @Override // com.alibaba.fastjson.parser.JSONLexerBase
    public final char[] sub_chars(int i2, int i3) {
        if (i3 < 0) {
            throw new StringIndexOutOfBoundsException(i3);
        }
        if (i2 == 0) {
            return this.buf;
        }
        char[] cArr = new char[i3];
        System.arraycopy(this.buf, i2, cArr, 0, i3);
        return cArr;
    }

    public JSONReaderScanner(String str, int i2) {
        this(new StringReader(str), i2);
    }

    public JSONReaderScanner(char[] cArr, int i2) {
        this(cArr, i2, JSON.DEFAULT_PARSER_FEATURE);
    }

    public JSONReaderScanner(Reader reader) {
        this(reader, JSON.DEFAULT_PARSER_FEATURE);
    }

    public JSONReaderScanner(Reader reader, int i2) {
        super(i2);
        this.reader = reader;
        ThreadLocal<char[]> threadLocal = BUF_LOCAL;
        char[] cArr = threadLocal.get();
        this.buf = cArr;
        if (cArr != null) {
            threadLocal.set(null);
        }
        if (this.buf == null) {
            this.buf = new char[16384];
        }
        try {
            this.bufLength = reader.read(this.buf);
            this.f8506bp = -1;
            next();
            if (this.f8507ch == 65279) {
                next();
            }
        } catch (IOException e2) {
            throw new JSONException(e2.getMessage(), e2);
        }
    }

    public JSONReaderScanner(char[] cArr, int i2, int i3) {
        this(new CharArrayReader(cArr, 0, i2), i3);
    }
}
