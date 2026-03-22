package com.alibaba.fastjson;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;

/* loaded from: classes.dex */
public abstract class JSONValidator implements Cloneable {

    /* renamed from: ch */
    public char f8501ch;
    public boolean eof;
    public Type type;
    public int pos = -1;
    public int count = 0;
    public boolean supportMultiValue = true;

    public static class ReaderValidator extends JSONValidator {
        private static final ThreadLocal<char[]> bufLocal = new ThreadLocal<>();
        private char[] buf;

        /* renamed from: r */
        public final Reader f8502r;
        private int end = -1;
        private int readCount = 0;

        public ReaderValidator(Reader reader) {
            this.f8502r = reader;
            ThreadLocal<char[]> threadLocal = bufLocal;
            char[] cArr = threadLocal.get();
            this.buf = cArr;
            if (cArr != null) {
                threadLocal.set(null);
            } else {
                this.buf = new char[8192];
            }
            next();
            skipWhiteSpace();
        }

        @Override // com.alibaba.fastjson.JSONValidator
        public void close() {
            bufLocal.set(this.buf);
            this.f8502r.close();
        }

        @Override // com.alibaba.fastjson.JSONValidator
        public void next() {
            int i2 = this.pos;
            if (i2 < this.end) {
                char[] cArr = this.buf;
                int i3 = i2 + 1;
                this.pos = i3;
                this.f8501ch = cArr[i3];
                return;
            }
            if (this.eof) {
                return;
            }
            try {
                Reader reader = this.f8502r;
                char[] cArr2 = this.buf;
                int read = reader.read(cArr2, 0, cArr2.length);
                this.readCount++;
                if (read > 0) {
                    this.f8501ch = this.buf[0];
                    this.pos = 0;
                    this.end = read - 1;
                } else {
                    if (read == -1) {
                        this.pos = 0;
                        this.end = 0;
                        this.buf = null;
                        this.f8501ch = (char) 0;
                        this.eof = true;
                        return;
                    }
                    this.pos = 0;
                    this.end = 0;
                    this.buf = null;
                    this.f8501ch = (char) 0;
                    this.eof = true;
                    throw new JSONException("read error");
                }
            } catch (IOException unused) {
                throw new JSONException("read error");
            }
        }
    }

    public enum Type {
        Object,
        Array,
        Value
    }

    public static class UTF16Validator extends JSONValidator {
        private final String str;

        public UTF16Validator(String str) {
            this.str = str;
            next();
            skipWhiteSpace();
        }

        @Override // com.alibaba.fastjson.JSONValidator
        public void next() {
            int i2 = this.pos + 1;
            this.pos = i2;
            if (i2 < this.str.length()) {
                this.f8501ch = this.str.charAt(this.pos);
            } else {
                this.f8501ch = (char) 0;
                this.eof = true;
            }
        }
    }

    public static class UTF8InputStreamValidator extends JSONValidator {
        private static final ThreadLocal<byte[]> bufLocal = new ThreadLocal<>();
        private byte[] buf;

        /* renamed from: is */
        private final InputStream f8503is;
        private int end = -1;
        private int readCount = 0;

        public UTF8InputStreamValidator(InputStream inputStream) {
            this.f8503is = inputStream;
            ThreadLocal<byte[]> threadLocal = bufLocal;
            byte[] bArr = threadLocal.get();
            this.buf = bArr;
            if (bArr != null) {
                threadLocal.set(null);
            } else {
                this.buf = new byte[8192];
            }
            next();
            skipWhiteSpace();
        }

        @Override // com.alibaba.fastjson.JSONValidator
        public void close() {
            bufLocal.set(this.buf);
            this.f8503is.close();
        }

        @Override // com.alibaba.fastjson.JSONValidator
        public void next() {
            int i2 = this.pos;
            if (i2 < this.end) {
                byte[] bArr = this.buf;
                int i3 = i2 + 1;
                this.pos = i3;
                this.f8501ch = (char) bArr[i3];
                return;
            }
            if (this.eof) {
                return;
            }
            try {
                InputStream inputStream = this.f8503is;
                byte[] bArr2 = this.buf;
                int read = inputStream.read(bArr2, 0, bArr2.length);
                this.readCount++;
                if (read > 0) {
                    this.f8501ch = (char) this.buf[0];
                    this.pos = 0;
                    this.end = read - 1;
                } else {
                    if (read == -1) {
                        this.pos = 0;
                        this.end = 0;
                        this.buf = null;
                        this.f8501ch = (char) 0;
                        this.eof = true;
                        return;
                    }
                    this.pos = 0;
                    this.end = 0;
                    this.buf = null;
                    this.f8501ch = (char) 0;
                    this.eof = true;
                    throw new JSONException("read error");
                }
            } catch (IOException unused) {
                throw new JSONException("read error");
            }
        }
    }

    public static class UTF8Validator extends JSONValidator {
        private final byte[] bytes;

        public UTF8Validator(byte[] bArr) {
            this.bytes = bArr;
            next();
            skipWhiteSpace();
        }

        @Override // com.alibaba.fastjson.JSONValidator
        public void next() {
            int i2 = this.pos + 1;
            this.pos = i2;
            byte[] bArr = this.bytes;
            if (i2 < bArr.length) {
                this.f8501ch = (char) bArr[i2];
            } else {
                this.f8501ch = (char) 0;
                this.eof = true;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:167:0x016a, code lost:
    
        if (r0 <= '9') goto L178;
     */
    /* JADX WARN: Removed duplicated region for block: B:132:0x017a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean any() {
        /*
            Method dump skipped, instructions count: 518
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.JSONValidator.any():boolean");
    }

    public static JSONValidator from(String str) {
        return new UTF16Validator(str);
    }

    public static JSONValidator fromUtf8(byte[] bArr) {
        return new UTF8Validator(bArr);
    }

    public static final boolean isWhiteSpace(char c2) {
        return c2 == ' ' || c2 == '\t' || c2 == '\r' || c2 == '\n' || c2 == '\f' || c2 == '\b';
    }

    public void close() {
    }

    public void fieldName() {
        next();
        while (true) {
            char c2 = this.f8501ch;
            if (c2 == '\\') {
                next();
                if (this.f8501ch == 'u') {
                    next();
                    next();
                    next();
                    next();
                    next();
                } else {
                    next();
                }
            } else {
                if (c2 == '\"') {
                    next();
                    return;
                }
                next();
            }
        }
    }

    public Type getType() {
        return this.type;
    }

    public abstract void next();

    public void skipWhiteSpace() {
        while (isWhiteSpace(this.f8501ch)) {
            next();
        }
    }

    public boolean validate() {
        while (any()) {
            this.count++;
            if (this.supportMultiValue && !this.eof) {
                skipWhiteSpace();
                if (this.eof) {
                }
            }
            return true;
        }
        return false;
    }

    public static JSONValidator from(Reader reader) {
        return new ReaderValidator(reader);
    }

    public static JSONValidator fromUtf8(InputStream inputStream) {
        return new UTF8InputStreamValidator(inputStream);
    }
}
