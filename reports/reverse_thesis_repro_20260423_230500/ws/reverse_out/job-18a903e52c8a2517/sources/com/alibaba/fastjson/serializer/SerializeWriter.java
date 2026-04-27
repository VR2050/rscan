package com.alibaba.fastjson.serializer;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.util.Base64;
import com.alibaba.fastjson.util.IOUtils;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.ref.SoftReference;
import java.nio.charset.Charset;
import kotlin.UByte;
import kotlin.text.Typography;

/* JADX INFO: loaded from: classes.dex */
public final class SerializeWriter extends Writer {
    private static final ThreadLocal<SoftReference<char[]>> bufLocal = new ThreadLocal<>();
    protected char[] buf;
    protected int count;
    private int features;
    private final Writer writer;

    public SerializeWriter() {
        this((Writer) null);
    }

    public SerializeWriter(Writer writer) {
        this.writer = writer;
        this.features = JSON.DEFAULT_GENERATE_FEATURE;
        SoftReference<char[]> ref = bufLocal.get();
        if (ref != null) {
            this.buf = ref.get();
            bufLocal.set(null);
        }
        if (this.buf == null) {
            this.buf = new char[1024];
        }
    }

    public SerializeWriter(SerializerFeature... features) {
        this((Writer) null, features);
    }

    public SerializeWriter(Writer writer, SerializerFeature... features) {
        this.writer = writer;
        SoftReference<char[]> ref = bufLocal.get();
        if (ref != null) {
            this.buf = ref.get();
            bufLocal.set(null);
        }
        if (this.buf == null) {
            this.buf = new char[1024];
        }
        int featuresValue = 0;
        for (SerializerFeature feature : features) {
            featuresValue |= feature.getMask();
        }
        this.features = featuresValue;
    }

    public int getBufferLength() {
        return this.buf.length;
    }

    public SerializeWriter(int initialSize) {
        this((Writer) null, initialSize);
    }

    public SerializeWriter(Writer writer, int initialSize) {
        this.writer = writer;
        if (initialSize <= 0) {
            throw new IllegalArgumentException("Negative initial size: " + initialSize);
        }
        this.buf = new char[initialSize];
    }

    public void config(SerializerFeature feature, boolean state) {
        if (state) {
            this.features |= feature.getMask();
        } else {
            this.features &= ~feature.getMask();
        }
    }

    public boolean isEnabled(SerializerFeature feature) {
        return SerializerFeature.isEnabled(this.features, feature);
    }

    @Override // java.io.Writer
    public void write(int c) {
        int newcount = this.count + 1;
        if (newcount > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(newcount);
            } else {
                flush();
                newcount = 1;
            }
        }
        this.buf[this.count] = (char) c;
        this.count = newcount;
    }

    public void write(char c) {
        int newcount = this.count + 1;
        if (newcount > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(newcount);
            } else {
                flush();
                newcount = 1;
            }
        }
        this.buf[this.count] = c;
        this.count = newcount;
    }

    @Override // java.io.Writer
    public void write(char[] c, int off, int len) {
        if (off < 0 || off > c.length || len < 0 || off + len > c.length || off + len < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (len == 0) {
            return;
        }
        int newcount = this.count + len;
        if (newcount > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(newcount);
            } else {
                do {
                    char[] cArr = this.buf;
                    int length = cArr.length;
                    int i = this.count;
                    int rest = length - i;
                    System.arraycopy(c, off, cArr, i, rest);
                    this.count = this.buf.length;
                    flush();
                    len -= rest;
                    off += rest;
                } while (len > this.buf.length);
                newcount = len;
            }
        }
        System.arraycopy(c, off, this.buf, this.count, len);
        this.count = newcount;
    }

    public void expandCapacity(int minimumCapacity) {
        int newCapacity = ((this.buf.length * 3) / 2) + 1;
        if (newCapacity < minimumCapacity) {
            newCapacity = minimumCapacity;
        }
        char[] newValue = new char[newCapacity];
        System.arraycopy(this.buf, 0, newValue, 0, this.count);
        this.buf = newValue;
    }

    @Override // java.io.Writer
    public void write(String str, int off, int len) {
        int newcount = this.count + len;
        if (newcount > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(newcount);
            } else {
                do {
                    char[] cArr = this.buf;
                    int length = cArr.length;
                    int i = this.count;
                    int rest = length - i;
                    str.getChars(off, off + rest, cArr, i);
                    this.count = this.buf.length;
                    flush();
                    len -= rest;
                    off += rest;
                } while (len > this.buf.length);
                newcount = len;
            }
        }
        str.getChars(off, off + len, this.buf, this.count);
        this.count = newcount;
    }

    public void writeTo(Writer out) throws IOException {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        out.write(this.buf, 0, this.count);
    }

    public void writeTo(OutputStream out, String charsetName) throws IOException {
        writeTo(out, Charset.forName(charsetName));
    }

    public void writeTo(OutputStream out, Charset charset) throws IOException {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        byte[] bytes = new String(this.buf, 0, this.count).getBytes(charset.name());
        out.write(bytes);
    }

    @Override // java.io.Writer, java.lang.Appendable
    public SerializeWriter append(CharSequence csq) {
        String s = csq == null ? "null" : csq.toString();
        write(s, 0, s.length());
        return this;
    }

    @Override // java.io.Writer, java.lang.Appendable
    public SerializeWriter append(CharSequence csq, int start, int end) {
        String s = (csq == null ? "null" : csq).subSequence(start, end).toString();
        write(s, 0, s.length());
        return this;
    }

    @Override // java.io.Writer, java.lang.Appendable
    public SerializeWriter append(char c) {
        write(c);
        return this;
    }

    public void reset() {
        this.count = 0;
    }

    public char[] toCharArray() {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        int i = this.count;
        char[] newValue = new char[i];
        System.arraycopy(this.buf, 0, newValue, 0, i);
        return newValue;
    }

    public byte[] toBytes(String charsetName) {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        if (charsetName == null) {
            charsetName = "UTF-8";
        }
        try {
            return new String(this.buf, 0, this.count).getBytes(charsetName);
        } catch (UnsupportedEncodingException e) {
            throw new JSONException("toBytes error", e);
        }
    }

    public int size() {
        return this.count;
    }

    public String toString() {
        return new String(this.buf, 0, this.count);
    }

    @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.writer != null && this.count > 0) {
            flush();
        }
        if (this.buf.length <= 8192) {
            bufLocal.set(new SoftReference<>(this.buf));
        }
        this.buf = null;
    }

    @Override // java.io.Writer
    public void write(String text) {
        if (text == null) {
            writeNull();
        } else {
            write(text, 0, text.length());
        }
    }

    public void writeInt(int i) {
        if (i == Integer.MIN_VALUE) {
            write("-2147483648");
            return;
        }
        int size = i < 0 ? IOUtils.stringSize(-i) + 1 : IOUtils.stringSize(i);
        int newcount = this.count + size;
        if (newcount > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(newcount);
            } else {
                char[] chars = new char[size];
                IOUtils.getChars(i, size, chars);
                write(chars, 0, chars.length);
                return;
            }
        }
        IOUtils.getChars(i, newcount, this.buf);
        this.count = newcount;
    }

    public void writeByteArray(byte[] bytes) {
        int bytesLen = bytes.length;
        boolean singleQuote = isEnabled(SerializerFeature.UseSingleQuotes);
        char quote = singleQuote ? '\'' : Typography.quote;
        if (bytesLen == 0) {
            String emptyString = singleQuote ? "''" : "\"\"";
            write(emptyString);
            return;
        }
        char[] CA = Base64.CA;
        int eLen = (bytesLen / 3) * 3;
        int charsLen = (((bytesLen - 1) / 3) + 1) << 2;
        int offset = this.count;
        int newcount = this.count + charsLen + 2;
        if (newcount > this.buf.length) {
            if (this.writer != null) {
                write(quote);
                int i = 0;
                while (i < eLen) {
                    int s = i + 1;
                    int s2 = s + 1;
                    int i2 = ((bytes[i] & 255) << 16) | ((bytes[s] & 255) << 8) | (bytes[s2] & 255);
                    write(CA[(i2 >>> 18) & 63]);
                    write(CA[(i2 >>> 12) & 63]);
                    write(CA[(i2 >>> 6) & 63]);
                    write(CA[i2 & 63]);
                    i = s2 + 1;
                }
                int left = bytesLen - eLen;
                if (left > 0) {
                    int i3 = (left == 2 ? (bytes[bytesLen - 1] & UByte.MAX_VALUE) << 2 : 0) | ((bytes[eLen] & UByte.MAX_VALUE) << 10);
                    write(CA[i3 >> 12]);
                    write(CA[(i3 >>> 6) & 63]);
                    write(left == 2 ? CA[i3 & 63] : '=');
                    write('=');
                }
                write(quote);
                return;
            }
            expandCapacity(newcount);
        }
        this.count = newcount;
        int offset2 = offset + 1;
        this.buf[offset] = quote;
        int i4 = 0;
        int d = offset2;
        while (i4 < eLen) {
            int s3 = i4 + 1;
            int s4 = s3 + 1;
            int i5 = ((bytes[i4] & 255) << 16) | ((bytes[s3] & 255) << 8);
            int s5 = s4 + 1;
            int i6 = i5 | (bytes[s4] & UByte.MAX_VALUE);
            char[] cArr = this.buf;
            int d2 = d + 1;
            cArr[d] = CA[(i6 >>> 18) & 63];
            int d3 = d2 + 1;
            cArr[d2] = CA[(i6 >>> 12) & 63];
            int d4 = d3 + 1;
            cArr[d3] = CA[(i6 >>> 6) & 63];
            d = d4 + 1;
            cArr[d4] = CA[i6 & 63];
            i4 = s5;
        }
        int left2 = bytesLen - eLen;
        if (left2 > 0) {
            int i7 = ((bytes[eLen] & UByte.MAX_VALUE) << 10) | (left2 == 2 ? (bytes[bytesLen - 1] & UByte.MAX_VALUE) << 2 : 0);
            char[] cArr2 = this.buf;
            cArr2[newcount - 5] = CA[i7 >> 12];
            cArr2[newcount - 4] = CA[(i7 >>> 6) & 63];
            cArr2[newcount - 3] = left2 == 2 ? CA[i7 & 63] : '=';
            this.buf[newcount - 2] = '=';
        }
        this.buf[newcount - 1] = quote;
    }

    public void writeLongAndChar(long i, char c) throws IOException {
        if (i == Long.MIN_VALUE) {
            write("-9223372036854775808");
            write(c);
            return;
        }
        int size = i < 0 ? IOUtils.stringSize(-i) + 1 : IOUtils.stringSize(i);
        int newcount0 = this.count + size;
        int newcount1 = newcount0 + 1;
        if (newcount1 > this.buf.length) {
            if (this.writer != null) {
                writeLong(i);
                write(c);
                return;
            }
            expandCapacity(newcount1);
        }
        IOUtils.getChars(i, newcount0, this.buf);
        this.buf[newcount0] = c;
        this.count = newcount1;
    }

    public void writeLong(long i) {
        if (i == Long.MIN_VALUE) {
            write("-9223372036854775808");
            return;
        }
        int size = i < 0 ? IOUtils.stringSize(-i) + 1 : IOUtils.stringSize(i);
        int newcount = this.count + size;
        if (newcount > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(newcount);
            } else {
                char[] chars = new char[size];
                IOUtils.getChars(i, size, chars);
                write(chars, 0, chars.length);
                return;
            }
        }
        IOUtils.getChars(i, newcount, this.buf);
        this.count = newcount;
    }

    public void writeNull() {
        write("null");
    }

    private void writeStringWithDoubleQuote(String text, char seperator) {
        writeStringWithDoubleQuote(text, seperator, true);
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00eb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void writeStringWithDoubleQuote(java.lang.String r27, char r28, boolean r29) {
        /*
            Method dump skipped, instruction units count: 1175
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.serializer.SerializeWriter.writeStringWithDoubleQuote(java.lang.String, char, boolean):void");
    }

    public void write(boolean value) {
        if (value) {
            write("true");
        } else {
            write("false");
        }
    }

    public void writeFieldValue(char seperator, String name, long value) {
        if (value == Long.MIN_VALUE || !isEnabled(SerializerFeature.QuoteFieldNames)) {
            writeFieldValue1(seperator, name, value);
            return;
        }
        char keySeperator = isEnabled(SerializerFeature.UseSingleQuotes) ? '\'' : Typography.quote;
        int intSize = value < 0 ? IOUtils.stringSize(-value) + 1 : IOUtils.stringSize(value);
        int nameLen = name.length();
        int newcount = this.count + nameLen + 4 + intSize;
        if (newcount > this.buf.length) {
            if (this.writer != null) {
                write(seperator);
                writeFieldName(name);
                writeLong(value);
                return;
            }
            expandCapacity(newcount);
        }
        int start = this.count;
        this.count = newcount;
        char[] cArr = this.buf;
        cArr[start] = seperator;
        int nameEnd = start + nameLen + 1;
        cArr[start + 1] = keySeperator;
        name.getChars(0, nameLen, cArr, start + 2);
        char[] cArr2 = this.buf;
        cArr2[nameEnd + 1] = keySeperator;
        cArr2[nameEnd + 2] = ':';
        IOUtils.getChars(value, this.count, cArr2);
    }

    public void writeFieldValue1(char seperator, String name, long value) {
        write(seperator);
        writeFieldName(name);
        writeLong(value);
    }

    public void writeFieldValue(char seperator, String name, String value) {
        if (isEnabled(SerializerFeature.QuoteFieldNames)) {
            if (isEnabled(SerializerFeature.UseSingleQuotes)) {
                write(seperator);
                writeFieldName(name);
                if (value == null) {
                    writeNull();
                    return;
                } else {
                    writeString(value);
                    return;
                }
            }
            if (isEnabled(SerializerFeature.BrowserCompatible)) {
                write(seperator);
                writeStringWithDoubleQuote(name, ':');
                writeStringWithDoubleQuote(value, (char) 0);
                return;
            }
            writeFieldValueStringWithDoubleQuote(seperator, name, value, true);
            return;
        }
        write(seperator);
        writeFieldName(name);
        if (value == null) {
            writeNull();
        } else {
            writeString(value);
        }
    }

    private void writeFieldValueStringWithDoubleQuote(char seperator, String name, String value, boolean checkSpecial) {
        int valueLen;
        int newcount;
        int newcount2;
        int nameLen = name.length();
        int newcount3 = this.count;
        if (value == null) {
            valueLen = 4;
            newcount = newcount3 + nameLen + 8;
        } else {
            valueLen = value.length();
            newcount = newcount3 + nameLen + valueLen + 6;
        }
        if (newcount > this.buf.length) {
            if (this.writer != null) {
                write(seperator);
                writeStringWithDoubleQuote(name, ':', checkSpecial);
                writeStringWithDoubleQuote(value, (char) 0, checkSpecial);
                return;
            }
            expandCapacity(newcount);
        }
        char[] cArr = this.buf;
        int i = this.count;
        cArr[i] = seperator;
        int nameStart = i + 2;
        int nameEnd = nameStart + nameLen;
        cArr[i + 1] = Typography.quote;
        name.getChars(0, nameLen, cArr, nameStart);
        this.count = newcount;
        char[] cArr2 = this.buf;
        cArr2[nameEnd] = Typography.quote;
        int index = nameEnd + 1;
        int index2 = index + 1;
        cArr2[index] = ':';
        if (value == null) {
            int index3 = index2 + 1;
            cArr2[index2] = 'n';
            int index4 = index3 + 1;
            cArr2[index3] = 'u';
            int index5 = index4 + 1;
            cArr2[index4] = 'l';
            int i2 = index5 + 1;
            cArr2[index5] = 'l';
            return;
        }
        int index6 = index2 + 1;
        cArr2[index2] = Typography.quote;
        int valueEnd = index6 + valueLen;
        value.getChars(0, valueLen, cArr2, index6);
        if (checkSpecial && !isEnabled(SerializerFeature.DisableCheckSpecialChar)) {
            int specialCount = 0;
            int lastSpecialIndex = -1;
            int firstSpecialIndex = -1;
            char lastSpecial = 0;
            for (int i3 = index6; i3 < valueEnd; i3++) {
                char ch = this.buf[i3];
                if (ch == 8232) {
                    specialCount++;
                    int lastSpecialIndex2 = i3;
                    newcount += 4;
                    if (firstSpecialIndex != -1) {
                        lastSpecial = ch;
                        lastSpecialIndex = lastSpecialIndex2;
                    } else {
                        firstSpecialIndex = i3;
                        lastSpecial = ch;
                        lastSpecialIndex = lastSpecialIndex2;
                    }
                } else if (ch >= ']') {
                    if (ch >= 127 && ch <= 160) {
                        if (firstSpecialIndex == -1) {
                            firstSpecialIndex = i3;
                        }
                        specialCount++;
                        int lastSpecialIndex3 = i3;
                        newcount += 4;
                        lastSpecial = ch;
                        lastSpecialIndex = lastSpecialIndex3;
                    }
                } else {
                    int lastSpecialIndex4 = this.features;
                    if (isSpecial(ch, lastSpecialIndex4)) {
                        specialCount++;
                        int lastSpecialIndex5 = i3;
                        if (ch < IOUtils.specicalFlags_doubleQuotes.length && IOUtils.specicalFlags_doubleQuotes[ch] == 4) {
                            newcount += 4;
                        }
                        if (firstSpecialIndex != -1) {
                            lastSpecial = ch;
                            lastSpecialIndex = lastSpecialIndex5;
                        } else {
                            firstSpecialIndex = i3;
                            lastSpecial = ch;
                            lastSpecialIndex = lastSpecialIndex5;
                        }
                    }
                }
            }
            if (specialCount > 0) {
                int newcount4 = newcount + specialCount;
                if (newcount4 > this.buf.length) {
                    expandCapacity(newcount4);
                }
                this.count = newcount4;
                if (specialCount == 1) {
                    char lastSpecial2 = lastSpecial;
                    if (lastSpecial2 == 8232) {
                        int srcPos = lastSpecialIndex + 1;
                        int destPos = lastSpecialIndex + 6;
                        newcount2 = newcount4;
                        char[] cArr3 = this.buf;
                        System.arraycopy(cArr3, srcPos, cArr3, destPos, (valueEnd - lastSpecialIndex) - 1);
                        char[] cArr4 = this.buf;
                        cArr4[lastSpecialIndex] = '\\';
                        int lastSpecialIndex6 = lastSpecialIndex + 1;
                        cArr4[lastSpecialIndex6] = 'u';
                        int lastSpecialIndex7 = lastSpecialIndex6 + 1;
                        cArr4[lastSpecialIndex7] = '2';
                        int lastSpecialIndex8 = lastSpecialIndex7 + 1;
                        cArr4[lastSpecialIndex8] = '0';
                        int lastSpecialIndex9 = lastSpecialIndex8 + 1;
                        cArr4[lastSpecialIndex9] = '2';
                        cArr4[lastSpecialIndex9 + 1] = '8';
                    } else {
                        newcount2 = newcount4;
                        if (lastSpecial2 < IOUtils.specicalFlags_doubleQuotes.length && IOUtils.specicalFlags_doubleQuotes[lastSpecial2] == 4) {
                            int srcPos2 = lastSpecialIndex + 1;
                            int destPos2 = lastSpecialIndex + 6;
                            int LengthOfCopy = (valueEnd - lastSpecialIndex) - 1;
                            char[] cArr5 = this.buf;
                            System.arraycopy(cArr5, srcPos2, cArr5, destPos2, LengthOfCopy);
                            int bufIndex = lastSpecialIndex;
                            char[] cArr6 = this.buf;
                            int bufIndex2 = bufIndex + 1;
                            cArr6[bufIndex] = '\\';
                            int bufIndex3 = bufIndex2 + 1;
                            cArr6[bufIndex2] = 'u';
                            int bufIndex4 = bufIndex3 + 1;
                            cArr6[bufIndex3] = IOUtils.DIGITS[(lastSpecial2 >>> '\f') & 15];
                            int bufIndex5 = bufIndex4 + 1;
                            this.buf[bufIndex4] = IOUtils.DIGITS[(lastSpecial2 >>> '\b') & 15];
                            int bufIndex6 = bufIndex5 + 1;
                            this.buf[bufIndex5] = IOUtils.DIGITS[(lastSpecial2 >>> 4) & 15];
                            int i4 = bufIndex6 + 1;
                            this.buf[bufIndex6] = IOUtils.DIGITS[lastSpecial2 & 15];
                        } else {
                            int srcPos3 = lastSpecialIndex + 1;
                            int destPos3 = lastSpecialIndex + 2;
                            int LengthOfCopy2 = (valueEnd - lastSpecialIndex) - 1;
                            char[] cArr7 = this.buf;
                            System.arraycopy(cArr7, srcPos3, cArr7, destPos3, LengthOfCopy2);
                            char[] cArr8 = this.buf;
                            cArr8[lastSpecialIndex] = '\\';
                            cArr8[lastSpecialIndex + 1] = IOUtils.replaceChars[lastSpecial2];
                        }
                    }
                } else {
                    newcount2 = newcount4;
                    if (specialCount > 1) {
                        int textIndex = firstSpecialIndex - index6;
                        int bufIndex7 = firstSpecialIndex;
                        for (int i5 = textIndex; i5 < value.length(); i5++) {
                            char ch2 = value.charAt(i5);
                            if ((ch2 < IOUtils.specicalFlags_doubleQuotes.length && IOUtils.specicalFlags_doubleQuotes[ch2] != 0) || (ch2 == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                                int bufIndex8 = bufIndex7 + 1;
                                this.buf[bufIndex7] = '\\';
                                if (IOUtils.specicalFlags_doubleQuotes[ch2] == 4) {
                                    char[] cArr9 = this.buf;
                                    int bufIndex9 = bufIndex8 + 1;
                                    cArr9[bufIndex8] = 'u';
                                    int bufIndex10 = bufIndex9 + 1;
                                    cArr9[bufIndex9] = IOUtils.DIGITS[(ch2 >>> '\f') & 15];
                                    int bufIndex11 = bufIndex10 + 1;
                                    this.buf[bufIndex10] = IOUtils.DIGITS[(ch2 >>> '\b') & 15];
                                    int bufIndex12 = bufIndex11 + 1;
                                    this.buf[bufIndex11] = IOUtils.DIGITS[(ch2 >>> 4) & 15];
                                    this.buf[bufIndex12] = IOUtils.DIGITS[ch2 & 15];
                                    valueEnd += 5;
                                    bufIndex7 = bufIndex12 + 1;
                                } else {
                                    this.buf[bufIndex8] = IOUtils.replaceChars[ch2];
                                    valueEnd++;
                                    bufIndex7 = bufIndex8 + 1;
                                }
                            } else if (ch2 != 8232) {
                                this.buf[bufIndex7] = ch2;
                                bufIndex7++;
                            } else {
                                char[] cArr10 = this.buf;
                                int bufIndex13 = bufIndex7 + 1;
                                cArr10[bufIndex7] = '\\';
                                int bufIndex14 = bufIndex13 + 1;
                                cArr10[bufIndex13] = 'u';
                                int bufIndex15 = bufIndex14 + 1;
                                cArr10[bufIndex14] = IOUtils.DIGITS[(ch2 >>> '\f') & 15];
                                int bufIndex16 = bufIndex15 + 1;
                                this.buf[bufIndex15] = IOUtils.DIGITS[(ch2 >>> '\b') & 15];
                                int bufIndex17 = bufIndex16 + 1;
                                this.buf[bufIndex16] = IOUtils.DIGITS[(ch2 >>> 4) & 15];
                                this.buf[bufIndex17] = IOUtils.DIGITS[ch2 & 15];
                                valueEnd += 5;
                                bufIndex7 = bufIndex17 + 1;
                            }
                        }
                    }
                }
            }
        }
        this.buf[this.count - 1] = Typography.quote;
    }

    static final boolean isSpecial(char ch, int features) {
        if (ch == ' ') {
            return false;
        }
        if (ch == '/' && SerializerFeature.isEnabled(features, SerializerFeature.WriteSlashAsSpecial)) {
            return true;
        }
        if (ch <= '#' || ch == '\\') {
            return ch <= 31 || ch == '\\' || ch == '\"';
        }
        return false;
    }

    public void writeString(String text) {
        if (isEnabled(SerializerFeature.UseSingleQuotes)) {
            writeStringWithSingleQuote(text);
        } else {
            writeStringWithDoubleQuote(text, (char) 0);
        }
    }

    private void writeStringWithSingleQuote(String text) {
        if (text == null) {
            int newcount = this.count + 4;
            if (newcount > this.buf.length) {
                expandCapacity(newcount);
            }
            "null".getChars(0, 4, this.buf, this.count);
            this.count = newcount;
            return;
        }
        int len = text.length();
        int newcount2 = this.count + len + 2;
        char c = '\r';
        char c2 = '\\';
        if (newcount2 > this.buf.length) {
            if (this.writer != null) {
                write('\'');
                for (int i = 0; i < text.length(); i++) {
                    char ch = text.charAt(i);
                    if (ch <= '\r' || ch == '\\' || ch == '\'' || (ch == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                        write('\\');
                        write(IOUtils.replaceChars[ch]);
                    } else {
                        write(ch);
                    }
                }
                write('\'');
                return;
            }
            expandCapacity(newcount2);
        }
        int i2 = this.count;
        int start = i2 + 1;
        int end = start + len;
        char[] cArr = this.buf;
        cArr[i2] = '\'';
        text.getChars(0, len, cArr, start);
        this.count = newcount2;
        int specialCount = 0;
        int lastSpecialIndex = -1;
        char lastSpecial = 0;
        for (int i3 = start; i3 < end; i3++) {
            char ch2 = this.buf[i3];
            if (ch2 <= '\r' || ch2 == '\\' || ch2 == '\'' || (ch2 == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                specialCount++;
                lastSpecialIndex = i3;
                lastSpecial = ch2;
            }
        }
        int newcount3 = newcount2 + specialCount;
        if (newcount3 > this.buf.length) {
            expandCapacity(newcount3);
        }
        this.count = newcount3;
        if (specialCount == 1) {
            char[] cArr2 = this.buf;
            System.arraycopy(cArr2, lastSpecialIndex + 1, cArr2, lastSpecialIndex + 2, (end - lastSpecialIndex) - 1);
            char[] cArr3 = this.buf;
            cArr3[lastSpecialIndex] = '\\';
            cArr3[lastSpecialIndex + 1] = IOUtils.replaceChars[lastSpecial];
        } else if (specialCount > 1) {
            char[] cArr4 = this.buf;
            System.arraycopy(cArr4, lastSpecialIndex + 1, cArr4, lastSpecialIndex + 2, (end - lastSpecialIndex) - 1);
            char[] cArr5 = this.buf;
            cArr5[lastSpecialIndex] = '\\';
            int lastSpecialIndex2 = lastSpecialIndex + 1;
            cArr5[lastSpecialIndex2] = IOUtils.replaceChars[lastSpecial];
            int end2 = end + 1;
            int i4 = lastSpecialIndex2 - 2;
            while (i4 >= start) {
                char ch3 = this.buf[i4];
                if (ch3 > c && ch3 != c2 && ch3 != '\'') {
                    if (ch3 != '/' || !isEnabled(SerializerFeature.WriteSlashAsSpecial)) {
                    }
                    i4--;
                    c = '\r';
                }
                char[] cArr6 = this.buf;
                System.arraycopy(cArr6, i4 + 1, cArr6, i4 + 2, (end2 - i4) - 1);
                char[] cArr7 = this.buf;
                c2 = '\\';
                cArr7[i4] = '\\';
                cArr7[i4 + 1] = IOUtils.replaceChars[ch3];
                end2++;
                i4--;
                c = '\r';
            }
        }
        this.buf[this.count - 1] = '\'';
    }

    public void writeFieldName(String key) {
        writeFieldName(key, false);
    }

    public void writeFieldName(String key, boolean checkSpecial) {
        if (key == null) {
            write("null:");
            return;
        }
        if (isEnabled(SerializerFeature.UseSingleQuotes)) {
            if (isEnabled(SerializerFeature.QuoteFieldNames)) {
                writeStringWithSingleQuote(key);
                write(':');
                return;
            } else {
                writeKeyWithSingleQuoteIfHasSpecial(key);
                return;
            }
        }
        if (isEnabled(SerializerFeature.QuoteFieldNames)) {
            writeStringWithDoubleQuote(key, ':', checkSpecial);
        } else {
            writeKeyWithDoubleQuoteIfHasSpecial(key);
        }
    }

    private void writeKeyWithDoubleQuoteIfHasSpecial(String text) {
        byte[] specicalFlags_doubleQuotes = IOUtils.specicalFlags_doubleQuotes;
        int len = text.length();
        int newcount = this.count + len + 1;
        if (newcount > this.buf.length) {
            if (this.writer != null) {
                if (len == 0) {
                    write(Typography.quote);
                    write(Typography.quote);
                    write(':');
                    return;
                }
                boolean hasSpecial = false;
                int i = 0;
                while (true) {
                    if (i >= len) {
                        break;
                    }
                    char ch = text.charAt(i);
                    if (ch >= specicalFlags_doubleQuotes.length || specicalFlags_doubleQuotes[ch] == 0) {
                        i++;
                    } else {
                        hasSpecial = true;
                        break;
                    }
                }
                if (hasSpecial) {
                    write(Typography.quote);
                }
                for (int i2 = 0; i2 < len; i2++) {
                    char ch2 = text.charAt(i2);
                    if (ch2 < specicalFlags_doubleQuotes.length && specicalFlags_doubleQuotes[ch2] != 0) {
                        write('\\');
                        write(IOUtils.replaceChars[ch2]);
                    } else {
                        write(ch2);
                    }
                }
                if (hasSpecial) {
                    write(Typography.quote);
                }
                write(':');
                return;
            }
            expandCapacity(newcount);
        }
        if (len == 0) {
            int i3 = this.count;
            if (i3 + 3 > this.buf.length) {
                expandCapacity(i3 + 3);
            }
            char[] cArr = this.buf;
            int i4 = this.count;
            int i5 = i4 + 1;
            this.count = i5;
            cArr[i4] = Typography.quote;
            int i6 = i5 + 1;
            this.count = i6;
            cArr[i5] = Typography.quote;
            this.count = i6 + 1;
            cArr[i6] = ':';
            return;
        }
        int newCount = this.count;
        int end = newCount + len;
        text.getChars(0, len, this.buf, newCount);
        this.count = newcount;
        boolean hasSpecial2 = false;
        int i7 = newCount;
        while (i7 < end) {
            char[] cArr2 = this.buf;
            char ch3 = cArr2[i7];
            if (ch3 < specicalFlags_doubleQuotes.length && specicalFlags_doubleQuotes[ch3] != 0) {
                if (!hasSpecial2) {
                    newcount += 3;
                    if (newcount > cArr2.length) {
                        expandCapacity(newcount);
                    }
                    this.count = newcount;
                    char[] cArr3 = this.buf;
                    System.arraycopy(cArr3, i7 + 1, cArr3, i7 + 3, (end - i7) - 1);
                    char[] cArr4 = this.buf;
                    System.arraycopy(cArr4, 0, cArr4, 1, i7);
                    char[] cArr5 = this.buf;
                    cArr5[newCount] = Typography.quote;
                    int i8 = i7 + 1;
                    cArr5[i8] = '\\';
                    i7 = i8 + 1;
                    cArr5[i7] = IOUtils.replaceChars[ch3];
                    end += 2;
                    this.buf[this.count - 2] = Typography.quote;
                    hasSpecial2 = true;
                } else {
                    newcount++;
                    if (newcount > cArr2.length) {
                        expandCapacity(newcount);
                    }
                    this.count = newcount;
                    char[] cArr6 = this.buf;
                    System.arraycopy(cArr6, i7 + 1, cArr6, i7 + 2, end - i7);
                    char[] cArr7 = this.buf;
                    cArr7[i7] = '\\';
                    i7++;
                    cArr7[i7] = IOUtils.replaceChars[ch3];
                    end++;
                }
            }
            i7++;
        }
        this.buf[this.count - 1] = ':';
    }

    private void writeKeyWithSingleQuoteIfHasSpecial(String text) {
        byte[] specicalFlags_singleQuotes = IOUtils.specicalFlags_singleQuotes;
        int len = text.length();
        int newcount = this.count + len + 1;
        if (newcount > this.buf.length) {
            if (this.writer != null) {
                if (len == 0) {
                    write('\'');
                    write('\'');
                    write(':');
                    return;
                }
                boolean hasSpecial = false;
                int i = 0;
                while (true) {
                    if (i >= len) {
                        break;
                    }
                    char ch = text.charAt(i);
                    if (ch >= specicalFlags_singleQuotes.length || specicalFlags_singleQuotes[ch] == 0) {
                        i++;
                    } else {
                        hasSpecial = true;
                        break;
                    }
                }
                if (hasSpecial) {
                    write('\'');
                }
                for (int i2 = 0; i2 < len; i2++) {
                    char ch2 = text.charAt(i2);
                    if (ch2 < specicalFlags_singleQuotes.length && specicalFlags_singleQuotes[ch2] != 0) {
                        write('\\');
                        write(IOUtils.replaceChars[ch2]);
                    } else {
                        write(ch2);
                    }
                }
                if (hasSpecial) {
                    write('\'');
                }
                write(':');
                return;
            }
            expandCapacity(newcount);
        }
        if (len == 0) {
            int i3 = this.count;
            if (i3 + 3 > this.buf.length) {
                expandCapacity(i3 + 3);
            }
            char[] cArr = this.buf;
            int i4 = this.count;
            int i5 = i4 + 1;
            this.count = i5;
            cArr[i4] = '\'';
            int i6 = i5 + 1;
            this.count = i6;
            cArr[i5] = '\'';
            this.count = i6 + 1;
            cArr[i6] = ':';
            return;
        }
        int newCount = this.count;
        int end = newCount + len;
        text.getChars(0, len, this.buf, newCount);
        this.count = newcount;
        boolean hasSpecial2 = false;
        int i7 = newCount;
        while (i7 < end) {
            char[] cArr2 = this.buf;
            char ch3 = cArr2[i7];
            if (ch3 < specicalFlags_singleQuotes.length && specicalFlags_singleQuotes[ch3] != 0) {
                if (!hasSpecial2) {
                    newcount += 3;
                    if (newcount > cArr2.length) {
                        expandCapacity(newcount);
                    }
                    this.count = newcount;
                    char[] cArr3 = this.buf;
                    System.arraycopy(cArr3, i7 + 1, cArr3, i7 + 3, (end - i7) - 1);
                    char[] cArr4 = this.buf;
                    System.arraycopy(cArr4, 0, cArr4, 1, i7);
                    char[] cArr5 = this.buf;
                    cArr5[newCount] = '\'';
                    int i8 = i7 + 1;
                    cArr5[i8] = '\\';
                    i7 = i8 + 1;
                    cArr5[i7] = IOUtils.replaceChars[ch3];
                    end += 2;
                    this.buf[this.count - 2] = '\'';
                    hasSpecial2 = true;
                } else {
                    newcount++;
                    if (newcount > cArr2.length) {
                        expandCapacity(newcount);
                    }
                    this.count = newcount;
                    char[] cArr6 = this.buf;
                    System.arraycopy(cArr6, i7 + 1, cArr6, i7 + 2, end - i7);
                    char[] cArr7 = this.buf;
                    cArr7[i7] = '\\';
                    i7++;
                    cArr7[i7] = IOUtils.replaceChars[ch3];
                    end++;
                }
            }
            i7++;
        }
        this.buf[newcount - 1] = ':';
    }

    @Override // java.io.Writer, java.io.Flushable
    public void flush() {
        Writer writer = this.writer;
        if (writer == null) {
            return;
        }
        try {
            writer.write(this.buf, 0, this.count);
            this.writer.flush();
            this.count = 0;
        } catch (IOException e) {
            throw new JSONException(e.getMessage(), e);
        }
    }
}
