package com.alibaba.fastjson.serializer;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.util.IOUtils;
import com.alibaba.fastjson.util.RyuDouble;
import com.alibaba.fastjson.util.RyuFloat;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigDecimal;
import java.nio.charset.Charset;
import java.util.List;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class SerializeWriter extends Writer {
    private static int BUFFER_THRESHOLD;
    public static final int nonDirectFeatures;
    public boolean beanToArray;
    public boolean browserSecure;
    public char[] buf;
    public int count;
    public boolean disableCircularReferenceDetect;
    public int features;
    public char keySeperator;
    public int maxBufSize;
    public boolean notWriteDefaultValue;
    public boolean quoteFieldNames;
    public long sepcialBits;
    public boolean sortField;
    public boolean useSingleQuotes;
    public boolean writeDirect;
    public boolean writeEnumUsingName;
    public boolean writeEnumUsingToString;
    public boolean writeNonStringValueAsString;
    private final Writer writer;
    private static final ThreadLocal<char[]> bufLocal = new ThreadLocal<>();
    private static final ThreadLocal<byte[]> bytesBufLocal = new ThreadLocal<>();
    private static final char[] VALUE_TRUE = ":true".toCharArray();
    private static final char[] VALUE_FALSE = ":false".toCharArray();

    static {
        int parseInt;
        BUFFER_THRESHOLD = 131072;
        try {
            String stringProperty = IOUtils.getStringProperty("fastjson.serializer_buffer_threshold");
            if (stringProperty != null && stringProperty.length() > 0 && (parseInt = Integer.parseInt(stringProperty)) >= 64 && parseInt <= 65536) {
                BUFFER_THRESHOLD = parseInt * 1024;
            }
        } catch (Throwable unused) {
        }
        nonDirectFeatures = SerializerFeature.UseSingleQuotes.mask | 0 | SerializerFeature.BrowserCompatible.mask | SerializerFeature.PrettyFormat.mask | SerializerFeature.WriteEnumUsingToString.mask | SerializerFeature.WriteNonStringValueAsString.mask | SerializerFeature.WriteSlashAsSpecial.mask | SerializerFeature.IgnoreErrorGetter.mask | SerializerFeature.WriteClassName.mask | SerializerFeature.NotWriteDefaultValue.mask;
    }

    public SerializeWriter() {
        this((Writer) null);
    }

    private int encodeToUTF8(OutputStream outputStream) {
        int i2 = (int) (this.count * 3.0d);
        ThreadLocal<byte[]> threadLocal = bytesBufLocal;
        byte[] bArr = threadLocal.get();
        if (bArr == null) {
            bArr = new byte[8192];
            threadLocal.set(bArr);
        }
        byte[] bArr2 = bArr.length < i2 ? new byte[i2] : bArr;
        int encodeUTF8 = IOUtils.encodeUTF8(this.buf, 0, this.count, bArr2);
        outputStream.write(bArr2, 0, encodeUTF8);
        if (bArr2 != bArr && bArr2.length <= BUFFER_THRESHOLD) {
            threadLocal.set(bArr2);
        }
        return encodeUTF8;
    }

    private byte[] encodeToUTF8Bytes() {
        int i2 = (int) (this.count * 3.0d);
        ThreadLocal<byte[]> threadLocal = bytesBufLocal;
        byte[] bArr = threadLocal.get();
        if (bArr == null) {
            bArr = new byte[8192];
            threadLocal.set(bArr);
        }
        byte[] bArr2 = bArr.length < i2 ? new byte[i2] : bArr;
        int encodeUTF8 = IOUtils.encodeUTF8(this.buf, 0, this.count, bArr2);
        byte[] bArr3 = new byte[encodeUTF8];
        System.arraycopy(bArr2, 0, bArr3, 0, encodeUTF8);
        if (bArr2 != bArr && bArr2.length <= BUFFER_THRESHOLD) {
            threadLocal.set(bArr2);
        }
        return bArr3;
    }

    private void writeEnumFieldValue(char c2, String str, String str2) {
        if (this.useSingleQuotes) {
            writeFieldValue(c2, str, str2);
        } else {
            writeFieldValueStringWithDoubleQuote(c2, str, str2);
        }
    }

    private void writeKeyWithSingleQuoteIfHasSpecial(String str) {
        byte[] bArr = IOUtils.specicalFlags_singleQuotes;
        int length = str.length();
        boolean z = true;
        int i2 = this.count + length + 1;
        int i3 = 0;
        if (i2 > this.buf.length) {
            if (this.writer != null) {
                if (length == 0) {
                    write(39);
                    write(39);
                    write(58);
                    return;
                }
                int i4 = 0;
                while (true) {
                    if (i4 < length) {
                        char charAt = str.charAt(i4);
                        if (charAt < bArr.length && bArr[charAt] != 0) {
                            break;
                        } else {
                            i4++;
                        }
                    } else {
                        z = false;
                        break;
                    }
                }
                if (z) {
                    write(39);
                }
                while (i3 < length) {
                    char charAt2 = str.charAt(i3);
                    if (charAt2 >= bArr.length || bArr[charAt2] == 0) {
                        write(charAt2);
                    } else {
                        write(92);
                        write(IOUtils.replaceChars[charAt2]);
                    }
                    i3++;
                }
                if (z) {
                    write(39);
                }
                write(58);
                return;
            }
            expandCapacity(i2);
        }
        if (length == 0) {
            int i5 = this.count;
            if (i5 + 3 > this.buf.length) {
                expandCapacity(i5 + 3);
            }
            char[] cArr = this.buf;
            int i6 = this.count;
            int i7 = i6 + 1;
            this.count = i7;
            cArr[i6] = '\'';
            int i8 = i7 + 1;
            this.count = i8;
            cArr[i7] = '\'';
            this.count = i8 + 1;
            cArr[i8] = ':';
            return;
        }
        int i9 = this.count;
        int i10 = i9 + length;
        str.getChars(0, length, this.buf, i9);
        this.count = i2;
        int i11 = i9;
        boolean z2 = false;
        while (i11 < i10) {
            char[] cArr2 = this.buf;
            char c2 = cArr2[i11];
            if (c2 < bArr.length && bArr[c2] != 0) {
                if (z2) {
                    i2++;
                    if (i2 > cArr2.length) {
                        expandCapacity(i2);
                    }
                    this.count = i2;
                    char[] cArr3 = this.buf;
                    int i12 = i11 + 1;
                    System.arraycopy(cArr3, i12, cArr3, i11 + 2, i10 - i11);
                    char[] cArr4 = this.buf;
                    cArr4[i11] = '\\';
                    cArr4[i12] = IOUtils.replaceChars[c2];
                    i10++;
                    i11 = i12;
                } else {
                    i2 += 3;
                    if (i2 > cArr2.length) {
                        expandCapacity(i2);
                    }
                    this.count = i2;
                    char[] cArr5 = this.buf;
                    int i13 = i11 + 1;
                    System.arraycopy(cArr5, i13, cArr5, i11 + 3, (i10 - i11) - 1);
                    char[] cArr6 = this.buf;
                    System.arraycopy(cArr6, i3, cArr6, 1, i11);
                    char[] cArr7 = this.buf;
                    cArr7[i9] = '\'';
                    cArr7[i13] = '\\';
                    int i14 = i13 + 1;
                    cArr7[i14] = IOUtils.replaceChars[c2];
                    i10 += 2;
                    cArr7[this.count - 2] = '\'';
                    i11 = i14;
                    z2 = true;
                }
            }
            i11++;
            i3 = 0;
        }
        this.buf[i2 - 1] = ':';
    }

    @Override // java.io.Writer, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.writer != null && this.count > 0) {
            flush();
        }
        char[] cArr = this.buf;
        if (cArr.length <= BUFFER_THRESHOLD) {
            bufLocal.set(cArr);
        }
        this.buf = null;
    }

    public void computeFeatures() {
        int i2 = this.features;
        boolean z = (SerializerFeature.QuoteFieldNames.mask & i2) != 0;
        this.quoteFieldNames = z;
        boolean z2 = (SerializerFeature.UseSingleQuotes.mask & i2) != 0;
        this.useSingleQuotes = z2;
        this.sortField = (SerializerFeature.SortField.mask & i2) != 0;
        this.disableCircularReferenceDetect = (SerializerFeature.DisableCircularReferenceDetect.mask & i2) != 0;
        boolean z3 = (SerializerFeature.BeanToArray.mask & i2) != 0;
        this.beanToArray = z3;
        this.writeNonStringValueAsString = (SerializerFeature.WriteNonStringValueAsString.mask & i2) != 0;
        this.notWriteDefaultValue = (SerializerFeature.NotWriteDefaultValue.mask & i2) != 0;
        boolean z4 = (SerializerFeature.WriteEnumUsingName.mask & i2) != 0;
        this.writeEnumUsingName = z4;
        this.writeEnumUsingToString = (SerializerFeature.WriteEnumUsingToString.mask & i2) != 0;
        this.writeDirect = z && (nonDirectFeatures & i2) == 0 && (z3 || z4);
        this.keySeperator = z2 ? '\'' : Typography.quote;
        boolean z5 = (SerializerFeature.BrowserSecure.mask & i2) != 0;
        this.browserSecure = z5;
        this.sepcialBits = z5 ? 5764610843043954687L : (i2 & SerializerFeature.WriteSlashAsSpecial.mask) != 0 ? 140758963191807L : 21474836479L;
    }

    public void config(SerializerFeature serializerFeature, boolean z) {
        if (z) {
            int mask = this.features | serializerFeature.getMask();
            this.features = mask;
            SerializerFeature serializerFeature2 = SerializerFeature.WriteEnumUsingToString;
            if (serializerFeature == serializerFeature2) {
                this.features = (~SerializerFeature.WriteEnumUsingName.getMask()) & mask;
            } else if (serializerFeature == SerializerFeature.WriteEnumUsingName) {
                this.features = (~serializerFeature2.getMask()) & mask;
            }
        } else {
            this.features = (~serializerFeature.getMask()) & this.features;
        }
        computeFeatures();
    }

    public void expandCapacity(int i2) {
        ThreadLocal<char[]> threadLocal;
        char[] cArr;
        int i3 = this.maxBufSize;
        if (i3 != -1 && i2 >= i3) {
            StringBuilder m586H = C1499a.m586H("serialize exceeded MAX_OUTPUT_LENGTH=");
            m586H.append(this.maxBufSize);
            m586H.append(", minimumCapacity=");
            m586H.append(i2);
            throw new JSONException(m586H.toString());
        }
        char[] cArr2 = this.buf;
        int length = cArr2.length + (cArr2.length >> 1) + 1;
        if (length >= i2) {
            i2 = length;
        }
        char[] cArr3 = new char[i2];
        System.arraycopy(cArr2, 0, cArr3, 0, this.count);
        if (this.buf.length < BUFFER_THRESHOLD && ((cArr = (threadLocal = bufLocal).get()) == null || cArr.length < this.buf.length)) {
            threadLocal.set(this.buf);
        }
        this.buf = cArr3;
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
        } catch (IOException e2) {
            throw new JSONException(e2.getMessage(), e2);
        }
    }

    public int getBufferLength() {
        return this.buf.length;
    }

    public int getMaxBufSize() {
        return this.maxBufSize;
    }

    public boolean isEnabled(SerializerFeature serializerFeature) {
        return (serializerFeature.mask & this.features) != 0;
    }

    public boolean isNotWriteDefaultValue() {
        return this.notWriteDefaultValue;
    }

    public boolean isSortField() {
        return this.sortField;
    }

    public void reset() {
        this.count = 0;
    }

    public void setMaxBufSize(int i2) {
        if (i2 >= this.buf.length) {
            this.maxBufSize = i2;
        } else {
            StringBuilder m586H = C1499a.m586H("must > ");
            m586H.append(this.buf.length);
            throw new JSONException(m586H.toString());
        }
    }

    public int size() {
        return this.count;
    }

    public byte[] toBytes(String str) {
        return toBytes((str == null || "UTF-8".equals(str)) ? IOUtils.UTF8 : Charset.forName(str));
    }

    public char[] toCharArray() {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        int i2 = this.count;
        char[] cArr = new char[i2];
        System.arraycopy(this.buf, 0, cArr, 0, i2);
        return cArr;
    }

    public char[] toCharArrayForSpringWebSocket() {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        int i2 = this.count;
        char[] cArr = new char[i2 - 2];
        System.arraycopy(this.buf, 1, cArr, 0, i2 - 2);
        return cArr;
    }

    public String toString() {
        return new String(this.buf, 0, this.count);
    }

    @Override // java.io.Writer
    public void write(int i2) {
        int i3 = 1;
        int i4 = this.count + 1;
        if (i4 > this.buf.length) {
            if (this.writer != null) {
                flush();
                this.buf[this.count] = (char) i2;
                this.count = i3;
            }
            expandCapacity(i4);
        }
        i3 = i4;
        this.buf[this.count] = (char) i2;
        this.count = i3;
    }

    public void writeByteArray(byte[] bArr) {
        if (isEnabled(SerializerFeature.WriteClassName.mask)) {
            writeHex(bArr);
            return;
        }
        int length = bArr.length;
        boolean z = this.useSingleQuotes;
        char c2 = z ? '\'' : Typography.quote;
        if (length == 0) {
            write(z ? "''" : "\"\"");
            return;
        }
        char[] cArr = IOUtils.f8513CA;
        int i2 = (length / 3) * 3;
        int i3 = length - 1;
        int i4 = this.count;
        int i5 = (((i3 / 3) + 1) << 2) + i4 + 2;
        if (i5 > this.buf.length) {
            if (this.writer != null) {
                write(c2);
                int i6 = 0;
                while (i6 < i2) {
                    int i7 = i6 + 1;
                    int i8 = i7 + 1;
                    int i9 = ((bArr[i6] & 255) << 16) | ((bArr[i7] & 255) << 8) | (bArr[i8] & 255);
                    write(cArr[(i9 >>> 18) & 63]);
                    write(cArr[(i9 >>> 12) & 63]);
                    write(cArr[(i9 >>> 6) & 63]);
                    write(cArr[i9 & 63]);
                    i6 = i8 + 1;
                }
                int i10 = length - i2;
                if (i10 > 0) {
                    int i11 = ((bArr[i2] & 255) << 10) | (i10 == 2 ? (bArr[i3] & 255) << 2 : 0);
                    write(cArr[i11 >> 12]);
                    write(cArr[(i11 >>> 6) & 63]);
                    write(i10 == 2 ? cArr[i11 & 63] : '=');
                    write(61);
                }
                write(c2);
                return;
            }
            expandCapacity(i5);
        }
        this.count = i5;
        int i12 = i4 + 1;
        this.buf[i4] = c2;
        int i13 = 0;
        while (i13 < i2) {
            int i14 = i13 + 1;
            int i15 = i14 + 1;
            int i16 = ((bArr[i13] & 255) << 16) | ((bArr[i14] & 255) << 8);
            int i17 = i15 + 1;
            int i18 = i16 | (bArr[i15] & 255);
            char[] cArr2 = this.buf;
            int i19 = i12 + 1;
            cArr2[i12] = cArr[(i18 >>> 18) & 63];
            int i20 = i19 + 1;
            cArr2[i19] = cArr[(i18 >>> 12) & 63];
            int i21 = i20 + 1;
            cArr2[i20] = cArr[(i18 >>> 6) & 63];
            i12 = i21 + 1;
            cArr2[i21] = cArr[i18 & 63];
            i13 = i17;
        }
        int i22 = length - i2;
        if (i22 > 0) {
            int i23 = ((bArr[i2] & 255) << 10) | (i22 == 2 ? (bArr[i3] & 255) << 2 : 0);
            char[] cArr3 = this.buf;
            cArr3[i5 - 5] = cArr[i23 >> 12];
            cArr3[i5 - 4] = cArr[(i23 >>> 6) & 63];
            cArr3[i5 - 3] = i22 == 2 ? cArr[i23 & 63] : '=';
            cArr3[i5 - 2] = '=';
        }
        this.buf[i5 - 1] = c2;
    }

    public void writeDouble(double d2, boolean z) {
        if (Double.isNaN(d2) || Double.isInfinite(d2)) {
            writeNull();
            return;
        }
        int i2 = this.count + 24;
        if (i2 > this.buf.length) {
            if (this.writer != null) {
                String ryuDouble = RyuDouble.toString(d2);
                write(ryuDouble, 0, ryuDouble.length());
                if (z && isEnabled(SerializerFeature.WriteClassName)) {
                    write(68);
                    return;
                }
                return;
            }
            expandCapacity(i2);
        }
        this.count += RyuDouble.toString(d2, this.buf, this.count);
        if (z && isEnabled(SerializerFeature.WriteClassName)) {
            write(68);
        }
    }

    public void writeEnum(Enum<?> r3) {
        if (r3 == null) {
            writeNull();
            return;
        }
        String str = null;
        if (this.writeEnumUsingName && !this.writeEnumUsingToString) {
            str = r3.name();
        } else if (this.writeEnumUsingToString) {
            str = r3.toString();
        }
        if (str == null) {
            writeInt(r3.ordinal());
            return;
        }
        int i2 = isEnabled(SerializerFeature.UseSingleQuotes) ? 39 : 34;
        write(i2);
        write(str);
        write(i2);
    }

    public void writeFieldName(String str) {
        writeFieldName(str, false);
    }

    public void writeFieldNameDirect(String str) {
        int length = str.length();
        int i2 = this.count + length + 3;
        if (i2 > this.buf.length) {
            expandCapacity(i2);
        }
        int i3 = this.count;
        char[] cArr = this.buf;
        cArr[i3] = Typography.quote;
        str.getChars(0, length, cArr, i3 + 1);
        this.count = i2;
        char[] cArr2 = this.buf;
        cArr2[i2 - 2] = Typography.quote;
        cArr2[i2 - 1] = ':';
    }

    public void writeFieldValue(char c2, String str, char c3) {
        write(c2);
        writeFieldName(str);
        if (c3 == 0) {
            writeString("\u0000");
        } else {
            writeString(Character.toString(c3));
        }
    }

    public void writeFieldValueStringWithDoubleQuote(char c2, String str, String str2) {
        int length = str.length();
        int i2 = this.count;
        int length2 = str2.length();
        int i3 = length + length2 + 6 + i2;
        if (i3 > this.buf.length) {
            if (this.writer != null) {
                write(c2);
                writeStringWithDoubleQuote(str, ':');
                writeStringWithDoubleQuote(str2, (char) 0);
                return;
            }
            expandCapacity(i3);
        }
        char[] cArr = this.buf;
        int i4 = this.count;
        cArr[i4] = c2;
        int i5 = i4 + 2;
        int i6 = i5 + length;
        cArr[i4 + 1] = Typography.quote;
        str.getChars(0, length, cArr, i5);
        this.count = i3;
        char[] cArr2 = this.buf;
        cArr2[i6] = Typography.quote;
        int i7 = i6 + 1;
        int i8 = i7 + 1;
        cArr2[i7] = ':';
        cArr2[i8] = Typography.quote;
        str2.getChars(0, length2, cArr2, i8 + 1);
        this.buf[this.count - 1] = Typography.quote;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x021b, code lost:
    
        if (r3 != '>') goto L102;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00d7, code lost:
    
        if (r1[r7] == 4) goto L53;
     */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00de  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void writeFieldValueStringWithDoubleQuoteCheck(char r22, java.lang.String r23, java.lang.String r24) {
        /*
            Method dump skipped, instructions count: 781
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.serializer.SerializeWriter.writeFieldValueStringWithDoubleQuoteCheck(char, java.lang.String, java.lang.String):void");
    }

    public void writeFloat(float f2, boolean z) {
        if (f2 != f2 || f2 == Float.POSITIVE_INFINITY || f2 == Float.NEGATIVE_INFINITY) {
            writeNull();
            return;
        }
        int i2 = this.count + 15;
        if (i2 > this.buf.length) {
            if (this.writer != null) {
                String ryuFloat = RyuFloat.toString(f2);
                write(ryuFloat, 0, ryuFloat.length());
                if (z && isEnabled(SerializerFeature.WriteClassName)) {
                    write(70);
                    return;
                }
                return;
            }
            expandCapacity(i2);
        }
        this.count += RyuFloat.toString(f2, this.buf, this.count);
        if (z && isEnabled(SerializerFeature.WriteClassName)) {
            write(70);
        }
    }

    public void writeHex(byte[] bArr) {
        int length = (bArr.length * 2) + this.count + 3;
        if (length > this.buf.length) {
            expandCapacity(length);
        }
        char[] cArr = this.buf;
        int i2 = this.count;
        int i3 = i2 + 1;
        this.count = i3;
        cArr[i2] = 'x';
        this.count = i3 + 1;
        cArr[i3] = '\'';
        for (byte b2 : bArr) {
            int i4 = b2 & 255;
            int i5 = i4 >> 4;
            int i6 = i4 & 15;
            char[] cArr2 = this.buf;
            int i7 = this.count;
            int i8 = i7 + 1;
            this.count = i8;
            int i9 = 48;
            cArr2[i7] = (char) (i5 + (i5 < 10 ? 48 : 55));
            this.count = i8 + 1;
            if (i6 >= 10) {
                i9 = 55;
            }
            cArr2[i8] = (char) (i6 + i9);
        }
        char[] cArr3 = this.buf;
        int i10 = this.count;
        this.count = i10 + 1;
        cArr3[i10] = '\'';
    }

    public void writeInt(int i2) {
        if (i2 == Integer.MIN_VALUE) {
            write("-2147483648");
            return;
        }
        int stringSize = i2 < 0 ? IOUtils.stringSize(-i2) + 1 : IOUtils.stringSize(i2);
        int i3 = this.count + stringSize;
        if (i3 > this.buf.length) {
            if (this.writer != null) {
                char[] cArr = new char[stringSize];
                IOUtils.getChars(i2, stringSize, cArr);
                write(cArr, 0, stringSize);
                return;
            }
            expandCapacity(i3);
        }
        IOUtils.getChars(i2, i3, this.buf);
        this.count = i3;
    }

    public void writeLong(long j2) {
        boolean z = isEnabled(SerializerFeature.BrowserCompatible) && !isEnabled(SerializerFeature.WriteClassName) && (j2 > 9007199254740991L || j2 < -9007199254740991L);
        if (j2 == Long.MIN_VALUE) {
            if (z) {
                write("\"-9223372036854775808\"");
                return;
            } else {
                write("-9223372036854775808");
                return;
            }
        }
        int stringSize = j2 < 0 ? IOUtils.stringSize(-j2) + 1 : IOUtils.stringSize(j2);
        int i2 = this.count + stringSize;
        if (z) {
            i2 += 2;
        }
        if (i2 > this.buf.length) {
            if (this.writer != null) {
                char[] cArr = new char[stringSize];
                IOUtils.getChars(j2, stringSize, cArr);
                if (!z) {
                    write(cArr, 0, stringSize);
                    return;
                }
                write(34);
                write(cArr, 0, stringSize);
                write(34);
                return;
            }
            expandCapacity(i2);
        }
        if (z) {
            char[] cArr2 = this.buf;
            cArr2[this.count] = Typography.quote;
            int i3 = i2 - 1;
            IOUtils.getChars(j2, i3, cArr2);
            this.buf[i3] = Typography.quote;
        } else {
            IOUtils.getChars(j2, i2, this.buf);
        }
        this.count = i2;
    }

    public void writeLongAndChar(long j2, char c2) {
        writeLong(j2);
        write(c2);
    }

    public void writeNull() {
        write("null");
    }

    public void writeString(String str, char c2) {
        if (!this.useSingleQuotes) {
            writeStringWithDoubleQuote(str, c2);
        } else {
            writeStringWithSingleQuote(str);
            write(c2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:179:0x02eb, code lost:
    
        if (r8[r10] == 4) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x0432, code lost:
    
        if (r4 != '>') goto L218;
     */
    /* JADX WARN: Removed duplicated region for block: B:182:0x02f2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void writeStringWithDoubleQuote(java.lang.String r23, char r24) {
        /*
            Method dump skipped, instructions count: 1338
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.serializer.SerializeWriter.writeStringWithDoubleQuote(java.lang.String, char):void");
    }

    public void writeStringWithSingleQuote(String str) {
        int i2 = 0;
        if (str == null) {
            int i3 = this.count + 4;
            if (i3 > this.buf.length) {
                expandCapacity(i3);
            }
            "null".getChars(0, 4, this.buf, this.count);
            this.count = i3;
            return;
        }
        int length = str.length();
        int i4 = this.count + length + 2;
        if (i4 > this.buf.length) {
            if (this.writer != null) {
                write(39);
                while (i2 < str.length()) {
                    char charAt = str.charAt(i2);
                    if (charAt <= '\r' || charAt == '\\' || charAt == '\'' || (charAt == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                        write(92);
                        write(IOUtils.replaceChars[charAt]);
                    } else {
                        write(charAt);
                    }
                    i2++;
                }
                write(39);
                return;
            }
            expandCapacity(i4);
        }
        int i5 = this.count;
        int i6 = i5 + 1;
        int i7 = i6 + length;
        char[] cArr = this.buf;
        cArr[i5] = '\'';
        str.getChars(0, length, cArr, i6);
        this.count = i4;
        int i8 = -1;
        char c2 = 0;
        for (int i9 = i6; i9 < i7; i9++) {
            char c3 = this.buf[i9];
            if (c3 <= '\r' || c3 == '\\' || c3 == '\'' || (c3 == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                i2++;
                i8 = i9;
                c2 = c3;
            }
        }
        int i10 = i4 + i2;
        if (i10 > this.buf.length) {
            expandCapacity(i10);
        }
        this.count = i10;
        if (i2 == 1) {
            char[] cArr2 = this.buf;
            int i11 = i8 + 1;
            System.arraycopy(cArr2, i11, cArr2, i8 + 2, (i7 - i8) - 1);
            char[] cArr3 = this.buf;
            cArr3[i8] = '\\';
            cArr3[i11] = IOUtils.replaceChars[c2];
        } else if (i2 > 1) {
            char[] cArr4 = this.buf;
            int i12 = i8 + 1;
            System.arraycopy(cArr4, i12, cArr4, i8 + 2, (i7 - i8) - 1);
            char[] cArr5 = this.buf;
            cArr5[i8] = '\\';
            cArr5[i12] = IOUtils.replaceChars[c2];
            int i13 = i7 + 1;
            for (int i14 = i12 - 2; i14 >= i6; i14--) {
                char c4 = this.buf[i14];
                if (c4 <= '\r' || c4 == '\\' || c4 == '\'' || (c4 == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                    char[] cArr6 = this.buf;
                    int i15 = i14 + 1;
                    System.arraycopy(cArr6, i15, cArr6, i14 + 2, (i13 - i14) - 1);
                    char[] cArr7 = this.buf;
                    cArr7[i14] = '\\';
                    cArr7[i15] = IOUtils.replaceChars[c4];
                    i13++;
                }
            }
        }
        this.buf[this.count - 1] = '\'';
    }

    public void writeTo(Writer writer) {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        writer.write(this.buf, 0, this.count);
    }

    public int writeToEx(OutputStream outputStream, Charset charset) {
        if (this.writer != null) {
            throw new UnsupportedOperationException("writer not null");
        }
        if (charset == IOUtils.UTF8) {
            return encodeToUTF8(outputStream);
        }
        byte[] bytes = new String(this.buf, 0, this.count).getBytes(charset);
        outputStream.write(bytes);
        return bytes.length;
    }

    public SerializeWriter(Writer writer) {
        this(writer, JSON.DEFAULT_GENERATE_FEATURE, SerializerFeature.EMPTY);
    }

    public boolean isEnabled(int i2) {
        return (i2 & this.features) != 0;
    }

    public void writeFieldName(String str, boolean z) {
        if (str == null) {
            write("null:");
            return;
        }
        if (this.useSingleQuotes) {
            if (!this.quoteFieldNames) {
                writeKeyWithSingleQuoteIfHasSpecial(str);
                return;
            } else {
                writeStringWithSingleQuote(str);
                write(58);
                return;
            }
        }
        if (this.quoteFieldNames) {
            writeStringWithDoubleQuote(str, ':');
            return;
        }
        boolean z2 = true;
        boolean z3 = str.length() == 0;
        int i2 = 0;
        while (true) {
            if (i2 >= str.length()) {
                z2 = z3;
                break;
            }
            char charAt = str.charAt(i2);
            if ((charAt < '@' && (this.sepcialBits & (1 << charAt)) != 0) || charAt == '\\') {
                break;
            } else {
                i2++;
            }
        }
        if (z2) {
            writeStringWithDoubleQuote(str, ':');
        } else {
            write(str);
            write(58);
        }
    }

    public void writeNull(SerializerFeature serializerFeature) {
        writeNull(0, serializerFeature.mask);
    }

    public SerializeWriter(SerializerFeature... serializerFeatureArr) {
        this((Writer) null, serializerFeatureArr);
    }

    public void writeNull(int i2, int i3) {
        if ((i2 & i3) == 0 && (this.features & i3) == 0) {
            writeNull();
            return;
        }
        int i4 = SerializerFeature.WriteMapNullValue.mask;
        if ((i2 & i4) != 0 && (i2 & (~i4) & SerializerFeature.WRITE_MAP_NULL_FEATURES) == 0) {
            writeNull();
            return;
        }
        if (i3 == SerializerFeature.WriteNullListAsEmpty.mask) {
            write("[]");
            return;
        }
        if (i3 == SerializerFeature.WriteNullStringAsEmpty.mask) {
            writeString("");
            return;
        }
        if (i3 == SerializerFeature.WriteNullBooleanAsFalse.mask) {
            write("false");
        } else if (i3 == SerializerFeature.WriteNullNumberAsZero.mask) {
            write(48);
        } else {
            writeNull();
        }
    }

    public SerializeWriter(Writer writer, SerializerFeature... serializerFeatureArr) {
        this(writer, 0, serializerFeatureArr);
    }

    public byte[] toBytes(Charset charset) {
        if (this.writer == null) {
            if (charset == IOUtils.UTF8) {
                return encodeToUTF8Bytes();
            }
            return new String(this.buf, 0, this.count).getBytes(charset);
        }
        throw new UnsupportedOperationException("writer not null");
    }

    public void writeTo(OutputStream outputStream, String str) {
        writeTo(outputStream, Charset.forName(str));
    }

    public SerializeWriter(Writer writer, int i2, SerializerFeature... serializerFeatureArr) {
        this.maxBufSize = -1;
        this.writer = writer;
        ThreadLocal<char[]> threadLocal = bufLocal;
        char[] cArr = threadLocal.get();
        this.buf = cArr;
        if (cArr != null) {
            threadLocal.set(null);
        } else {
            this.buf = new char[2048];
        }
        for (SerializerFeature serializerFeature : serializerFeatureArr) {
            i2 |= serializerFeature.getMask();
        }
        this.features = i2;
        computeFeatures();
    }

    public void writeFieldValue(char c2, String str, boolean z) {
        if (!this.quoteFieldNames) {
            write(c2);
            writeFieldName(str);
            write(z);
            return;
        }
        int i2 = z ? 4 : 5;
        int length = str.length();
        int i3 = this.count + length + 4 + i2;
        if (i3 > this.buf.length) {
            if (this.writer != null) {
                write(c2);
                writeString(str);
                write(58);
                write(z);
                return;
            }
            expandCapacity(i3);
        }
        int i4 = this.count;
        this.count = i3;
        char[] cArr = this.buf;
        cArr[i4] = c2;
        int i5 = i4 + length + 1;
        cArr[i4 + 1] = this.keySeperator;
        str.getChars(0, length, cArr, i4 + 2);
        char[] cArr2 = this.buf;
        cArr2[i5 + 1] = this.keySeperator;
        if (z) {
            System.arraycopy(VALUE_TRUE, 0, cArr2, i5 + 2, 5);
        } else {
            System.arraycopy(VALUE_FALSE, 0, cArr2, i5 + 2, 6);
        }
    }

    public void writeString(String str) {
        if (this.useSingleQuotes) {
            writeStringWithSingleQuote(str);
        } else {
            writeStringWithDoubleQuote(str, (char) 0);
        }
    }

    public void writeTo(OutputStream outputStream, Charset charset) {
        writeToEx(outputStream, charset);
    }

    @Override // java.io.Writer, java.lang.Appendable
    public SerializeWriter append(CharSequence charSequence) {
        String charSequence2 = charSequence == null ? "null" : charSequence.toString();
        write(charSequence2, 0, charSequence2.length());
        return this;
    }

    @Override // java.io.Writer
    public void write(char[] cArr, int i2, int i3) {
        int i4;
        if (i2 < 0 || i2 > cArr.length || i3 < 0 || (i4 = i2 + i3) > cArr.length || i4 < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (i3 == 0) {
            return;
        }
        int i5 = this.count + i3;
        if (i5 > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(i5);
            } else {
                do {
                    char[] cArr2 = this.buf;
                    int length = cArr2.length;
                    int i6 = this.count;
                    int i7 = length - i6;
                    System.arraycopy(cArr, i2, cArr2, i6, i7);
                    this.count = this.buf.length;
                    flush();
                    i3 -= i7;
                    i2 += i7;
                } while (i3 > this.buf.length);
                i5 = i3;
            }
        }
        System.arraycopy(cArr, i2, this.buf, this.count, i3);
        this.count = i5;
    }

    public void writeString(char[] cArr) {
        if (this.useSingleQuotes) {
            writeStringWithSingleQuote(cArr);
        } else {
            writeStringWithDoubleQuote(new String(cArr), (char) 0);
        }
    }

    @Override // java.io.Writer, java.lang.Appendable
    public SerializeWriter append(CharSequence charSequence, int i2, int i3) {
        if (charSequence == null) {
            charSequence = "null";
        }
        String charSequence2 = charSequence.subSequence(i2, i3).toString();
        write(charSequence2, 0, charSequence2.length());
        return this;
    }

    @Override // java.io.Writer, java.lang.Appendable
    public SerializeWriter append(char c2) {
        write(c2);
        return this;
    }

    public SerializeWriter(int i2) {
        this((Writer) null, i2);
    }

    public SerializeWriter(Writer writer, int i2) {
        this.maxBufSize = -1;
        this.writer = writer;
        if (i2 > 0) {
            this.buf = new char[i2];
            computeFeatures();
            return;
        }
        throw new IllegalArgumentException(C1499a.m626l("Negative initial size: ", i2));
    }

    @Override // java.io.Writer
    public void write(String str, int i2, int i3) {
        int i4;
        int i5 = this.count + i3;
        if (i5 > this.buf.length) {
            if (this.writer == null) {
                expandCapacity(i5);
            } else {
                while (true) {
                    char[] cArr = this.buf;
                    int length = cArr.length;
                    int i6 = this.count;
                    int i7 = length - i6;
                    i4 = i2 + i7;
                    str.getChars(i2, i4, cArr, i6);
                    this.count = this.buf.length;
                    flush();
                    i3 -= i7;
                    if (i3 <= this.buf.length) {
                        break;
                    } else {
                        i2 = i4;
                    }
                }
                i5 = i3;
                i2 = i4;
            }
        }
        str.getChars(i2, i3 + i2, this.buf, this.count);
        this.count = i5;
    }

    public void writeFieldValue(char c2, String str, int i2) {
        if (i2 != Integer.MIN_VALUE && this.quoteFieldNames) {
            int stringSize = i2 < 0 ? IOUtils.stringSize(-i2) + 1 : IOUtils.stringSize(i2);
            int length = str.length();
            int i3 = this.count + length + 4 + stringSize;
            if (i3 > this.buf.length) {
                if (this.writer != null) {
                    write(c2);
                    writeFieldName(str);
                    writeInt(i2);
                    return;
                }
                expandCapacity(i3);
            }
            int i4 = this.count;
            this.count = i3;
            char[] cArr = this.buf;
            cArr[i4] = c2;
            int i5 = i4 + length + 1;
            cArr[i4 + 1] = this.keySeperator;
            str.getChars(0, length, cArr, i4 + 2);
            char[] cArr2 = this.buf;
            cArr2[i5 + 1] = this.keySeperator;
            cArr2[i5 + 2] = ':';
            IOUtils.getChars(i2, this.count, cArr2);
            return;
        }
        write(c2);
        writeFieldName(str);
        writeInt(i2);
    }

    @Override // java.io.Writer
    public void write(String str) {
        if (str == null) {
            writeNull();
        } else {
            write(str, 0, str.length());
        }
    }

    public void write(List<String> list) {
        boolean z;
        int i2;
        if (list.isEmpty()) {
            write("[]");
            return;
        }
        int i3 = this.count;
        int size = list.size();
        int i4 = i3;
        int i5 = 0;
        while (i5 < size) {
            String str = list.get(i5);
            if (str == null) {
                z = true;
            } else {
                int length = str.length();
                z = false;
                for (int i6 = 0; i6 < length; i6++) {
                    char charAt = str.charAt(i6);
                    z = charAt < ' ' || charAt > '~' || charAt == '\"' || charAt == '\\';
                    if (z) {
                        break;
                    }
                }
            }
            if (z) {
                this.count = i3;
                write(91);
                for (int i7 = 0; i7 < list.size(); i7++) {
                    String str2 = list.get(i7);
                    if (i7 != 0) {
                        write(44);
                    }
                    if (str2 == null) {
                        write("null");
                    } else {
                        writeStringWithDoubleQuote(str2, (char) 0);
                    }
                }
                write(93);
                return;
            }
            int length2 = str.length() + i4 + 3;
            if (i5 == list.size() - 1) {
                length2++;
            }
            if (length2 > this.buf.length) {
                this.count = i4;
                expandCapacity(length2);
            }
            if (i5 == 0) {
                i2 = i4 + 1;
                this.buf[i4] = '[';
            } else {
                i2 = i4 + 1;
                this.buf[i4] = ',';
            }
            int i8 = i2 + 1;
            this.buf[i2] = Typography.quote;
            str.getChars(0, str.length(), this.buf, i8);
            int length3 = str.length() + i8;
            this.buf[length3] = Typography.quote;
            i5++;
            i4 = length3 + 1;
        }
        this.buf[i4] = ']';
        this.count = i4 + 1;
    }

    public void writeStringWithSingleQuote(char[] cArr) {
        int i2 = 0;
        if (cArr == null) {
            int i3 = this.count + 4;
            if (i3 > this.buf.length) {
                expandCapacity(i3);
            }
            "null".getChars(0, 4, this.buf, this.count);
            this.count = i3;
            return;
        }
        int length = cArr.length;
        int i4 = this.count + length + 2;
        if (i4 > this.buf.length) {
            if (this.writer != null) {
                write(39);
                while (i2 < cArr.length) {
                    char c2 = cArr[i2];
                    if (c2 > '\r' && c2 != '\\' && c2 != '\'' && (c2 != '/' || !isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                        write(c2);
                    } else {
                        write(92);
                        write(IOUtils.replaceChars[c2]);
                    }
                    i2++;
                }
                write(39);
                return;
            }
            expandCapacity(i4);
        }
        int i5 = this.count;
        int i6 = i5 + 1;
        int i7 = length + i6;
        char[] cArr2 = this.buf;
        cArr2[i5] = '\'';
        System.arraycopy(cArr, 0, cArr2, i6, cArr.length);
        this.count = i4;
        int i8 = -1;
        char c3 = 0;
        for (int i9 = i6; i9 < i7; i9++) {
            char c4 = this.buf[i9];
            if (c4 <= '\r' || c4 == '\\' || c4 == '\'' || (c4 == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                i2++;
                i8 = i9;
                c3 = c4;
            }
        }
        int i10 = i4 + i2;
        if (i10 > this.buf.length) {
            expandCapacity(i10);
        }
        this.count = i10;
        if (i2 == 1) {
            char[] cArr3 = this.buf;
            int i11 = i8 + 1;
            System.arraycopy(cArr3, i11, cArr3, i8 + 2, (i7 - i8) - 1);
            char[] cArr4 = this.buf;
            cArr4[i8] = '\\';
            cArr4[i11] = IOUtils.replaceChars[c3];
        } else if (i2 > 1) {
            char[] cArr5 = this.buf;
            int i12 = i8 + 1;
            System.arraycopy(cArr5, i12, cArr5, i8 + 2, (i7 - i8) - 1);
            char[] cArr6 = this.buf;
            cArr6[i8] = '\\';
            cArr6[i12] = IOUtils.replaceChars[c3];
            int i13 = i7 + 1;
            for (int i14 = i12 - 2; i14 >= i6; i14--) {
                char c5 = this.buf[i14];
                if (c5 <= '\r' || c5 == '\\' || c5 == '\'' || (c5 == '/' && isEnabled(SerializerFeature.WriteSlashAsSpecial))) {
                    char[] cArr7 = this.buf;
                    int i15 = i14 + 1;
                    System.arraycopy(cArr7, i15, cArr7, i14 + 2, (i13 - i14) - 1);
                    char[] cArr8 = this.buf;
                    cArr8[i14] = '\\';
                    cArr8[i15] = IOUtils.replaceChars[c5];
                    i13++;
                }
            }
        }
        this.buf[this.count - 1] = '\'';
    }

    public void writeFieldValue(char c2, String str, long j2) {
        if (j2 != Long.MIN_VALUE && this.quoteFieldNames && !isEnabled(SerializerFeature.BrowserCompatible.mask)) {
            int stringSize = j2 < 0 ? IOUtils.stringSize(-j2) + 1 : IOUtils.stringSize(j2);
            int length = str.length();
            int i2 = this.count + length + 4 + stringSize;
            if (i2 > this.buf.length) {
                if (this.writer != null) {
                    write(c2);
                    writeFieldName(str);
                    writeLong(j2);
                    return;
                }
                expandCapacity(i2);
            }
            int i3 = this.count;
            this.count = i2;
            char[] cArr = this.buf;
            cArr[i3] = c2;
            int i4 = i3 + length + 1;
            cArr[i3 + 1] = this.keySeperator;
            str.getChars(0, length, cArr, i3 + 2);
            char[] cArr2 = this.buf;
            cArr2[i4 + 1] = this.keySeperator;
            cArr2[i4 + 2] = ':';
            IOUtils.getChars(j2, this.count, cArr2);
            return;
        }
        write(c2);
        writeFieldName(str);
        writeLong(j2);
    }

    public void write(boolean z) {
        if (z) {
            write("true");
        } else {
            write("false");
        }
    }

    public void writeFieldValue(char c2, String str, float f2) {
        write(c2);
        writeFieldName(str);
        writeFloat(f2, false);
    }

    public void writeFieldValue(char c2, String str, double d2) {
        write(c2);
        writeFieldName(str);
        writeDouble(d2, false);
    }

    public void writeFieldValue(char c2, String str, String str2) {
        if (this.quoteFieldNames) {
            if (this.useSingleQuotes) {
                write(c2);
                writeFieldName(str);
                if (str2 == null) {
                    writeNull();
                    return;
                } else {
                    writeString(str2);
                    return;
                }
            }
            if (isEnabled(SerializerFeature.BrowserCompatible)) {
                write(c2);
                writeStringWithDoubleQuote(str, ':');
                writeStringWithDoubleQuote(str2, (char) 0);
                return;
            }
            writeFieldValueStringWithDoubleQuoteCheck(c2, str, str2);
            return;
        }
        write(c2);
        writeFieldName(str);
        if (str2 == null) {
            writeNull();
        } else {
            writeString(str2);
        }
    }

    public void writeFieldValue(char c2, String str, Enum<?> r4) {
        if (r4 == null) {
            write(c2);
            writeFieldName(str);
            writeNull();
        } else if (this.writeEnumUsingName && !this.writeEnumUsingToString) {
            writeEnumFieldValue(c2, str, r4.name());
        } else if (this.writeEnumUsingToString) {
            writeEnumFieldValue(c2, str, r4.toString());
        } else {
            writeFieldValue(c2, str, r4.ordinal());
        }
    }

    public void writeFieldValue(char c2, String str, BigDecimal bigDecimal) {
        String bigDecimal2;
        write(c2);
        writeFieldName(str);
        if (bigDecimal == null) {
            writeNull();
            return;
        }
        int scale = bigDecimal.scale();
        if (isEnabled(SerializerFeature.WriteBigDecimalAsPlain) && scale >= -100 && scale < 100) {
            bigDecimal2 = bigDecimal.toPlainString();
        } else {
            bigDecimal2 = bigDecimal.toString();
        }
        write(bigDecimal2);
    }

    /* JADX WARN: Code restructure failed: missing block: B:177:0x02e7, code lost:
    
        if (r7[r10] == 4) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x042e, code lost:
    
        if (r3 != '>') goto L220;
     */
    /* JADX WARN: Removed duplicated region for block: B:180:0x02f0  */
    /* JADX WARN: Removed duplicated region for block: B:183:0x02f4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void writeStringWithDoubleQuote(char[] r24, char r25) {
        /*
            Method dump skipped, instructions count: 1332
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.alibaba.fastjson.serializer.SerializeWriter.writeStringWithDoubleQuote(char[], char):void");
    }
}
