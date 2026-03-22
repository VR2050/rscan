package com.p397ta.utdid2.p400b.p401a;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;
import kotlin.text.Typography;
import org.xmlpull.v1.XmlSerializer;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: com.ta.utdid2.b.a.a */
/* loaded from: classes2.dex */
public class C4138a implements XmlSerializer {

    /* renamed from: a */
    private OutputStream f10812a;

    /* renamed from: a */
    private Writer f10813a;

    /* renamed from: a */
    private CharsetEncoder f10815a;

    /* renamed from: e */
    private boolean f10817e;
    private int mPos;

    /* renamed from: a */
    private static final String[] f10811a = {null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "&quot;", null, null, null, "&amp;", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "&lt;", null, "&gt;", null};

    /* renamed from: a */
    private static String f10810a = "xmlpull.org/v1/doc/features.html#indent-output";

    /* renamed from: a */
    private final char[] f10816a = new char[8192];

    /* renamed from: a */
    private ByteBuffer f10814a = ByteBuffer.allocate(8192);

    /* renamed from: a */
    private void m4664a(String str, int i2, int i3) {
        if (i3 > 8192) {
            int i4 = i3 + i2;
            while (i2 < i4) {
                int i5 = i2 + 8192;
                m4664a(str, i2, i5 < i4 ? 8192 : i4 - i2);
                i2 = i5;
            }
            return;
        }
        int i6 = this.mPos;
        if (i6 + i3 > 8192) {
            flush();
            i6 = this.mPos;
        }
        str.getChars(i2, i2 + i3, this.f10816a, i6);
        this.mPos = i6 + i3;
    }

    private void append(char c2) {
        int i2 = this.mPos;
        if (i2 >= 8191) {
            flush();
            i2 = this.mPos;
        }
        this.f10816a[i2] = c2;
        this.mPos = i2 + 1;
    }

    /* renamed from: d */
    public static String m4666d() {
        StringBuilder m586H = C1499a.m586H("http://");
        m586H.append(f10810a);
        return m586H.toString();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public XmlSerializer attribute(String str, String str2, String str3) {
        append(' ');
        if (str != null) {
            append(str);
            append(':');
        }
        append(str2);
        append("=\"");
        m4663a(str3);
        append(Typography.quote);
        return this;
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void cdsect(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void comment(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void docdecl(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void endDocument() {
        flush();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public XmlSerializer endTag(String str, String str2) {
        if (this.f10817e) {
            append(" />\n");
        } else {
            append("</");
            if (str != null) {
                append(str);
                append(':');
            }
            append(str2);
            append(">\n");
        }
        this.f10817e = false;
        return this;
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void entityRef(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void flush() {
        int i2 = this.mPos;
        if (i2 > 0) {
            if (this.f10812a != null) {
                CharBuffer wrap = CharBuffer.wrap(this.f10816a, 0, i2);
                CoderResult encode = this.f10815a.encode(wrap, this.f10814a, true);
                while (!encode.isError()) {
                    if (encode.isOverflow()) {
                        m4662a();
                        encode = this.f10815a.encode(wrap, this.f10814a, true);
                    } else {
                        m4662a();
                        this.f10812a.flush();
                    }
                }
                throw new IOException(encode.toString());
            }
            this.f10813a.write(this.f10816a, 0, i2);
            this.f10813a.flush();
            this.mPos = 0;
        }
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public int getDepth() {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public boolean getFeature(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public String getName() {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public String getNamespace() {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public String getPrefix(String str, boolean z) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public Object getProperty(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void ignorableWhitespace(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void processingInstruction(String str) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void setFeature(String str, boolean z) {
        if (!str.equals(m4666d())) {
            throw new UnsupportedOperationException();
        }
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void setOutput(OutputStream outputStream, String str) {
        if (outputStream == null) {
            throw new IllegalArgumentException();
        }
        try {
            this.f10815a = Charset.forName(str).newEncoder();
            this.f10812a = outputStream;
        } catch (IllegalCharsetNameException e2) {
            throw ((UnsupportedEncodingException) new UnsupportedEncodingException(str).initCause(e2));
        } catch (UnsupportedCharsetException e3) {
            throw ((UnsupportedEncodingException) new UnsupportedEncodingException(str).initCause(e3));
        }
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void setPrefix(String str, String str2) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void setProperty(String str, Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void startDocument(String str, Boolean bool) {
        append(C1499a.m582D(C1499a.m586H("<?xml version='1.0' encoding='utf-8' standalone='"), bool.booleanValue() ? "yes" : "no", "' ?>\n"));
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public XmlSerializer startTag(String str, String str2) {
        if (this.f10817e) {
            append(">\n");
        }
        append(Typography.less);
        if (str != null) {
            append(str);
            append(':');
        }
        append(str2);
        this.f10817e = true;
        return this;
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public XmlSerializer text(char[] cArr, int i2, int i3) {
        if (this.f10817e) {
            append(">");
            this.f10817e = false;
        }
        m4665a(cArr, i2, i3);
        return this;
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public XmlSerializer text(String str) {
        if (this.f10817e) {
            append(">");
            this.f10817e = false;
        }
        m4663a(str);
        return this;
    }

    private void append(char[] cArr, int i2, int i3) {
        if (i3 > 8192) {
            int i4 = i3 + i2;
            while (i2 < i4) {
                int i5 = i2 + 8192;
                append(cArr, i2, i5 < i4 ? 8192 : i4 - i2);
                i2 = i5;
            }
            return;
        }
        int i6 = this.mPos;
        if (i6 + i3 > 8192) {
            flush();
            i6 = this.mPos;
        }
        System.arraycopy(cArr, i2, this.f10816a, i6, i3);
        this.mPos = i6 + i3;
    }

    /* renamed from: a */
    private void m4663a(String str) {
        String str2;
        int length = str.length();
        String[] strArr = f10811a;
        char length2 = (char) strArr.length;
        int i2 = 0;
        int i3 = 0;
        while (i2 < length) {
            char charAt = str.charAt(i2);
            if (charAt < length2 && (str2 = strArr[charAt]) != null) {
                if (i3 < i2) {
                    m4664a(str, i3, i2 - i3);
                }
                i3 = i2 + 1;
                append(str2);
            }
            i2++;
        }
        if (i3 < i2) {
            m4664a(str, i3, i2 - i3);
        }
    }

    @Override // org.xmlpull.v1.XmlSerializer
    public void setOutput(Writer writer) {
        this.f10813a = writer;
    }

    private void append(String str) {
        m4664a(str, 0, str.length());
    }

    /* renamed from: a */
    private void m4665a(char[] cArr, int i2, int i3) {
        String str;
        String[] strArr = f10811a;
        char length = (char) strArr.length;
        int i4 = i3 + i2;
        int i5 = i2;
        while (i2 < i4) {
            char c2 = cArr[i2];
            if (c2 < length && (str = strArr[c2]) != null) {
                if (i5 < i2) {
                    append(cArr, i5, i2 - i5);
                }
                i5 = i2 + 1;
                append(str);
            }
            i2++;
        }
        if (i5 < i2) {
            append(cArr, i5, i2 - i5);
        }
    }

    /* renamed from: a */
    private void m4662a() {
        int position = this.f10814a.position();
        if (position > 0) {
            this.f10814a.flip();
            this.f10812a.write(this.f10814a.array(), 0, position);
            this.f10814a.clear();
        }
    }
}
