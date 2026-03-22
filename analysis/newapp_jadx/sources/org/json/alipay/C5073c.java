package org.json.alipay;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: org.json.alipay.c */
/* loaded from: classes3.dex */
public final class C5073c {

    /* renamed from: a */
    private int f12996a;

    /* renamed from: b */
    private Reader f12997b;

    /* renamed from: c */
    private char f12998c;

    /* renamed from: d */
    private boolean f12999d;

    private C5073c(Reader reader) {
        this.f12997b = reader.markSupported() ? reader : new BufferedReader(reader);
        this.f12999d = false;
        this.f12996a = 0;
    }

    public C5073c(String str) {
        this(new StringReader(str));
    }

    /* renamed from: a */
    private String m5708a(int i2) {
        if (i2 == 0) {
            return "";
        }
        char[] cArr = new char[i2];
        int i3 = 0;
        if (this.f12999d) {
            this.f12999d = false;
            cArr[0] = this.f12998c;
            i3 = 1;
        }
        while (i3 < i2) {
            try {
                int read = this.f12997b.read(cArr, i3, i2 - i3);
                if (read == -1) {
                    break;
                }
                i3 += read;
            } catch (IOException e2) {
                throw new JSONException(e2);
            }
        }
        this.f12996a += i3;
        if (i3 < i2) {
            throw m5709a("Substring bounds error");
        }
        this.f12998c = cArr[i2 - 1];
        return new String(cArr);
    }

    /* renamed from: a */
    public final JSONException m5709a(String str) {
        StringBuilder m586H = C1499a.m586H(str);
        m586H.append(toString());
        return new JSONException(m586H.toString());
    }

    /* renamed from: a */
    public final void m5710a() {
        int i2;
        if (this.f12999d || (i2 = this.f12996a) <= 0) {
            throw new JSONException("Stepping back two steps is not supported");
        }
        this.f12996a = i2 - 1;
        this.f12999d = true;
    }

    /* renamed from: b */
    public final char m5711b() {
        if (this.f12999d) {
            this.f12999d = false;
            char c2 = this.f12998c;
            if (c2 != 0) {
                this.f12996a++;
            }
            return c2;
        }
        try {
            int read = this.f12997b.read();
            if (read <= 0) {
                this.f12998c = (char) 0;
                return (char) 0;
            }
            this.f12996a++;
            char c3 = (char) read;
            this.f12998c = c3;
            return c3;
        } catch (IOException e2) {
            throw new JSONException(e2);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0053, code lost:
    
        return r0;
     */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final char m5712c() {
        /*
            r5 = this;
        L0:
            char r0 = r5.m5711b()
            r1 = 13
            r2 = 10
            r3 = 47
            if (r0 != r3) goto L3e
            char r0 = r5.m5711b()
            r4 = 42
            if (r0 == r4) goto L25
            if (r0 == r3) goto L1a
            r5.m5710a()
            return r3
        L1a:
            char r0 = r5.m5711b()
            if (r0 == r2) goto L0
            if (r0 == r1) goto L0
            if (r0 != 0) goto L1a
            goto L0
        L25:
            char r0 = r5.m5711b()
            if (r0 == 0) goto L37
            if (r0 != r4) goto L25
            char r0 = r5.m5711b()
            if (r0 == r3) goto L0
            r5.m5710a()
            goto L25
        L37:
            java.lang.String r0 = "Unclosed comment"
            org.json.alipay.JSONException r0 = r5.m5709a(r0)
            throw r0
        L3e:
            r3 = 35
            if (r0 != r3) goto L4d
        L42:
            char r0 = r5.m5711b()
            if (r0 == r2) goto L0
            if (r0 == r1) goto L0
            if (r0 != 0) goto L42
            goto L0
        L4d:
            if (r0 == 0) goto L53
            r1 = 32
            if (r0 <= r1) goto L0
        L53:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.json.alipay.C5073c.m5712c():char");
    }

    /* JADX WARN: Code restructure failed: missing block: B:125:0x0146, code lost:
    
        throw m5709a("Unterminated string");
     */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object m5713d() {
        /*
            Method dump skipped, instructions count: 327
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.json.alipay.C5073c.m5713d():java.lang.Object");
    }

    public final String toString() {
        return " at character " + this.f12996a;
    }
}
