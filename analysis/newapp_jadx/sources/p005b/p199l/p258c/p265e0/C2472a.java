package p005b.p199l.p258c.p265e0;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.Reader;
import java.util.Objects;
import kotlin.text.Typography;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.p260c0.AbstractC2459q;

/* renamed from: b.l.c.e0.a */
/* loaded from: classes2.dex */
public class C2472a implements Closeable {

    /* renamed from: c */
    public static final char[] f6639c = ")]}'\n".toCharArray();

    /* renamed from: e */
    public final Reader f6640e;

    /* renamed from: f */
    public boolean f6641f = false;

    /* renamed from: g */
    public final char[] f6642g = new char[1024];

    /* renamed from: h */
    public int f6643h = 0;

    /* renamed from: i */
    public int f6644i = 0;

    /* renamed from: j */
    public int f6645j = 0;

    /* renamed from: k */
    public int f6646k = 0;

    /* renamed from: l */
    public int f6647l = 0;

    /* renamed from: m */
    public long f6648m;

    /* renamed from: n */
    public int f6649n;

    /* renamed from: o */
    public String f6650o;

    /* renamed from: p */
    public int[] f6651p;

    /* renamed from: q */
    public int f6652q;

    /* renamed from: r */
    public String[] f6653r;

    /* renamed from: s */
    public int[] f6654s;

    /* renamed from: b.l.c.e0.a$a */
    public static class a extends AbstractC2459q {
    }

    static {
        AbstractC2459q.f6608a = new a();
    }

    public C2472a(Reader reader) {
        int[] iArr = new int[32];
        this.f6651p = iArr;
        this.f6652q = 0;
        this.f6652q = 0 + 1;
        iArr[0] = 6;
        this.f6653r = new String[32];
        this.f6654s = new int[32];
        Objects.requireNonNull(reader, "in == null");
        this.f6640e = reader;
    }

    /* renamed from: C */
    public String m2826C() {
        StringBuilder m589K = C1499a.m589K(" at line ", this.f6645j + 1, " column ", (this.f6643h - this.f6646k) + 1, " path ");
        m589K.append(getPath());
        return m589K.toString();
    }

    /* renamed from: D */
    public boolean mo2770D() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 5) {
            this.f6647l = 0;
            int[] iArr = this.f6654s;
            int i3 = this.f6652q - 1;
            iArr[i3] = iArr[i3] + 1;
            return true;
        }
        if (i2 != 6) {
            StringBuilder m586H = C1499a.m586H("Expected a boolean but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
        this.f6647l = 0;
        int[] iArr2 = this.f6654s;
        int i4 = this.f6652q - 1;
        iArr2[i4] = iArr2[i4] + 1;
        return false;
    }

    /* renamed from: E */
    public double mo2771E() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 15) {
            this.f6647l = 0;
            int[] iArr = this.f6654s;
            int i3 = this.f6652q - 1;
            iArr[i3] = iArr[i3] + 1;
            return this.f6648m;
        }
        if (i2 == 16) {
            this.f6650o = new String(this.f6642g, this.f6643h, this.f6649n);
            this.f6643h += this.f6649n;
        } else if (i2 == 8 || i2 == 9) {
            this.f6650o = m2828W(i2 == 8 ? '\'' : Typography.quote);
        } else if (i2 == 10) {
            this.f6650o = m2829Y();
        } else if (i2 != 11) {
            StringBuilder m586H = C1499a.m586H("Expected a double but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
        this.f6647l = 11;
        double parseDouble = Double.parseDouble(this.f6650o);
        if (!this.f6641f && (Double.isNaN(parseDouble) || Double.isInfinite(parseDouble))) {
            throw new C2475d("JSON forbids NaN and infinities: " + parseDouble + m2826C());
        }
        this.f6650o = null;
        this.f6647l = 0;
        int[] iArr2 = this.f6654s;
        int i4 = this.f6652q - 1;
        iArr2[i4] = iArr2[i4] + 1;
        return parseDouble;
    }

    /* renamed from: I */
    public int mo2772I() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 15) {
            long j2 = this.f6648m;
            int i3 = (int) j2;
            if (j2 != i3) {
                StringBuilder m586H = C1499a.m586H("Expected an int but was ");
                m586H.append(this.f6648m);
                m586H.append(m2826C());
                throw new NumberFormatException(m586H.toString());
            }
            this.f6647l = 0;
            int[] iArr = this.f6654s;
            int i4 = this.f6652q - 1;
            iArr[i4] = iArr[i4] + 1;
            return i3;
        }
        if (i2 == 16) {
            this.f6650o = new String(this.f6642g, this.f6643h, this.f6649n);
            this.f6643h += this.f6649n;
        } else {
            if (i2 != 8 && i2 != 9 && i2 != 10) {
                StringBuilder m586H2 = C1499a.m586H("Expected an int but was ");
                m586H2.append(mo2777Z());
                m586H2.append(m2826C());
                throw new IllegalStateException(m586H2.toString());
            }
            if (i2 == 10) {
                this.f6650o = m2829Y();
            } else {
                this.f6650o = m2828W(i2 == 8 ? '\'' : Typography.quote);
            }
            try {
                int parseInt = Integer.parseInt(this.f6650o);
                this.f6647l = 0;
                int[] iArr2 = this.f6654s;
                int i5 = this.f6652q - 1;
                iArr2[i5] = iArr2[i5] + 1;
                return parseInt;
            } catch (NumberFormatException unused) {
            }
        }
        this.f6647l = 11;
        double parseDouble = Double.parseDouble(this.f6650o);
        int i6 = (int) parseDouble;
        if (i6 != parseDouble) {
            StringBuilder m586H3 = C1499a.m586H("Expected an int but was ");
            m586H3.append(this.f6650o);
            m586H3.append(m2826C());
            throw new NumberFormatException(m586H3.toString());
        }
        this.f6650o = null;
        this.f6647l = 0;
        int[] iArr3 = this.f6654s;
        int i7 = this.f6652q - 1;
        iArr3[i7] = iArr3[i7] + 1;
        return i6;
    }

    /* renamed from: P */
    public long mo2773P() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 15) {
            this.f6647l = 0;
            int[] iArr = this.f6654s;
            int i3 = this.f6652q - 1;
            iArr[i3] = iArr[i3] + 1;
            return this.f6648m;
        }
        if (i2 == 16) {
            this.f6650o = new String(this.f6642g, this.f6643h, this.f6649n);
            this.f6643h += this.f6649n;
        } else {
            if (i2 != 8 && i2 != 9 && i2 != 10) {
                StringBuilder m586H = C1499a.m586H("Expected a long but was ");
                m586H.append(mo2777Z());
                m586H.append(m2826C());
                throw new IllegalStateException(m586H.toString());
            }
            if (i2 == 10) {
                this.f6650o = m2829Y();
            } else {
                this.f6650o = m2828W(i2 == 8 ? '\'' : Typography.quote);
            }
            try {
                long parseLong = Long.parseLong(this.f6650o);
                this.f6647l = 0;
                int[] iArr2 = this.f6654s;
                int i4 = this.f6652q - 1;
                iArr2[i4] = iArr2[i4] + 1;
                return parseLong;
            } catch (NumberFormatException unused) {
            }
        }
        this.f6647l = 11;
        double parseDouble = Double.parseDouble(this.f6650o);
        long j2 = (long) parseDouble;
        if (j2 != parseDouble) {
            StringBuilder m586H2 = C1499a.m586H("Expected a long but was ");
            m586H2.append(this.f6650o);
            m586H2.append(m2826C());
            throw new NumberFormatException(m586H2.toString());
        }
        this.f6650o = null;
        this.f6647l = 0;
        int[] iArr3 = this.f6654s;
        int i5 = this.f6652q - 1;
        iArr3[i5] = iArr3[i5] + 1;
        return j2;
    }

    /* renamed from: S */
    public String mo2774S() {
        String m2828W;
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 14) {
            m2828W = m2829Y();
        } else if (i2 == 12) {
            m2828W = m2828W('\'');
        } else {
            if (i2 != 13) {
                StringBuilder m586H = C1499a.m586H("Expected a name but was ");
                m586H.append(mo2777Z());
                m586H.append(m2826C());
                throw new IllegalStateException(m586H.toString());
            }
            m2828W = m2828W(Typography.quote);
        }
        this.f6647l = 0;
        this.f6653r[this.f6652q - 1] = m2828W;
        return m2828W;
    }

    /* renamed from: U */
    public final int m2827U(boolean z) {
        char[] cArr = this.f6642g;
        int i2 = this.f6643h;
        int i3 = this.f6644i;
        while (true) {
            boolean z2 = true;
            if (i2 == i3) {
                this.f6643h = i2;
                if (!m2837s(1)) {
                    if (!z) {
                        return -1;
                    }
                    StringBuilder m586H = C1499a.m586H("End of input");
                    m586H.append(m2826C());
                    throw new EOFException(m586H.toString());
                }
                i2 = this.f6643h;
                i3 = this.f6644i;
            }
            int i4 = i2 + 1;
            char c2 = cArr[i2];
            if (c2 == '\n') {
                this.f6645j++;
                this.f6646k = i4;
            } else if (c2 != ' ' && c2 != '\r' && c2 != '\t') {
                if (c2 == '/') {
                    this.f6643h = i4;
                    if (i4 == i3) {
                        this.f6643h = i4 - 1;
                        boolean m2837s = m2837s(2);
                        this.f6643h++;
                        if (!m2837s) {
                            return c2;
                        }
                    }
                    m2834e();
                    int i5 = this.f6643h;
                    char c3 = cArr[i5];
                    if (c3 == '*') {
                        this.f6643h = i5 + 1;
                        while (true) {
                            if (this.f6643h + 2 > this.f6644i && !m2837s(2)) {
                                z2 = false;
                                break;
                            }
                            char[] cArr2 = this.f6642g;
                            int i6 = this.f6643h;
                            if (cArr2[i6] != '\n') {
                                for (int i7 = 0; i7 < 2; i7++) {
                                    if (this.f6642g[this.f6643h + i7] != "*/".charAt(i7)) {
                                        break;
                                    }
                                }
                                break;
                            }
                            this.f6645j++;
                            this.f6646k = i6 + 1;
                            this.f6643h++;
                        }
                        if (!z2) {
                            m2835f0("Unterminated comment");
                            throw null;
                        }
                        i2 = this.f6643h + 2;
                        i3 = this.f6644i;
                    } else {
                        if (c3 != '/') {
                            return c2;
                        }
                        this.f6643h = i5 + 1;
                        m2833d0();
                        i2 = this.f6643h;
                        i3 = this.f6644i;
                    }
                } else {
                    if (c2 != '#') {
                        this.f6643h = i4;
                        return c2;
                    }
                    this.f6643h = i4;
                    m2834e();
                    m2833d0();
                    i2 = this.f6643h;
                    i3 = this.f6644i;
                }
            }
            i2 = i4;
        }
    }

    /* renamed from: V */
    public void mo2775V() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 != 7) {
            StringBuilder m586H = C1499a.m586H("Expected null but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
        this.f6647l = 0;
        int[] iArr = this.f6654s;
        int i3 = this.f6652q - 1;
        iArr[i3] = iArr[i3] + 1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x005d, code lost:
    
        if (r2 != null) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x005f, code lost:
    
        r2 = new java.lang.StringBuilder(java.lang.Math.max((r3 - r4) * 2, 16));
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x006d, code lost:
    
        r2.append(r0, r4, r3 - r4);
        r10.f6643h = r3;
     */
    /* renamed from: W */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String m2828W(char r11) {
        /*
            r10 = this;
            char[] r0 = r10.f6642g
            r1 = 0
            r2 = r1
        L4:
            int r3 = r10.f6643h
            int r4 = r10.f6644i
        L8:
            r5 = r4
            r4 = r3
        La:
            r6 = 16
            r7 = 1
            if (r3 >= r5) goto L5d
            int r8 = r3 + 1
            char r3 = r0[r3]
            if (r3 != r11) goto L29
            r10.f6643h = r8
            int r8 = r8 - r4
            int r8 = r8 - r7
            if (r2 != 0) goto L21
            java.lang.String r11 = new java.lang.String
            r11.<init>(r0, r4, r8)
            return r11
        L21:
            r2.append(r0, r4, r8)
            java.lang.String r11 = r2.toString()
            return r11
        L29:
            r9 = 92
            if (r3 != r9) goto L50
            r10.f6643h = r8
            int r8 = r8 - r4
            int r8 = r8 - r7
            if (r2 != 0) goto L41
            int r2 = r8 + 1
            int r2 = r2 * 2
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            int r2 = java.lang.Math.max(r2, r6)
            r3.<init>(r2)
            r2 = r3
        L41:
            r2.append(r0, r4, r8)
            char r3 = r10.m2831b0()
            r2.append(r3)
            int r3 = r10.f6643h
            int r4 = r10.f6644i
            goto L8
        L50:
            r6 = 10
            if (r3 != r6) goto L5b
            int r3 = r10.f6645j
            int r3 = r3 + r7
            r10.f6645j = r3
            r10.f6646k = r8
        L5b:
            r3 = r8
            goto La
        L5d:
            if (r2 != 0) goto L6d
            int r2 = r3 - r4
            int r2 = r2 * 2
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            int r2 = java.lang.Math.max(r2, r6)
            r5.<init>(r2)
            r2 = r5
        L6d:
            int r5 = r3 - r4
            r2.append(r0, r4, r5)
            r10.f6643h = r3
            boolean r3 = r10.m2837s(r7)
            if (r3 == 0) goto L7b
            goto L4
        L7b:
            java.lang.String r11 = "Unterminated string"
            r10.m2835f0(r11)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.p265e0.C2472a.m2828W(char):java.lang.String");
    }

    /* renamed from: X */
    public String mo2776X() {
        String str;
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 10) {
            str = m2829Y();
        } else if (i2 == 8) {
            str = m2828W('\'');
        } else if (i2 == 9) {
            str = m2828W(Typography.quote);
        } else if (i2 == 11) {
            str = this.f6650o;
            this.f6650o = null;
        } else if (i2 == 15) {
            str = Long.toString(this.f6648m);
        } else {
            if (i2 != 16) {
                StringBuilder m586H = C1499a.m586H("Expected a string but was ");
                m586H.append(mo2777Z());
                m586H.append(m2826C());
                throw new IllegalStateException(m586H.toString());
            }
            str = new String(this.f6642g, this.f6643h, this.f6649n);
            this.f6643h += this.f6649n;
        }
        this.f6647l = 0;
        int[] iArr = this.f6654s;
        int i3 = this.f6652q - 1;
        iArr[i3] = iArr[i3] + 1;
        return str;
    }

    /* JADX WARN: Code restructure failed: missing block: B:58:0x004a, code lost:
    
        m2834e();
     */
    /* JADX WARN: Failed to find 'out' block for switch in B:54:0x0044. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x008a  */
    /* renamed from: Y */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String m2829Y() {
        /*
            r6 = this;
            r0 = 0
            r1 = 0
        L2:
            r2 = 0
        L3:
            int r3 = r6.f6643h
            int r4 = r3 + r2
            int r5 = r6.f6644i
            if (r4 >= r5) goto L4e
            char[] r4 = r6.f6642g
            int r3 = r3 + r2
            char r3 = r4[r3]
            r4 = 9
            if (r3 == r4) goto L5c
            r4 = 10
            if (r3 == r4) goto L5c
            r4 = 12
            if (r3 == r4) goto L5c
            r4 = 13
            if (r3 == r4) goto L5c
            r4 = 32
            if (r3 == r4) goto L5c
            r4 = 35
            if (r3 == r4) goto L4a
            r4 = 44
            if (r3 == r4) goto L5c
            r4 = 47
            if (r3 == r4) goto L4a
            r4 = 61
            if (r3 == r4) goto L4a
            r4 = 123(0x7b, float:1.72E-43)
            if (r3 == r4) goto L5c
            r4 = 125(0x7d, float:1.75E-43)
            if (r3 == r4) goto L5c
            r4 = 58
            if (r3 == r4) goto L5c
            r4 = 59
            if (r3 == r4) goto L4a
            switch(r3) {
                case 91: goto L5c;
                case 92: goto L4a;
                case 93: goto L5c;
                default: goto L47;
            }
        L47:
            int r2 = r2 + 1
            goto L3
        L4a:
            r6.m2834e()
            goto L5c
        L4e:
            char[] r3 = r6.f6642g
            int r3 = r3.length
            if (r2 >= r3) goto L5e
            int r3 = r2 + 1
            boolean r3 = r6.m2837s(r3)
            if (r3 == 0) goto L5c
            goto L3
        L5c:
            r0 = r2
            goto L7e
        L5e:
            if (r1 != 0) goto L6b
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r3 = 16
            int r3 = java.lang.Math.max(r2, r3)
            r1.<init>(r3)
        L6b:
            char[] r3 = r6.f6642g
            int r4 = r6.f6643h
            r1.append(r3, r4, r2)
            int r3 = r6.f6643h
            int r3 = r3 + r2
            r6.f6643h = r3
            r2 = 1
            boolean r2 = r6.m2837s(r2)
            if (r2 != 0) goto L2
        L7e:
            if (r1 != 0) goto L8a
            java.lang.String r1 = new java.lang.String
            char[] r2 = r6.f6642g
            int r3 = r6.f6643h
            r1.<init>(r2, r3, r0)
            goto L95
        L8a:
            char[] r2 = r6.f6642g
            int r3 = r6.f6643h
            r1.append(r2, r3, r0)
            java.lang.String r1 = r1.toString()
        L95:
            int r2 = r6.f6643h
            int r2 = r2 + r0
            r6.f6643h = r2
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.p265e0.C2472a.m2829Y():java.lang.String");
    }

    /* renamed from: Z */
    public EnumC2473b mo2777Z() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        switch (i2) {
            case 1:
                return EnumC2473b.BEGIN_OBJECT;
            case 2:
                return EnumC2473b.END_OBJECT;
            case 3:
                return EnumC2473b.BEGIN_ARRAY;
            case 4:
                return EnumC2473b.END_ARRAY;
            case 5:
            case 6:
                return EnumC2473b.BOOLEAN;
            case 7:
                return EnumC2473b.NULL;
            case 8:
            case 9:
            case 10:
            case 11:
                return EnumC2473b.STRING;
            case 12:
            case 13:
            case 14:
                return EnumC2473b.NAME;
            case 15:
            case 16:
                return EnumC2473b.NUMBER;
            case 17:
                return EnumC2473b.END_DOCUMENT;
            default:
                throw new AssertionError();
        }
    }

    /* renamed from: a0 */
    public final void m2830a0(int i2) {
        int i3 = this.f6652q;
        int[] iArr = this.f6651p;
        if (i3 == iArr.length) {
            int[] iArr2 = new int[i3 * 2];
            int[] iArr3 = new int[i3 * 2];
            String[] strArr = new String[i3 * 2];
            System.arraycopy(iArr, 0, iArr2, 0, i3);
            System.arraycopy(this.f6654s, 0, iArr3, 0, this.f6652q);
            System.arraycopy(this.f6653r, 0, strArr, 0, this.f6652q);
            this.f6651p = iArr2;
            this.f6654s = iArr3;
            this.f6653r = strArr;
        }
        int[] iArr4 = this.f6651p;
        int i4 = this.f6652q;
        this.f6652q = i4 + 1;
        iArr4[i4] = i2;
    }

    /* renamed from: b */
    public void mo2778b() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 3) {
            m2830a0(1);
            this.f6654s[this.f6652q - 1] = 0;
            this.f6647l = 0;
        } else {
            StringBuilder m586H = C1499a.m586H("Expected BEGIN_ARRAY but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
    }

    /* renamed from: b0 */
    public final char m2831b0() {
        int i2;
        int i3;
        if (this.f6643h == this.f6644i && !m2837s(1)) {
            m2835f0("Unterminated escape sequence");
            throw null;
        }
        char[] cArr = this.f6642g;
        int i4 = this.f6643h;
        int i5 = i4 + 1;
        this.f6643h = i5;
        char c2 = cArr[i4];
        if (c2 == '\n') {
            this.f6645j++;
            this.f6646k = i5;
        } else if (c2 != '\"' && c2 != '\'' && c2 != '/' && c2 != '\\') {
            if (c2 == 'b') {
                return '\b';
            }
            if (c2 == 'f') {
                return '\f';
            }
            if (c2 == 'n') {
                return '\n';
            }
            if (c2 == 'r') {
                return '\r';
            }
            if (c2 == 't') {
                return '\t';
            }
            if (c2 != 'u') {
                m2835f0("Invalid escape sequence");
                throw null;
            }
            if (i5 + 4 > this.f6644i && !m2837s(4)) {
                m2835f0("Unterminated escape sequence");
                throw null;
            }
            char c3 = 0;
            int i6 = this.f6643h;
            int i7 = i6 + 4;
            while (i6 < i7) {
                char c4 = this.f6642g[i6];
                char c5 = (char) (c3 << 4);
                if (c4 < '0' || c4 > '9') {
                    if (c4 >= 'a' && c4 <= 'f') {
                        i2 = c4 - 'a';
                    } else {
                        if (c4 < 'A' || c4 > 'F') {
                            StringBuilder m586H = C1499a.m586H("\\u");
                            m586H.append(new String(this.f6642g, this.f6643h, 4));
                            throw new NumberFormatException(m586H.toString());
                        }
                        i2 = c4 - 'A';
                    }
                    i3 = i2 + 10;
                } else {
                    i3 = c4 - '0';
                }
                c3 = (char) (i3 + c5);
                i6++;
            }
            this.f6643h += 4;
            return c3;
        }
        return c2;
    }

    /* renamed from: c0 */
    public final void m2832c0(char c2) {
        char[] cArr = this.f6642g;
        do {
            int i2 = this.f6643h;
            int i3 = this.f6644i;
            while (i2 < i3) {
                int i4 = i2 + 1;
                char c3 = cArr[i2];
                if (c3 == c2) {
                    this.f6643h = i4;
                    return;
                }
                if (c3 == '\\') {
                    this.f6643h = i4;
                    m2831b0();
                    i2 = this.f6643h;
                    i3 = this.f6644i;
                } else {
                    if (c3 == '\n') {
                        this.f6645j++;
                        this.f6646k = i4;
                    }
                    i2 = i4;
                }
            }
            this.f6643h = i2;
        } while (m2837s(1));
        m2835f0("Unterminated string");
        throw null;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f6647l = 0;
        this.f6651p[0] = 8;
        this.f6652q = 1;
        this.f6640e.close();
    }

    /* renamed from: d */
    public void mo2779d() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 == 1) {
            m2830a0(3);
            this.f6647l = 0;
        } else {
            StringBuilder m586H = C1499a.m586H("Expected BEGIN_OBJECT but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
    }

    /* renamed from: d0 */
    public final void m2833d0() {
        char c2;
        do {
            if (this.f6643h >= this.f6644i && !m2837s(1)) {
                return;
            }
            char[] cArr = this.f6642g;
            int i2 = this.f6643h;
            int i3 = i2 + 1;
            this.f6643h = i3;
            c2 = cArr[i2];
            if (c2 == '\n') {
                this.f6645j++;
                this.f6646k = i3;
                return;
            }
        } while (c2 != '\r');
    }

    /* renamed from: e */
    public final void m2834e() {
        if (this.f6641f) {
            return;
        }
        m2835f0("Use JsonReader.setLenient(true) to accept malformed JSON");
        throw null;
    }

    /* JADX WARN: Failed to find 'out' block for switch in B:65:0x009b. Please report as an issue. */
    /* renamed from: e0 */
    public void mo2780e0() {
        int i2 = 0;
        do {
            int i3 = this.f6647l;
            if (i3 == 0) {
                i3 = m2836k();
            }
            if (i3 == 3) {
                m2830a0(1);
            } else if (i3 == 1) {
                m2830a0(3);
            } else {
                if (i3 == 4) {
                    this.f6652q--;
                } else if (i3 == 2) {
                    this.f6652q--;
                } else {
                    if (i3 == 14 || i3 == 10) {
                        do {
                            int i4 = 0;
                            while (true) {
                                int i5 = this.f6643h + i4;
                                if (i5 < this.f6644i) {
                                    char c2 = this.f6642g[i5];
                                    if (c2 != '\t' && c2 != '\n' && c2 != '\f' && c2 != '\r' && c2 != ' ') {
                                        if (c2 != '#') {
                                            if (c2 != ',') {
                                                if (c2 != '/' && c2 != '=') {
                                                    if (c2 != '{' && c2 != '}' && c2 != ':') {
                                                        if (c2 != ';') {
                                                            switch (c2) {
                                                                case '[':
                                                                case ']':
                                                                    break;
                                                                case '\\':
                                                                    break;
                                                                default:
                                                                    i4++;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    this.f6643h = i5;
                                }
                            }
                            m2834e();
                            this.f6643h += i4;
                        } while (m2837s(1));
                    } else if (i3 == 8 || i3 == 12) {
                        m2832c0('\'');
                    } else if (i3 == 9 || i3 == 13) {
                        m2832c0(Typography.quote);
                    } else if (i3 == 16) {
                        this.f6643h += this.f6649n;
                    }
                    this.f6647l = 0;
                }
                i2--;
                this.f6647l = 0;
            }
            i2++;
            this.f6647l = 0;
        } while (i2 != 0);
        int[] iArr = this.f6654s;
        int i6 = this.f6652q;
        int i7 = i6 - 1;
        iArr[i7] = iArr[i7] + 1;
        this.f6653r[i6 - 1] = "null";
    }

    /* renamed from: f0 */
    public final IOException m2835f0(String str) {
        StringBuilder m586H = C1499a.m586H(str);
        m586H.append(m2826C());
        throw new C2475d(m586H.toString());
    }

    public String getPath() {
        StringBuilder m584F = C1499a.m584F(Typography.dollar);
        int i2 = this.f6652q;
        for (int i3 = 0; i3 < i2; i3++) {
            int i4 = this.f6651p[i3];
            if (i4 == 1 || i4 == 2) {
                m584F.append('[');
                m584F.append(this.f6654s[i3]);
                m584F.append(']');
            } else if (i4 == 3 || i4 == 4 || i4 == 5) {
                m584F.append('.');
                String[] strArr = this.f6653r;
                if (strArr[i3] != null) {
                    m584F.append(strArr[i3]);
                }
            }
        }
        return m584F.toString();
    }

    /* JADX WARN: Code restructure failed: missing block: B:107:0x0203, code lost:
    
        if (m2838v(r6) != false) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0205, code lost:
    
        if (r13 != 2) goto L171;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0207, code lost:
    
        if (r15 == false) goto L171;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x020d, code lost:
    
        if (r10 != Long.MIN_VALUE) goto L164;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x020f, code lost:
    
        if (r16 == false) goto L171;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0215, code lost:
    
        if (r10 != 0) goto L167;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0217, code lost:
    
        if (r16 != false) goto L171;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0219, code lost:
    
        if (r16 == false) goto L169;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x021c, code lost:
    
        r10 = -r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x021d, code lost:
    
        r19.f6648m = r10;
        r19.f6643h += r9;
        r6 = 15;
        r19.f6647l = 15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0229, code lost:
    
        if (r13 == 2) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x022c, code lost:
    
        if (r13 == 4) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x022f, code lost:
    
        if (r13 != 7) goto L113;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0231, code lost:
    
        r19.f6649n = r9;
        r6 = 16;
        r19.f6647l = 16;
     */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0174 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0264 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0265  */
    /* renamed from: k */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int m2836k() {
        /*
            Method dump skipped, instructions count: 793
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.p265e0.C2472a.m2836k():int");
    }

    /* renamed from: o */
    public void mo2785o() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 != 4) {
            StringBuilder m586H = C1499a.m586H("Expected END_ARRAY but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
        int i3 = this.f6652q - 1;
        this.f6652q = i3;
        int[] iArr = this.f6654s;
        int i4 = i3 - 1;
        iArr[i4] = iArr[i4] + 1;
        this.f6647l = 0;
    }

    /* renamed from: q */
    public void mo2786q() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        if (i2 != 2) {
            StringBuilder m586H = C1499a.m586H("Expected END_OBJECT but was ");
            m586H.append(mo2777Z());
            m586H.append(m2826C());
            throw new IllegalStateException(m586H.toString());
        }
        int i3 = this.f6652q - 1;
        this.f6652q = i3;
        this.f6653r[i3] = null;
        int[] iArr = this.f6654s;
        int i4 = i3 - 1;
        iArr[i4] = iArr[i4] + 1;
        this.f6647l = 0;
    }

    /* renamed from: s */
    public final boolean m2837s(int i2) {
        int i3;
        int i4;
        char[] cArr = this.f6642g;
        int i5 = this.f6646k;
        int i6 = this.f6643h;
        this.f6646k = i5 - i6;
        int i7 = this.f6644i;
        if (i7 != i6) {
            int i8 = i7 - i6;
            this.f6644i = i8;
            System.arraycopy(cArr, i6, cArr, 0, i8);
        } else {
            this.f6644i = 0;
        }
        this.f6643h = 0;
        do {
            Reader reader = this.f6640e;
            int i9 = this.f6644i;
            int read = reader.read(cArr, i9, cArr.length - i9);
            if (read == -1) {
                return false;
            }
            i3 = this.f6644i + read;
            this.f6644i = i3;
            if (this.f6645j == 0 && (i4 = this.f6646k) == 0 && i3 > 0 && cArr[0] == 65279) {
                this.f6643h++;
                this.f6646k = i4 + 1;
                i2++;
            }
        } while (i3 < i2);
        return true;
    }

    /* renamed from: t */
    public boolean mo2787t() {
        int i2 = this.f6647l;
        if (i2 == 0) {
            i2 = m2836k();
        }
        return (i2 == 2 || i2 == 4) ? false : true;
    }

    public String toString() {
        return getClass().getSimpleName() + m2826C();
    }

    /* renamed from: v */
    public final boolean m2838v(char c2) {
        if (c2 == '\t' || c2 == '\n' || c2 == '\f' || c2 == '\r' || c2 == ' ') {
            return false;
        }
        if (c2 != '#') {
            if (c2 == ',') {
                return false;
            }
            if (c2 != '/' && c2 != '=') {
                if (c2 == '{' || c2 == '}' || c2 == ':') {
                    return false;
                }
                if (c2 != ';') {
                    switch (c2) {
                        case '[':
                        case ']':
                            return false;
                        case '\\':
                            break;
                        default:
                            return true;
                    }
                }
            }
        }
        m2834e();
        return false;
    }
}
