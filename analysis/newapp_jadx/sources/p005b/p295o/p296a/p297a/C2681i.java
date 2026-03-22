package p005b.p295o.p296a.p297a;

import java.io.Reader;
import java.util.Hashtable;
import java.util.Objects;
import kotlin.text.Typography;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.o.a.a.i */
/* loaded from: classes2.dex */
public class C2681i implements InterfaceC2684l {

    /* renamed from: b */
    public static final char[] f7299b = {'.', '-', '_', ':'};

    /* renamed from: c */
    public static final boolean[] f7300c = new boolean[128];

    /* renamed from: d */
    public static final char[] f7301d;

    /* renamed from: e */
    public static final char[] f7302e;

    /* renamed from: f */
    public static final char[] f7303f;

    /* renamed from: g */
    public static final char[] f7304g;

    /* renamed from: h */
    public static final char[] f7305h;

    /* renamed from: i */
    public static final char[] f7306i;

    /* renamed from: j */
    public static final char[] f7307j;

    /* renamed from: k */
    public static final char[] f7308k;

    /* renamed from: l */
    public static final char[] f7309l;

    /* renamed from: m */
    public static final char[] f7310m;

    /* renamed from: n */
    public static final char[] f7311n;

    /* renamed from: o */
    public static final char[] f7312o;

    /* renamed from: p */
    public static final char[] f7313p;

    /* renamed from: q */
    public static final char[] f7314q;

    /* renamed from: r */
    public static final char[] f7315r;

    /* renamed from: s */
    public static final char[] f7316s;

    /* renamed from: t */
    public static final char[] f7317t;

    /* renamed from: u */
    public static final char[] f7318u;

    /* renamed from: v */
    public static final char[] f7319v;

    /* renamed from: A */
    public final Hashtable f7320A;

    /* renamed from: B */
    public final C2674b f7321B;

    /* renamed from: C */
    public final String f7322C;

    /* renamed from: D */
    public int f7323D;

    /* renamed from: E */
    public boolean f7324E;

    /* renamed from: F */
    public final char[] f7325F;

    /* renamed from: G */
    public int f7326G;

    /* renamed from: H */
    public int f7327H;

    /* renamed from: I */
    public boolean f7328I;

    /* renamed from: J */
    public final char[] f7329J;

    /* renamed from: K */
    public int f7330K;

    /* renamed from: L */
    public final InterfaceC2683k f7331L;

    /* renamed from: w */
    public String f7332w;

    /* renamed from: x */
    public String f7333x;

    /* renamed from: y */
    public final Reader f7334y;

    /* renamed from: z */
    public final Hashtable f7335z;

    static {
        for (char c2 = 0; c2 < 128; c2 = (char) (c2 + 1)) {
            f7300c[c2] = m3193j(c2);
        }
        f7301d = "<!--".toCharArray();
        f7302e = "-->".toCharArray();
        f7303f = "<?".toCharArray();
        f7304g = "?>".toCharArray();
        f7305h = "<!DOCTYPE".toCharArray();
        f7306i = "<?xml".toCharArray();
        f7307j = "encoding".toCharArray();
        f7308k = "version".toCharArray();
        f7309l = new char[]{'_', '.', ':', '-'};
        f7310m = "<!".toCharArray();
        f7311n = "&#".toCharArray();
        f7312o = "<!ENTITY".toCharArray();
        f7313p = "NDATA".toCharArray();
        f7314q = "SYSTEM".toCharArray();
        f7315r = "PUBLIC".toCharArray();
        f7316s = "<![CDATA[".toCharArray();
        f7317t = "]]>".toCharArray();
        f7318u = "/>".toCharArray();
        f7319v = "</".toCharArray();
    }

    public C2681i(String str, Reader reader, C2674b c2674b, String str2, InterfaceC2683k interfaceC2683k) {
        char[] cArr;
        this.f7333x = null;
        Hashtable hashtable = new Hashtable();
        this.f7335z = hashtable;
        this.f7320A = new Hashtable();
        this.f7323D = -2;
        this.f7324E = false;
        this.f7326G = 0;
        this.f7327H = 0;
        this.f7328I = false;
        this.f7329J = new char[255];
        this.f7330K = -1;
        this.f7330K = 1;
        this.f7321B = c2674b;
        this.f7322C = str2 != null ? str2.toLowerCase() : null;
        hashtable.put("lt", "<");
        hashtable.put("gt", ">");
        hashtable.put("amp", "&");
        hashtable.put("apos", "'");
        hashtable.put("quot", "\"");
        this.f7334y = reader;
        this.f7325F = new char[1024];
        m3200a();
        this.f7332w = str;
        this.f7331L = interfaceC2683k;
        C2673a c2673a = (C2673a) interfaceC2683k;
        c2673a.f7271d = this;
        C2675c c2675c = c2673a.f7270c;
        c2675c.f7273g = str;
        c2675c.mo3170c();
        char[] cArr2 = f7306i;
        if (m3211o(cArr2)) {
            m3199F(cArr2);
            m3198E();
            m3199F(f7308k);
            m3219w();
            char m3214r = m3214r('\'', Typography.quote);
            m3213q();
            while (true) {
                char m3212p = m3212p();
                if (!(Character.isDigit(m3212p) || ('a' <= m3212p && m3212p <= 'z') || (('Z' <= m3212p && m3212p <= 'Z') || m3191g(m3212p, f7309l)))) {
                    break;
                } else {
                    m3213q();
                }
            }
            m3215s(m3214r);
            if (m3210n()) {
                m3198E();
            }
            char[] cArr3 = f7307j;
            if (m3211o(cArr3)) {
                m3199F(cArr3);
                m3219w();
                char m3214r2 = m3214r('\'', Typography.quote);
                StringBuffer stringBuffer = new StringBuffer();
                while (!m3202c(m3214r2)) {
                    stringBuffer.append(m3213q());
                }
                m3215s(m3214r2);
                String stringBuffer2 = stringBuffer.toString();
                if (this.f7322C != null && !stringBuffer2.toLowerCase().equals(this.f7322C)) {
                    throw new C2677e(this.f7332w, stringBuffer2, this.f7322C);
                }
            }
            while (true) {
                cArr = f7304g;
                if (m3211o(cArr)) {
                    break;
                } else {
                    m3213q();
                }
            }
            m3199F(cArr);
        }
        while (m3206i()) {
            m3221y();
        }
        char[] cArr4 = f7305h;
        if (m3211o(cArr4)) {
            m3199F(cArr4);
            m3198E();
            this.f7333x = m3222z();
            if (m3210n()) {
                m3198E();
                if (!m3202c(Typography.greater) && !m3202c('[')) {
                    this.f7324E = true;
                    m3220x();
                    if (m3210n()) {
                        m3198E();
                    }
                }
            }
            if (m3202c('[')) {
                m3213q();
                while (!m3202c(']')) {
                    if (m3207k() || m3210n()) {
                        if (m3207k()) {
                            m3194A();
                        } else {
                            m3198E();
                        }
                    } else if (m3208l()) {
                        m3195B();
                    } else if (m3205f()) {
                        m3216t();
                    } else {
                        char[] cArr5 = f7312o;
                        if (m3211o(cArr5)) {
                            m3199F(cArr5);
                            m3198E();
                            String str3 = "(WARNING: external ID not read)";
                            if (m3202c('%')) {
                                m3215s('%');
                                m3198E();
                                String m3222z = m3222z();
                                m3198E();
                                if (m3203d('\'', Typography.quote)) {
                                    str3 = m3218v();
                                } else {
                                    m3220x();
                                }
                                this.f7320A.put(m3222z, str3);
                            } else {
                                String m3222z2 = m3222z();
                                m3198E();
                                if (m3203d('\'', Typography.quote)) {
                                    str3 = m3218v();
                                } else {
                                    if (!(m3211o(f7314q) || m3211o(f7315r))) {
                                        throw new C2682j(this, "expecting double-quote, \"PUBLIC\" or \"SYSTEM\" while reading entity declaration");
                                    }
                                    m3220x();
                                    if (m3210n()) {
                                        m3198E();
                                    }
                                    char[] cArr6 = f7313p;
                                    if (m3211o(cArr6)) {
                                        m3199F(cArr6);
                                        m3198E();
                                        m3222z();
                                    }
                                }
                                this.f7335z.put(m3222z2, str3);
                            }
                            if (m3210n()) {
                                m3198E();
                            }
                            m3215s(Typography.greater);
                        } else {
                            if (!m3211o(f7310m)) {
                                throw new C2682j(this, "expecting processing instruction, comment, or \"<!\"");
                            }
                            while (!m3202c(Typography.greater)) {
                                if (m3203d('\'', Typography.quote)) {
                                    char m3213q = m3213q();
                                    while (!m3202c(m3213q)) {
                                        m3213q();
                                    }
                                    m3215s(m3213q);
                                } else {
                                    m3213q();
                                }
                            }
                            m3215s(Typography.greater);
                        }
                    }
                }
                m3215s(']');
                if (m3210n()) {
                    m3198E();
                }
            }
            m3215s(Typography.greater);
            while (m3206i()) {
                m3221y();
            }
        }
        Objects.requireNonNull((C2673a) this.f7331L);
        C2676d m3217u = m3217u();
        String str4 = this.f7333x;
        if (str4 != null && !str4.equals(m3217u.f7279j)) {
            C2674b c2674b2 = this.f7321B;
            StringBuilder m586H = C1499a.m586H("DOCTYPE name \"");
            m586H.append(this.f7333x);
            m586H.append("\" not same as tag name, \"");
            c2674b2.m3168c(C1499a.m582D(m586H, m3217u.f7279j, "\" of root element"), this.f7332w, this.f7330K);
        }
        while (m3206i()) {
            m3221y();
        }
        Reader reader2 = this.f7334y;
        if (reader2 != null) {
            reader2.close();
        }
        Objects.requireNonNull((C2673a) this.f7331L);
    }

    /* renamed from: g */
    public static final boolean m3191g(char c2, char[] cArr) {
        for (char c3 : cArr) {
            if (c2 == c3) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: h */
    public static boolean m3192h(char c2) {
        return "abcdefghijklmnopqrstuvwxyz".indexOf(Character.toLowerCase(c2)) != -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:31:? A[RETURN, SYNTHETIC] */
    /* renamed from: j */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean m3193j(char r3) {
        /*
            boolean r0 = java.lang.Character.isDigit(r3)
            r1 = 0
            r2 = 1
            if (r0 != 0) goto L49
            boolean r0 = m3192h(r3)
            if (r0 != 0) goto L49
            char[] r0 = p005b.p295o.p296a.p297a.C2681i.f7299b
            boolean r0 = m3191g(r3, r0)
            if (r0 != 0) goto L49
            r0 = 183(0xb7, float:2.56E-43)
            if (r3 == r0) goto L46
            r0 = 903(0x387, float:1.265E-42)
            if (r3 == r0) goto L46
            r0 = 1600(0x640, float:2.242E-42)
            if (r3 == r0) goto L46
            r0 = 3654(0xe46, float:5.12E-42)
            if (r3 == r0) goto L46
            r0 = 3782(0xec6, float:5.3E-42)
            if (r3 == r0) goto L46
            r0 = 12293(0x3005, float:1.7226E-41)
            if (r3 == r0) goto L46
            r0 = 720(0x2d0, float:1.009E-42)
            if (r3 == r0) goto L46
            r0 = 721(0x2d1, float:1.01E-42)
            if (r3 == r0) goto L46
            r0 = 12445(0x309d, float:1.7439E-41)
            if (r3 == r0) goto L46
            r0 = 12446(0x309e, float:1.744E-41)
            if (r3 == r0) goto L46
            switch(r3) {
                case 12337: goto L46;
                case 12338: goto L46;
                case 12339: goto L46;
                case 12340: goto L46;
                case 12341: goto L46;
                default: goto L41;
            }
        L41:
            switch(r3) {
                case 12540: goto L46;
                case 12541: goto L46;
                case 12542: goto L46;
                default: goto L44;
            }
        L44:
            r3 = 0
            goto L47
        L46:
            r3 = 1
        L47:
            if (r3 == 0) goto L4a
        L49:
            r1 = 1
        L4a:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.C2681i.m3193j(char):boolean");
    }

    /* renamed from: A */
    public final String m3194A() {
        m3215s('%');
        String m3222z = m3222z();
        String str = (String) this.f7320A.get(m3222z);
        if (str == null) {
            this.f7321B.m3168c(C1499a.m639y("No declaration of %", m3222z, ";"), this.f7332w, this.f7330K);
            str = "";
        }
        m3215s(';');
        return str;
    }

    /* renamed from: B */
    public final void m3195B() {
        m3199F(f7303f);
        while (true) {
            char[] cArr = f7304g;
            if (m3211o(cArr)) {
                m3199F(cArr);
                return;
            }
            m3213q();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:21:0x004c, code lost:
    
        ((p005b.p295o.p296a.p297a.C2673a) r4.f7331L).m3165a(r4.f7329J, 0, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0055, code lost:
    
        return;
     */
    /* renamed from: C */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m3196C() {
        /*
            r4 = this;
            r0 = 0
        L1:
            r1 = 0
        L2:
            r2 = 60
            boolean r2 = r4.m3202c(r2)
            if (r2 != 0) goto L4a
            r2 = 38
            boolean r2 = r4.m3202c(r2)
            if (r2 != 0) goto L4a
            char[] r2 = p005b.p295o.p296a.p297a.C2681i.f7317t
            boolean r2 = r4.m3211o(r2)
            if (r2 != 0) goto L4a
            char[] r2 = r4.f7329J
            char r3 = r4.m3213q()
            r2[r1] = r3
            char[] r2 = r4.f7329J
            char r2 = r2[r1]
            r3 = 13
            if (r2 != r3) goto L3a
            char r2 = r4.m3212p()
            r3 = 10
            if (r2 != r3) goto L3a
            char[] r2 = r4.f7329J
            char r3 = r4.m3213q()
            r2[r1] = r3
        L3a:
            int r1 = r1 + 1
            r2 = 255(0xff, float:3.57E-43)
            if (r1 != r2) goto L2
            b.o.a.a.k r1 = r4.f7331L
            char[] r3 = r4.f7329J
            b.o.a.a.a r1 = (p005b.p295o.p296a.p297a.C2673a) r1
            r1.m3165a(r3, r0, r2)
            goto L1
        L4a:
            if (r1 <= 0) goto L55
            b.o.a.a.k r2 = r4.f7331L
            char[] r3 = r4.f7329J
            b.o.a.a.a r2 = (p005b.p295o.p296a.p297a.C2673a) r2
            r2.m3165a(r3, r0, r1)
        L55:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.C2681i.m3196C():void");
    }

    /* renamed from: D */
    public final char[] m3197D() {
        int i2;
        char c2;
        char[] cArr = f7311n;
        if (!m3211o(cArr)) {
            m3215s(Typography.amp);
            String m3222z = m3222z();
            String str = (String) this.f7335z.get(m3222z);
            if (str == null) {
                if (this.f7324E) {
                    this.f7321B.m3168c(C1499a.m639y("&", m3222z, "; not found -- possibly defined in external DTD)"), this.f7332w, this.f7330K);
                } else {
                    this.f7321B.m3168c(C1499a.m639y("No declaration of &", m3222z, ";"), this.f7332w, this.f7330K);
                }
                str = "";
            }
            m3215s(';');
            return str.toCharArray();
        }
        char[] cArr2 = new char[1];
        m3199F(cArr);
        if (m3202c('x')) {
            m3213q();
            i2 = 16;
        } else {
            i2 = 10;
        }
        int i3 = 0;
        while (true) {
            c2 = ' ';
            if (m3202c(';')) {
                m3215s(';');
                String str2 = new String(this.f7329J, 0, i3);
                try {
                    c2 = (char) Integer.parseInt(str2, i2);
                    break;
                } catch (NumberFormatException unused) {
                    this.f7321B.m3168c(C1499a.m582D(C1499a.m591M("\"", str2, "\" is not a valid "), i2 == 16 ? "hexadecimal" : "decimal", " number"), this.f7332w, this.f7330K);
                }
            } else {
                int i4 = i3 + 1;
                this.f7329J[i3] = m3213q();
                if (i4 >= 255) {
                    this.f7321B.m3168c("Tmp buffer overflow on readCharRef", this.f7332w, this.f7330K);
                    break;
                }
                i3 = i4;
            }
        }
        cArr2[0] = c2;
        return cArr2;
    }

    /* renamed from: E */
    public final void m3198E() {
        char m3213q = m3213q();
        if (m3213q != ' ' && m3213q != '\t' && m3213q != '\r' && m3213q != '\n') {
            throw new C2682j(this, m3213q, new char[]{' ', '\t', '\r', '\n'});
        }
        while (m3204e(' ', '\t', '\r', '\n')) {
            m3213q();
        }
    }

    /* renamed from: F */
    public final void m3199F(char[] cArr) {
        int length = cArr.length;
        if (this.f7327H - this.f7326G < length && m3201b(length) <= 0) {
            this.f7323D = -1;
            throw new C2682j(this, "end of XML file", cArr);
        }
        char[] cArr2 = this.f7325F;
        int i2 = this.f7327H;
        this.f7323D = cArr2[i2 - 1];
        if (i2 - this.f7326G < length) {
            throw new C2682j(this, "end of XML file", cArr);
        }
        for (int i3 = 0; i3 < length; i3++) {
            if (this.f7325F[this.f7326G + i3] != cArr[i3]) {
                throw new C2682j(this, new String(this.f7325F, this.f7326G, length), cArr);
            }
        }
        this.f7326G += length;
    }

    /* renamed from: a */
    public final int m3200a() {
        if (this.f7328I) {
            return -1;
        }
        int i2 = this.f7327H;
        char[] cArr = this.f7325F;
        if (i2 == cArr.length) {
            this.f7327H = 0;
            this.f7326G = 0;
        }
        Reader reader = this.f7334y;
        int i3 = this.f7327H;
        int read = reader.read(cArr, i3, cArr.length - i3);
        if (read <= 0) {
            this.f7328I = true;
            return -1;
        }
        this.f7327H += read;
        return read;
    }

    /* renamed from: b */
    public final int m3201b(int i2) {
        int i3;
        int i4;
        if (this.f7328I) {
            return -1;
        }
        int i5 = 0;
        if (this.f7325F.length - this.f7326G < i2) {
            int i6 = 0;
            while (true) {
                i3 = this.f7326G;
                int i7 = i3 + i6;
                i4 = this.f7327H;
                if (i7 >= i4) {
                    break;
                }
                char[] cArr = this.f7325F;
                cArr[i6] = cArr[i3 + i6];
                i6++;
            }
            int i8 = i4 - i3;
            this.f7327H = i8;
            this.f7326G = 0;
            i5 = i8;
        }
        int m3200a = m3200a();
        if (m3200a != -1) {
            return i5 + m3200a;
        }
        if (i5 == 0) {
            return -1;
        }
        return i5;
    }

    /* renamed from: c */
    public final boolean m3202c(char c2) {
        if (this.f7326G < this.f7327H || m3200a() != -1) {
            return this.f7325F[this.f7326G] == c2;
        }
        throw new C2682j(this, "unexpected end of expression.");
    }

    /* renamed from: d */
    public final boolean m3203d(char c2, char c3) {
        if (this.f7326G >= this.f7327H && m3200a() == -1) {
            return false;
        }
        char c4 = this.f7325F[this.f7326G];
        return c4 == c2 || c4 == c3;
    }

    /* renamed from: e */
    public final boolean m3204e(char c2, char c3, char c4, char c5) {
        if (this.f7326G >= this.f7327H && m3200a() == -1) {
            return false;
        }
        char c6 = this.f7325F[this.f7326G];
        return c6 == c2 || c6 == c3 || c6 == c4 || c6 == c5;
    }

    /* renamed from: f */
    public final boolean m3205f() {
        return m3211o(f7301d);
    }

    /* renamed from: i */
    public final boolean m3206i() {
        return m3205f() || m3208l() || m3210n();
    }

    /* renamed from: k */
    public final boolean m3207k() {
        return m3202c('%');
    }

    /* renamed from: l */
    public final boolean m3208l() {
        return m3211o(f7303f);
    }

    /* renamed from: m */
    public final boolean m3209m() {
        return m3202c(Typography.amp);
    }

    /* renamed from: n */
    public final boolean m3210n() {
        return m3204e(' ', '\t', '\r', '\n');
    }

    /* renamed from: o */
    public final boolean m3211o(char[] cArr) {
        int length = cArr.length;
        if (this.f7327H - this.f7326G < length && m3201b(length) <= 0) {
            this.f7323D = -1;
            return false;
        }
        char[] cArr2 = this.f7325F;
        int i2 = this.f7327H;
        this.f7323D = cArr2[i2 - 1];
        if (i2 - this.f7326G < length) {
            return false;
        }
        for (int i3 = 0; i3 < length; i3++) {
            if (this.f7325F[this.f7326G + i3] != cArr[i3]) {
                return false;
            }
        }
        return true;
    }

    /* renamed from: p */
    public final char m3212p() {
        if (this.f7326G < this.f7327H || m3200a() != -1) {
            return this.f7325F[this.f7326G];
        }
        throw new C2682j(this, "unexpected end of expression.");
    }

    /* renamed from: q */
    public final char m3213q() {
        if (this.f7326G >= this.f7327H && m3200a() == -1) {
            throw new C2682j(this, "unexpected end of expression.");
        }
        char[] cArr = this.f7325F;
        int i2 = this.f7326G;
        if (cArr[i2] == '\n') {
            this.f7330K++;
        }
        this.f7326G = i2 + 1;
        return cArr[i2];
    }

    /* renamed from: r */
    public final char m3214r(char c2, char c3) {
        char m3213q = m3213q();
        if (m3213q == c2 || m3213q == c3) {
            return m3213q;
        }
        throw new C2682j(this, m3213q, new char[]{c2, c3});
    }

    /* renamed from: s */
    public final void m3215s(char c2) {
        char m3213q = m3213q();
        if (m3213q == c2) {
            return;
        }
        throw new C2682j(this, "got '" + m3213q + "' instead of expected '" + c2 + "'");
    }

    /* renamed from: t */
    public final void m3216t() {
        m3199F(f7301d);
        while (true) {
            char[] cArr = f7302e;
            if (m3211o(cArr)) {
                m3199F(cArr);
                return;
            }
            m3213q();
        }
    }

    @Override // p005b.p295o.p296a.p297a.InterfaceC2684l
    public String toString() {
        return this.f7332w;
    }

    /* renamed from: u */
    public final C2676d m3217u() {
        char[] cArr;
        C2676d c2676d = new C2676d();
        m3215s(Typography.less);
        c2676d.f7279j = C2685m.m3223a(m3222z());
        c2676d.mo3170c();
        while (m3210n()) {
            m3198E();
            if (!m3203d('/', Typography.greater)) {
                String m3222z = m3222z();
                m3219w();
                char m3214r = m3214r('\'', Typography.quote);
                StringBuffer stringBuffer = new StringBuffer();
                while (!m3202c(m3214r)) {
                    if (m3209m()) {
                        stringBuffer.append(m3197D());
                    } else {
                        stringBuffer.append(m3213q());
                    }
                }
                m3215s(m3214r);
                String stringBuffer2 = stringBuffer.toString();
                if (c2676d.m3179i(m3222z) != null) {
                    this.f7321B.m3168c("Element " + this + " contains attribute " + m3222z + "more than once", this.f7332w, this.f7330K);
                }
                c2676d.m3180j(m3222z, stringBuffer2);
            }
        }
        if (m3210n()) {
            m3198E();
        }
        boolean m3202c = m3202c(Typography.greater);
        if (m3202c) {
            m3215s(Typography.greater);
        } else {
            m3199F(f7318u);
        }
        C2673a c2673a = (C2673a) this.f7331L;
        C2676d c2676d2 = c2673a.f7269b;
        if (c2676d2 == null) {
            C2675c c2675c = c2673a.f7270c;
            c2675c.f7272f = c2676d;
            c2676d.f7281a = c2675c;
            c2675c.mo3170c();
        } else {
            c2676d2.m3176f(c2676d);
        }
        c2673a.f7269b = c2676d;
        if (m3202c) {
            m3196C();
            boolean z = true;
            while (z) {
                if (!m3211o(f7319v)) {
                    if (m3209m()) {
                        char[] m3197D = m3197D();
                        ((C2673a) this.f7331L).m3165a(m3197D, 0, m3197D.length);
                    } else {
                        char[] cArr2 = f7316s;
                        if (m3211o(cArr2)) {
                            m3199F(cArr2);
                            StringBuffer stringBuffer3 = null;
                            int i2 = 0;
                            while (true) {
                                cArr = f7317t;
                                if (m3211o(cArr)) {
                                    break;
                                }
                                if (i2 >= 255) {
                                    if (stringBuffer3 == null) {
                                        stringBuffer3 = new StringBuffer(i2);
                                        stringBuffer3.append(this.f7329J, 0, i2);
                                    } else {
                                        stringBuffer3.append(this.f7329J, 0, i2);
                                    }
                                    i2 = 0;
                                }
                                this.f7329J[i2] = m3213q();
                                i2++;
                            }
                            m3199F(cArr);
                            if (stringBuffer3 != null) {
                                stringBuffer3.append(this.f7329J, 0, i2);
                                char[] charArray = stringBuffer3.toString().toCharArray();
                                ((C2673a) this.f7331L).m3165a(charArray, 0, charArray.length);
                            } else {
                                ((C2673a) this.f7331L).m3165a(this.f7329J, 0, i2);
                            }
                        } else if (m3208l()) {
                            m3195B();
                        } else if (m3205f()) {
                            m3216t();
                        } else if (m3202c(Typography.less)) {
                            m3217u();
                        }
                    }
                    m3196C();
                }
                z = false;
                m3196C();
            }
            m3199F(f7319v);
            String m3222z2 = m3222z();
            if (!m3222z2.equals(c2676d.f7279j)) {
                this.f7321B.m3168c(C1499a.m582D(C1499a.m591M("end tag (", m3222z2, ") does not match begin tag ("), c2676d.f7279j, ChineseToPinyinResource.Field.RIGHT_BRACKET), this.f7332w, this.f7330K);
            }
            if (m3210n()) {
                m3198E();
            }
            m3215s(Typography.greater);
        }
        C2673a c2673a2 = (C2673a) this.f7331L;
        c2673a2.f7269b = c2673a2.f7269b.f7282b;
        return c2676d;
    }

    /* renamed from: v */
    public final String m3218v() {
        char m3214r = m3214r('\'', Typography.quote);
        StringBuffer stringBuffer = new StringBuffer();
        while (!m3202c(m3214r)) {
            if (m3207k()) {
                stringBuffer.append(m3194A());
            } else if (m3209m()) {
                stringBuffer.append(m3197D());
            } else {
                stringBuffer.append(m3213q());
            }
        }
        m3215s(m3214r);
        return stringBuffer.toString();
    }

    /* renamed from: w */
    public final void m3219w() {
        if (m3210n()) {
            m3198E();
        }
        m3215s('=');
        if (m3210n()) {
            m3198E();
        }
    }

    /* renamed from: x */
    public final String m3220x() {
        char[] cArr = f7314q;
        if (m3211o(cArr)) {
            m3199F(cArr);
        } else {
            char[] cArr2 = f7315r;
            if (!m3211o(cArr2)) {
                throw new C2682j(this, "expecting \"SYSTEM\" or \"PUBLIC\" while reading external ID");
            }
            m3199F(cArr2);
            m3198E();
            char m3213q = m3213q();
            while (m3212p() != m3213q) {
                m3213q();
            }
            m3215s(m3213q);
        }
        m3198E();
        char m3213q2 = m3213q();
        while (m3212p() != m3213q2) {
            m3213q();
        }
        m3215s(m3213q2);
        return "(WARNING: external ID not read)";
    }

    /* renamed from: y */
    public final void m3221y() {
        if (m3205f()) {
            m3216t();
        } else if (m3208l()) {
            m3195B();
        } else {
            if (!m3210n()) {
                throw new C2682j(this, "expecting comment or processing instruction or space");
            }
            m3198E();
        }
    }

    /* renamed from: z */
    public final String m3222z() {
        char[] cArr = this.f7329J;
        char m3213q = m3213q();
        if (!m3192h(m3213q) && m3213q != '_' && m3213q != ':') {
            throw new C2682j(this, "got '" + m3213q + "' instead of letter, underscore, colon as expected");
        }
        cArr[0] = m3213q;
        int i2 = 1;
        StringBuffer stringBuffer = null;
        while (true) {
            char m3212p = m3212p();
            if (!(m3212p < 128 ? f7300c[m3212p] : m3193j(m3212p))) {
                break;
            }
            if (i2 >= 255) {
                if (stringBuffer == null) {
                    stringBuffer = new StringBuffer(i2);
                    stringBuffer.append(this.f7329J, 0, i2);
                } else {
                    stringBuffer.append(this.f7329J, 0, i2);
                }
                i2 = 0;
            }
            this.f7329J[i2] = m3213q();
            i2++;
        }
        if (stringBuffer == null) {
            return C2685m.m3223a(new String(this.f7329J, 0, i2));
        }
        stringBuffer.append(this.f7329J, 0, i2);
        return stringBuffer.toString();
    }
}
