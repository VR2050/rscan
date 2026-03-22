package p005b.p199l.p200a.p201a.p208f1.p211c0;

import android.util.Pair;
import com.luck.picture.lib.config.PictureMimeType;
import p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.c0.b */
/* loaded from: classes.dex */
public final class C1982b {

    /* renamed from: a */
    public static final byte[] f3589a = C2344d0.m2342t("OpusHead");

    /* renamed from: b.l.a.a.f1.c0.b$a */
    public interface a {
        /* renamed from: a */
        boolean mo1516a();

        /* renamed from: b */
        int mo1517b();

        /* renamed from: c */
        int mo1518c();
    }

    /* renamed from: b.l.a.a.f1.c0.b$b */
    public static final class b implements a {

        /* renamed from: a */
        public final int f3590a;

        /* renamed from: b */
        public final int f3591b;

        /* renamed from: c */
        public final C2360t f3592c;

        public b(AbstractC1981a.b bVar) {
            C2360t c2360t = bVar.f3588b;
            this.f3592c = c2360t;
            c2360t.m2567C(12);
            this.f3590a = c2360t.m2588t();
            this.f3591b = c2360t.m2588t();
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.a
        /* renamed from: a */
        public boolean mo1516a() {
            return this.f3590a != 0;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.a
        /* renamed from: b */
        public int mo1517b() {
            return this.f3591b;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.a
        /* renamed from: c */
        public int mo1518c() {
            int i2 = this.f3590a;
            return i2 == 0 ? this.f3592c.m2588t() : i2;
        }
    }

    /* renamed from: b.l.a.a.f1.c0.b$c */
    public static final class c implements a {

        /* renamed from: a */
        public final C2360t f3593a;

        /* renamed from: b */
        public final int f3594b;

        /* renamed from: c */
        public final int f3595c;

        /* renamed from: d */
        public int f3596d;

        /* renamed from: e */
        public int f3597e;

        public c(AbstractC1981a.b bVar) {
            C2360t c2360t = bVar.f3588b;
            this.f3593a = c2360t;
            c2360t.m2567C(12);
            this.f3595c = c2360t.m2588t() & 255;
            this.f3594b = c2360t.m2588t();
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.a
        /* renamed from: a */
        public boolean mo1516a() {
            return false;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.a
        /* renamed from: b */
        public int mo1517b() {
            return this.f3594b;
        }

        @Override // p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.a
        /* renamed from: c */
        public int mo1518c() {
            int i2 = this.f3595c;
            if (i2 == 8) {
                return this.f3593a.m2585q();
            }
            if (i2 == 16) {
                return this.f3593a.m2590v();
            }
            int i3 = this.f3596d;
            this.f3596d = i3 + 1;
            if (i3 % 2 != 0) {
                return this.f3597e & 15;
            }
            int m2585q = this.f3593a.m2585q();
            this.f3597e = m2585q;
            return (m2585q & 240) >> 4;
        }
    }

    /* renamed from: a */
    public static Pair<String, byte[]> m1512a(C2360t c2360t, int i2) {
        c2360t.m2567C(i2 + 8 + 4);
        c2360t.m2568D(1);
        m1513b(c2360t);
        c2360t.m2568D(2);
        int m2585q = c2360t.m2585q();
        if ((m2585q & 128) != 0) {
            c2360t.m2568D(2);
        }
        if ((m2585q & 64) != 0) {
            c2360t.m2568D(c2360t.m2590v());
        }
        if ((m2585q & 32) != 0) {
            c2360t.m2568D(2);
        }
        c2360t.m2568D(1);
        m1513b(c2360t);
        String m2541d = C2357q.m2541d(c2360t.m2585q());
        if (PictureMimeType.MIME_TYPE_AUDIO.equals(m2541d) || "audio/vnd.dts".equals(m2541d) || "audio/vnd.dts.hd".equals(m2541d)) {
            return Pair.create(m2541d, null);
        }
        c2360t.m2568D(12);
        c2360t.m2568D(1);
        int m1513b = m1513b(c2360t);
        byte[] bArr = new byte[m1513b];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, m1513b);
        c2360t.f6134b += m1513b;
        return Pair.create(m2541d, bArr);
    }

    /* renamed from: b */
    public static int m1513b(C2360t c2360t) {
        int m2585q = c2360t.m2585q();
        int i2 = m2585q & 127;
        while ((m2585q & 128) == 128) {
            m2585q = c2360t.m2585q();
            i2 = (i2 << 7) | (m2585q & 127);
        }
        return i2;
    }

    /* renamed from: c */
    public static Pair<Integer, C1990j> m1514c(C2360t c2360t, int i2, int i3) {
        Integer num;
        C1990j c1990j;
        Pair<Integer, C1990j> create;
        int i4;
        int i5;
        byte[] bArr;
        int i6 = c2360t.f6134b;
        while (i6 - i2 < i3) {
            c2360t.m2567C(i6);
            int m2573e = c2360t.m2573e();
            int i7 = 1;
            C4195m.m4761D(m2573e > 0, "childAtomSize should be positive");
            if (c2360t.m2573e() == 1936289382) {
                int i8 = i6 + 8;
                int i9 = -1;
                int i10 = 0;
                String str = null;
                Integer num2 = null;
                while (i8 - i6 < m2573e) {
                    c2360t.m2567C(i8);
                    int m2573e2 = c2360t.m2573e();
                    int m2573e3 = c2360t.m2573e();
                    if (m2573e3 == 1718775137) {
                        num2 = Integer.valueOf(c2360t.m2573e());
                    } else if (m2573e3 == 1935894637) {
                        c2360t.m2568D(4);
                        str = c2360t.m2582n(4);
                    } else if (m2573e3 == 1935894633) {
                        i9 = i8;
                        i10 = m2573e2;
                    }
                    i8 += m2573e2;
                }
                if ("cenc".equals(str) || "cbc1".equals(str) || "cens".equals(str) || "cbcs".equals(str)) {
                    C4195m.m4761D(num2 != null, "frma atom is mandatory");
                    C4195m.m4761D(i9 != -1, "schi atom is mandatory");
                    int i11 = i9 + 8;
                    while (true) {
                        if (i11 - i9 >= i10) {
                            num = num2;
                            c1990j = null;
                            break;
                        }
                        c2360t.m2567C(i11);
                        int m2573e4 = c2360t.m2573e();
                        if (c2360t.m2573e() == 1952804451) {
                            int m2573e5 = (c2360t.m2573e() >> 24) & 255;
                            c2360t.m2568D(i7);
                            if (m2573e5 == 0) {
                                c2360t.m2568D(i7);
                                i4 = 0;
                                i5 = 0;
                            } else {
                                int m2585q = c2360t.m2585q();
                                int i12 = (m2585q & 240) >> 4;
                                i4 = m2585q & 15;
                                i5 = i12;
                            }
                            boolean z = c2360t.m2585q() == i7;
                            int m2585q2 = c2360t.m2585q();
                            byte[] bArr2 = new byte[16];
                            System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr2, 0, 16);
                            c2360t.f6134b += 16;
                            if (z && m2585q2 == 0) {
                                int m2585q3 = c2360t.m2585q();
                                byte[] bArr3 = new byte[m2585q3];
                                System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr3, 0, m2585q3);
                                c2360t.f6134b += m2585q3;
                                bArr = bArr3;
                            } else {
                                bArr = null;
                            }
                            num = num2;
                            c1990j = new C1990j(z, str, m2585q2, bArr2, i5, i4, bArr);
                        } else {
                            i11 += m2573e4;
                            i7 = 1;
                        }
                    }
                    C4195m.m4761D(c1990j != null, "tenc atom is mandatory");
                    create = Pair.create(num, c1990j);
                } else {
                    create = null;
                }
                if (create != null) {
                    return create;
                }
            }
            i6 += m2573e;
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:512:0x00af, code lost:
    
        if (r12 == 0) goto L48;
     */
    /* JADX WARN: Removed duplicated region for block: B:181:0x048c  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x06b3  */
    /* JADX WARN: Removed duplicated region for block: B:248:0x06dc A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:266:0x06ef A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:269:0x06fd  */
    /* JADX WARN: Removed duplicated region for block: B:271:0x06ff  */
    /* JADX WARN: Removed duplicated region for block: B:450:0x0937  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p199l.p200a.p201a.p208f1.p211c0.C1989i m1515d(p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a.a r41, p005b.p199l.p200a.p201a.p208f1.p211c0.AbstractC1981a.b r42, long r43, com.google.android.exoplayer2.drm.DrmInitData r45, boolean r46, boolean r47) {
        /*
            Method dump skipped, instructions count: 2615
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p211c0.C1982b.m1515d(b.l.a.a.f1.c0.a$a, b.l.a.a.f1.c0.a$b, long, com.google.android.exoplayer2.drm.DrmInitData, boolean, boolean):b.l.a.a.f1.c0.i");
    }
}
