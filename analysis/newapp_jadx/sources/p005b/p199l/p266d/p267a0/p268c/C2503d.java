package p005b.p199l.p266d.p267a0.p268c;

import com.alibaba.fastjson.asm.Opcodes;
import java.io.UnsupportedEncodingException;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.p274v.C2545c;

/* renamed from: b.l.d.a0.c.d */
/* loaded from: classes2.dex */
public final class C2503d {

    /* renamed from: a */
    public static final char[] f6738a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".toCharArray();

    /* renamed from: a */
    public static void m2876a(C2545c c2545c, StringBuilder sb, int i2, boolean z) {
        while (i2 > 1) {
            if (c2545c.m2964a() < 11) {
                throw C2525g.m2925a();
            }
            int m2965b = c2545c.m2965b(11);
            sb.append(m2881f(m2965b / 45));
            sb.append(m2881f(m2965b % 45));
            i2 -= 2;
        }
        if (i2 == 1) {
            if (c2545c.m2964a() < 6) {
                throw C2525g.m2925a();
            }
            sb.append(m2881f(c2545c.m2965b(6)));
        }
        if (z) {
            for (int length = sb.length(); length < sb.length(); length++) {
                if (sb.charAt(length) == '%') {
                    if (length < sb.length() - 1) {
                        int i3 = length + 1;
                        if (sb.charAt(i3) == '%') {
                            sb.deleteCharAt(i3);
                        }
                    }
                    sb.setCharAt(length, (char) 29);
                }
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:59:0x0143, code lost:
    
        if (r1 == 2) goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x0147, code lost:
    
        if ((r17 * 10) >= r23) goto L130;
     */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m2877b(p005b.p199l.p266d.p274v.C2545c r21, java.lang.StringBuilder r22, int r23, p005b.p199l.p266d.p274v.EnumC2546d r24, java.util.Collection<byte[]> r25, java.util.Map<p005b.p199l.p266d.EnumC2523e, ?> r26) {
        /*
            Method dump skipped, instructions count: 382
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p267a0.p268c.C2503d.m2877b(b.l.d.v.c, java.lang.StringBuilder, int, b.l.d.v.d, java.util.Collection, java.util.Map):void");
    }

    /* renamed from: c */
    public static void m2878c(C2545c c2545c, StringBuilder sb, int i2) {
        if (i2 * 13 > c2545c.m2964a()) {
            throw C2525g.m2925a();
        }
        byte[] bArr = new byte[i2 * 2];
        int i3 = 0;
        while (i2 > 0) {
            int m2965b = c2545c.m2965b(13);
            int i4 = (m2965b % 96) | ((m2965b / 96) << 8);
            int i5 = i4 + (i4 < 2560 ? 41377 : 42657);
            bArr[i3] = (byte) (i5 >> 8);
            bArr[i3 + 1] = (byte) i5;
            i3 += 2;
            i2--;
        }
        try {
            sb.append(new String(bArr, "GB2312"));
        } catch (UnsupportedEncodingException unused) {
            throw C2525g.m2925a();
        }
    }

    /* renamed from: d */
    public static void m2879d(C2545c c2545c, StringBuilder sb, int i2) {
        if (i2 * 13 > c2545c.m2964a()) {
            throw C2525g.m2925a();
        }
        byte[] bArr = new byte[i2 * 2];
        int i3 = 0;
        while (i2 > 0) {
            int m2965b = c2545c.m2965b(13);
            int i4 = (m2965b % Opcodes.CHECKCAST) | ((m2965b / Opcodes.CHECKCAST) << 8);
            int i5 = i4 + (i4 < 7936 ? 33088 : 49472);
            bArr[i3] = (byte) (i5 >> 8);
            bArr[i3 + 1] = (byte) i5;
            i3 += 2;
            i2--;
        }
        try {
            sb.append(new String(bArr, "SJIS"));
        } catch (UnsupportedEncodingException unused) {
            throw C2525g.m2925a();
        }
    }

    /* renamed from: e */
    public static void m2880e(C2545c c2545c, StringBuilder sb, int i2) {
        while (i2 >= 3) {
            if (c2545c.m2964a() < 10) {
                throw C2525g.m2925a();
            }
            int m2965b = c2545c.m2965b(10);
            if (m2965b >= 1000) {
                throw C2525g.m2925a();
            }
            sb.append(m2881f(m2965b / 100));
            sb.append(m2881f((m2965b / 10) % 10));
            sb.append(m2881f(m2965b % 10));
            i2 -= 3;
        }
        if (i2 == 2) {
            if (c2545c.m2964a() < 7) {
                throw C2525g.m2925a();
            }
            int m2965b2 = c2545c.m2965b(7);
            if (m2965b2 >= 100) {
                throw C2525g.m2925a();
            }
            sb.append(m2881f(m2965b2 / 10));
            sb.append(m2881f(m2965b2 % 10));
            return;
        }
        if (i2 == 1) {
            if (c2545c.m2964a() < 4) {
                throw C2525g.m2925a();
            }
            int m2965b3 = c2545c.m2965b(4);
            if (m2965b3 >= 10) {
                throw C2525g.m2925a();
            }
            sb.append(m2881f(m2965b3));
        }
    }

    /* renamed from: f */
    public static char m2881f(int i2) {
        char[] cArr = f6738a;
        if (i2 < cArr.length) {
            return cArr[i2];
        }
        throw C2525g.m2925a();
    }
}
