package p005b.p295o.p296a.p297a;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.o.a.a.h */
/* loaded from: classes2.dex */
public class C2680h implements InterfaceC2684l {

    /* renamed from: b */
    public C2681i f7298b;

    /* JADX WARN: Removed duplicated region for block: B:11:0x00cc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2680h(java.lang.String r11, java.io.InputStream r12, p005b.p295o.p296a.p297a.C2674b r13, java.lang.String r14, p005b.p295o.p296a.p297a.InterfaceC2683k r15) {
        /*
            Method dump skipped, instructions count: 454
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p295o.p296a.p297a.C2680h.<init>(java.lang.String, java.io.InputStream, b.o.a.a.b, java.lang.String, b.o.a.a.k):void");
    }

    /* renamed from: a */
    public static boolean m3187a(byte[] bArr, int i2) {
        return bArr[0] == ((byte) (i2 >>> 24)) && bArr[1] == ((byte) ((i2 >>> 16) & 255)) && bArr[2] == ((byte) ((i2 >>> 8) & 255)) && bArr[3] == ((byte) (i2 & 255));
    }

    /* renamed from: b */
    public static boolean m3188b(byte[] bArr, short s) {
        return bArr[0] == ((byte) (s >>> 8)) && bArr[1] == ((byte) (s & 255));
    }

    /* renamed from: c */
    public static String m3189c(String str) {
        return str.toLowerCase().equals("utf8") ? "UTF-8" : str;
    }

    /* renamed from: d */
    public static String m3190d(byte b2) {
        String hexString = Integer.toHexString(b2);
        int length = hexString.length();
        return length != 1 ? length != 2 ? hexString.substring(hexString.length() - 2) : hexString : C1499a.m637w("0", hexString);
    }

    @Override // p005b.p295o.p296a.p297a.InterfaceC2684l
    public String toString() {
        return this.f7298b.f7332w;
    }
}
