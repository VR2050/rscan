package com.p397ta.utdid2.p398a.p399a;

/* renamed from: com.ta.utdid2.a.a.f */
/* loaded from: classes2.dex */
public class C4135f {

    /* renamed from: com.ta.utdid2.a.a.f$a */
    public static class a {

        /* renamed from: d */
        public int[] f10806d;

        /* renamed from: x */
        public int f10807x;

        /* renamed from: y */
        public int f10808y;

        private a() {
            this.f10806d = new int[256];
        }
    }

    /* renamed from: a */
    public static byte[] m4658a(byte[] bArr) {
        a m4657a;
        if (bArr == null || (m4657a = m4657a("QrMgt8GGYI6T52ZY5AnhtxkLzb8egpFn3j5JELI8H6wtACbUnZ5cc3aYTsTRbmkAkRJeYbtx92LPBWm7nBO9UIl7y5i5MQNmUZNf5QENurR5tGyo7yJ2G0MBjWvy6iAtlAbacKP0SwOUeUWx5dsBdyhxa7Id1APtybSdDgicBDuNjI0mlZFUzZSS9dmN8lBD0WTVOMz0pRZbR3cysomRXOO1ghqjJdTcyDIxzpNAEszN8RMGjrzyU7Hjbmwi6YNK")) == null) {
            return null;
        }
        return m4659a(bArr, m4657a);
    }

    /* renamed from: a */
    private static a m4657a(String str) {
        if (str == null) {
            return null;
        }
        a aVar = new a();
        for (int i2 = 0; i2 < 256; i2++) {
            aVar.f10806d[i2] = i2;
        }
        aVar.f10807x = 0;
        aVar.f10808y = 0;
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < 256; i5++) {
            try {
                char charAt = str.charAt(i3);
                int[] iArr = aVar.f10806d;
                i4 = ((charAt + iArr[i5]) + i4) % 256;
                int i6 = iArr[i5];
                iArr[i5] = iArr[i4];
                iArr[i4] = i6;
                i3 = (i3 + 1) % str.length();
            } catch (Exception unused) {
                return null;
            }
        }
        return aVar;
    }

    /* renamed from: a */
    private static byte[] m4659a(byte[] bArr, a aVar) {
        if (bArr == null || aVar == null) {
            return null;
        }
        int i2 = aVar.f10807x;
        int i3 = aVar.f10808y;
        for (int i4 = 0; i4 < bArr.length; i4++) {
            i2 = (i2 + 1) % 256;
            int[] iArr = aVar.f10806d;
            i3 = (iArr[i2] + i3) % 256;
            int i5 = iArr[i2];
            iArr[i2] = iArr[i3];
            iArr[i3] = i5;
            int i6 = (iArr[i2] + iArr[i3]) % 256;
            bArr[i4] = (byte) (iArr[i6] ^ bArr[i4]);
        }
        aVar.f10807x = i2;
        aVar.f10808y = i3;
        return bArr;
    }
}
