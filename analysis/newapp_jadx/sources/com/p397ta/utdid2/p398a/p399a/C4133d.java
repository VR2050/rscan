package com.p397ta.utdid2.p398a.p399a;

/* renamed from: com.ta.utdid2.a.a.d */
/* loaded from: classes2.dex */
public class C4133d {
    public static byte[] getBytes(int i2) {
        byte[] bArr = {(byte) ((r3 >> 8) % 256), (byte) (r3 % 256), (byte) (r3 % 256), (byte) (i2 % 256)};
        int i3 = i2 >> 8;
        int i4 = i3 >> 8;
        return bArr;
    }
}
