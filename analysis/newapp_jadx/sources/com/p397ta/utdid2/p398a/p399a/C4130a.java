package com.p397ta.utdid2.p398a.p399a;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.ta.utdid2.a.a.a */
/* loaded from: classes2.dex */
public class C4130a {
    /* renamed from: a */
    public static String m4639a(String str) {
        byte[] bArr;
        try {
            bArr = m4644a(m4642a(), str.getBytes());
        } catch (Exception unused) {
            bArr = null;
        }
        if (bArr != null) {
            return m4640a(bArr);
        }
        return null;
    }

    /* renamed from: b */
    public static String m4645b(String str) {
        try {
            return new String(m4647b(m4642a(), m4643a(str)));
        } catch (Exception unused) {
            return null;
        }
    }

    /* renamed from: a */
    private static byte[] m4642a() {
        return C4135f.m4658a(new byte[]{33, 83, -50, -89, -84, -114, 80, 99, 10, 63, 22, -65, -11, 30, 101, -118});
    }

    /* renamed from: b */
    private static byte[] m4647b(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, secretKeySpec, new IvParameterSpec(m4646b()));
        return cipher.doFinal(bArr2);
    }

    /* renamed from: a */
    private static byte[] m4644a(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(1, secretKeySpec, new IvParameterSpec(m4646b()));
        return cipher.doFinal(bArr2);
    }

    /* renamed from: b */
    private static byte[] m4646b() {
        try {
            byte[] decode = C4131b.decode("IUQSvE6r1TfFPdPEjfklLw==".getBytes("UTF-8"), 2);
            if (decode != null) {
                return C4135f.m4658a(decode);
            }
        } catch (Exception unused) {
        }
        return new byte[16];
    }

    /* renamed from: a */
    private static byte[] m4643a(String str) {
        int length = str.length() / 2;
        byte[] bArr = new byte[length];
        for (int i2 = 0; i2 < length; i2++) {
            int i3 = i2 * 2;
            bArr[i2] = Integer.valueOf(str.substring(i3, i3 + 2), 16).byteValue();
        }
        return bArr;
    }

    /* renamed from: a */
    private static String m4640a(byte[] bArr) {
        if (bArr == null) {
            return "";
        }
        StringBuffer stringBuffer = new StringBuffer(bArr.length * 2);
        for (byte b2 : bArr) {
            m4641a(stringBuffer, b2);
        }
        return stringBuffer.toString();
    }

    /* renamed from: a */
    private static void m4641a(StringBuffer stringBuffer, byte b2) {
        stringBuffer.append("0123456789ABCDEF".charAt((b2 >> 4) & 15));
        stringBuffer.append("0123456789ABCDEF".charAt(b2 & 15));
    }
}
