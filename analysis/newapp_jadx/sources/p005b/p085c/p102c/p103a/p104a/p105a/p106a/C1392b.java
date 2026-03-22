package p005b.p085c.p102c.p103a.p104a.p105a.p106a;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.c.c.a.a.a.a.b */
/* loaded from: classes.dex */
public final class C1392b {
    /* renamed from: a */
    public static String m459a() {
        String str = new String();
        for (int i2 = 0; i2 < 58; i2 += 4) {
            StringBuilder m586H = C1499a.m586H(str);
            m586H.append("idnjfhncnsfuobcnt847y929o449u474w7j3h22aoddc98euk#%&&)*&^%#".charAt(i2));
            str = m586H.toString();
        }
        return str;
    }

    /* renamed from: b */
    public static String m460b(String str, String str2) {
        try {
            PBEKeySpec m461c = m461c(str);
            byte[] bytes = str2.getBytes();
            byte[] m463e = m463e();
            SecretKeySpec secretKeySpec = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(m461c).getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(1, secretKeySpec, new IvParameterSpec(m463e));
            byte[] salt = m461c.getSalt();
            ByteBuffer allocate = ByteBuffer.allocate(salt.length + cipher.getOutputSize(bytes.length));
            allocate.put(salt);
            cipher.doFinal(ByteBuffer.wrap(bytes), allocate);
            byte[] array = allocate.array();
            if (array == null) {
                return "";
            }
            StringBuffer stringBuffer = new StringBuffer(array.length * 2);
            for (byte b2 : array) {
                stringBuffer.append("0123456789ABCDEF".charAt((b2 >> 4) & 15));
                stringBuffer.append("0123456789ABCDEF".charAt(b2 & 15));
            }
            return stringBuffer.toString();
        } catch (Exception unused) {
            return null;
        }
    }

    /* renamed from: c */
    public static PBEKeySpec m461c(String str) {
        Class<?> cls = Class.forName(new String(C1391a.m458a("amF2YS5zZWN1cml0eS5TZWN1cmVSYW5kb20=")));
        Object newInstance = cls.newInstance();
        byte[] bArr = new byte[16];
        Method method = cls.getMethod("nextBytes", bArr.getClass());
        method.setAccessible(true);
        method.invoke(newInstance, bArr);
        return new PBEKeySpec(str.toCharArray(), bArr, 10, 128);
    }

    /* renamed from: d */
    public static String m462d(String str, String str2) {
        boolean z;
        byte[] doFinal;
        try {
            PBEKeySpec m461c = m461c(str);
            int length = str2.length() / 2;
            byte[] bArr = new byte[length];
            z = false;
            for (int i2 = 0; i2 < length; i2++) {
                int i3 = i2 * 2;
                bArr[i2] = Integer.valueOf(str2.substring(i3, i3 + 2), 16).byteValue();
            }
            byte[] m463e = m463e();
            if (length <= 16) {
                doFinal = null;
            } else {
                SecretKeySpec secretKeySpec = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(m461c.getPassword(), Arrays.copyOf(bArr, 16), 10, 128)).getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(2, secretKeySpec, new IvParameterSpec(m463e));
                doFinal = cipher.doFinal(bArr, 16, length - 16);
            }
        } catch (Exception unused) {
        }
        if (doFinal == null) {
            throw new Exception();
        }
        String str3 = new String(doFinal);
        byte[] bytes = str3.getBytes();
        int length2 = bytes.length;
        int i4 = 0;
        while (true) {
            if (i4 >= length2) {
                z = true;
                break;
            }
            byte b2 = bytes[i4];
            if ((b2 >= 0 && b2 <= 31) || b2 >= Byte.MAX_VALUE) {
                break;
            }
            i4++;
        }
        if (z) {
            return str3;
        }
        return null;
    }

    /* renamed from: e */
    public static byte[] m463e() {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i2 = 0; i2 < 48; i2 += 2) {
                sb.append("AsAgAtA5A6AdAgABABACADAfAsAdAfAsAgAaAgA3A5A6=8=0".charAt(i2));
            }
            return C1391a.m458a(sb.toString());
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }
}
