package p005b.p113c0.p114a.p130l;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.conscrypt.EvpMdRef;

/* renamed from: b.c0.a.l.a */
/* loaded from: classes2.dex */
public class C1489a {

    /* renamed from: a */
    public static final char[] f1495a = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /* renamed from: a */
    public static String m559a(String str) {
        try {
            byte[] digest = MessageDigest.getInstance(EvpMdRef.MD5.JCA_NAME).digest(str.getBytes());
            char[] cArr = new char[32];
            for (int i2 = 0; i2 < 32; i2 += 2) {
                byte b2 = digest[i2 / 2];
                char[] cArr2 = f1495a;
                cArr[i2] = cArr2[(b2 >>> 4) & 15];
                cArr[i2 + 1] = cArr2[b2 & 15];
            }
            return new String(cArr);
        } catch (NoSuchAlgorithmException e2) {
            throw new IllegalStateException("Could not find MessageDigest with algorithm \"MD5\"", e2);
        }
    }
}
