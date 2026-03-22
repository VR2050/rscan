package p005b.p113c0.p114a.p124i.p127p;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/* renamed from: b.c0.a.i.p.b */
/* loaded from: classes2.dex */
public class C1479b {
    public C1479b() {
        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException unused) {
            secureRandom = new SecureRandom();
        }
        secureRandom.nextInt();
    }
}
