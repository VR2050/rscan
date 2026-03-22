package p005b.p172h.p173a.p174r;

import android.text.TextUtils;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.conscrypt.EvpMdRef;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.h.a.r.f */
/* loaded from: classes.dex */
public class C1834f {
    /* renamed from: a */
    public String m1189a(String str) {
        int lastIndexOf = str.lastIndexOf(46);
        String substring = (lastIndexOf == -1 || lastIndexOf <= str.lastIndexOf(47) || (lastIndexOf + 2) + 4 <= str.length()) ? "" : str.substring(lastIndexOf + 1, str.length());
        try {
            byte[] digest = MessageDigest.getInstance(EvpMdRef.MD5.JCA_NAME).digest(str.getBytes());
            StringBuffer stringBuffer = new StringBuffer();
            for (byte b2 : digest) {
                stringBuffer.append(String.format("%02x", Byte.valueOf(b2)));
            }
            String stringBuffer2 = stringBuffer.toString();
            return TextUtils.isEmpty(substring) ? stringBuffer2 : C1499a.m639y(stringBuffer2, ".", substring);
        } catch (NoSuchAlgorithmException e2) {
            throw new IllegalStateException(e2);
        }
    }
}
