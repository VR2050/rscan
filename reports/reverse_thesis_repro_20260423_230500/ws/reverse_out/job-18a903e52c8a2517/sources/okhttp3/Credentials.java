package okhttp3;

import com.king.zxing.util.LogUtils;
import java.nio.charset.Charset;
import okhttp3.internal.Util;
import okio.ByteString;

/* JADX INFO: loaded from: classes3.dex */
public final class Credentials {
    private Credentials() {
    }

    public static String basic(String username, String password) {
        return basic(username, password, Util.ISO_8859_1);
    }

    public static String basic(String username, String password, Charset charset) {
        String usernameAndPassword = username + LogUtils.COLON + password;
        String encoded = ByteString.encodeString(usernameAndPassword, charset).base64();
        return "Basic " + encoded;
    }
}
