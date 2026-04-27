package io.openinstall.sdk;

import android.text.TextUtils;
import com.just.agentweb.DefaultWebClient;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.ByteCompanionObject;

/* JADX INFO: loaded from: classes3.dex */
public class cp implements cm {
    private static final byte[] f = {-4, 110, 4, -38, -91, 80, -53, 111, 30, -30, -48, -69, -66, 0, 67, -63, -48, -79, 83, -104, 75, 58, -36, ByteCompanionObject.MAX_VALUE, -37, -82, -69, -22, -10, 70, 19, 83, 112, 43, 124, -73, 85, 79, -123, -87, -19, -26, -66, 101, -42, 64, 112, -60, 67, -25, -14, -63, -53, -62, 21, -105, ByteCompanionObject.MIN_VALUE, -8, -62, -64, 44, -69, 21, -23};
    private final boolean a;
    private final String b;
    private String c;
    private Map<String, ?> d;
    private Map<String, ?> e;

    public cp(boolean z, String str) {
        this.a = z;
        this.b = str;
    }

    private static String a(String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        byte[] bytes = str.getBytes(bu.c);
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            byte[] bArr = f;
            bytes[i] = (byte) (b ^ bArr[i % bArr.length]);
        }
        return bt.b().a().b(bytes);
    }

    protected static String c(Map<String, ?> map) {
        if (map == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, ?> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (key != null && value != null && !TextUtils.isEmpty(key)) {
                if (value instanceof String) {
                    String strA = a((String) value);
                    if (!TextUtils.isEmpty(strA)) {
                        sb.append(key);
                        sb.append("=");
                        sb.append(strA);
                        sb.append("&");
                    }
                } else if (value instanceof List) {
                    Iterator it = ((List) value).iterator();
                    while (it.hasNext()) {
                        String strA2 = a((String) it.next());
                        if (!TextUtils.isEmpty(strA2)) {
                            sb.append(key);
                            sb.append("=");
                            sb.append(strA2);
                            sb.append("&");
                        }
                    }
                }
            }
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }

    @Override // io.openinstall.sdk.cm
    public cl a() {
        return cl.POST;
    }

    public void a(Map<String, ?> map) {
        this.d = map;
    }

    @Override // io.openinstall.sdk.cm
    public String b() {
        StringBuilder sb;
        String str = DefaultWebClient.HTTPS_SCHEME + this.c + "/api/v2_5/android/" + as.a().e();
        if (this.b.startsWith("/")) {
            sb = new StringBuilder();
            sb.append(str);
        } else {
            sb = new StringBuilder();
            sb.append(str);
            sb.append("/");
        }
        sb.append(this.b);
        return sb.toString();
    }

    public void b(String str) {
        this.c = str;
    }

    public void b(Map<String, ?> map) {
        this.e = map;
    }

    @Override // io.openinstall.sdk.cm
    public String c() {
        Map<String, ?> map = this.d;
        if (map == null || map.size() <= 0) {
            return null;
        }
        return c(this.d);
    }

    @Override // io.openinstall.sdk.cm
    public byte[] d() {
        String strC;
        Map<String, ?> map = this.e;
        if (map == null || map.size() <= 0 || (strC = c(this.e)) == null || strC.length() <= 0) {
            return null;
        }
        return strC.getBytes(bu.c);
    }

    @Override // io.openinstall.sdk.cm
    public Map<String, String> e() {
        return null;
    }

    public String f() {
        return this.c;
    }

    public boolean g() {
        return this.a;
    }
}
