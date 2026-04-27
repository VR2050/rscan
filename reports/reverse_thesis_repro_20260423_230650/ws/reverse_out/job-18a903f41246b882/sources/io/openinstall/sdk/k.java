package io.openinstall.sdk;

import android.content.Context;
import android.os.Build;
import android.text.TextUtils;
import java.io.File;

/* JADX INFO: loaded from: classes3.dex */
public class k {
    private static k a;
    private static final Object b = new Object();
    private StringBuilder c = new StringBuilder();
    private final String[] d = {"dmJveA==", "Z29sZGZpc2g=", "X3g4Ng==", "YW9zcA==", "c2RrX2dwaG9uZQ==", "c2RrX3Bob25l"};

    private k() {
    }

    public static k a() {
        if (a == null) {
            synchronized (b) {
                if (a == null) {
                    a = new k();
                }
            }
        }
        return a;
    }

    private String a(String str) {
        Object objInvoke;
        try {
            objInvoke = Class.forName("android.os.SystemProperties").getMethod("get", String.class).invoke(null, str);
        } catch (Exception e) {
        }
        String str2 = objInvoke != null ? (String) objInvoke : null;
        if (TextUtils.isEmpty(str2)) {
            return null;
        }
        return str2;
    }

    private boolean a(Context context, String str) {
        return !context.getPackageManager().hasSystemFeature(dw.a(str));
    }

    private boolean a(String[] strArr) {
        int i = 0;
        while (true) {
            String[] strArr2 = this.d;
            if (i >= strArr2.length) {
                break;
            }
            strArr2[i] = dw.a(strArr2[i]);
            i++;
        }
        for (String str : strArr) {
            String strA = a(dw.a(str));
            if (strA != null) {
                String lowerCase = strA.toLowerCase();
                for (String str2 : this.d) {
                    if (lowerCase.contains(str2)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean b(String[] strArr) {
        for (String str : strArr) {
            if (new File(dw.a(str)).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean c(String[] strArr) {
        for (String str : strArr) {
            if (new File(dw.a(str)).exists()) {
                return false;
            }
        }
        return true;
    }

    public boolean a(Context context) {
        this.c.setLength(0);
        int i = a(new String[]{"cm8uYnVpbGQuZmxhdm9y", "cm8uYm9hcmQucGxhdGZvcm0=", "cm8uaGFyZHdhcmU="}) ? 5 : 0;
        if (a(context, "YW5kcm9pZC5oYXJkd2FyZS5ibHVldG9vdGg=")) {
            i += 5;
        }
        if (a(context, "YW5kcm9pZC5oYXJkd2FyZS5jYW1lcmEuZmxhc2g=")) {
            i += 5;
        }
        if (b(new String[]{"L3N5c3RlbS9mcmFtZXdvcmsveDg2", "L3N5c3RlbS9mcmFtZXdvcmsveDg2XzY0", "L3N5c3RlbS9saWIvbGliY2xjb3JlX3g4Ni5iYw==", "L3N5c3RlbS9saWI2NC9saWJjbGNvcmVfeDg2LmJj", "L3N5c3RlbS9iaW4vbm94LXByb3A=", "L3N5c3RlbS9iaW4vZHJvaWQ0eC1wcm9w", "L3N5c3RlbS9iaW4vdHRWTS1wcm9w", "L3N5c3RlbS9iaW4vbWljcm92aXJ0LXByb3A=", "L3N5c3RlbS9iaW4vbmVtdVZNLXByb3A=", "L3N5c3RlbS9iaW4vYW5kcm9WTS1wcm9w", "L3N5c3RlbS9iaW4vZ2VueW1vdGlvbi12Ym94LXNm", "L3N5c3RlbS9ldGMvaW5pdC5hbmRyb1ZNLnNo", "L3N5c3RlbS9ldGMvbXVtdS1jb25maWdz", "L3N5c3RlbS9hcHAvS2V5Q2hhaW4vb2F0L3g4Ng==", "L3N5c3RlbS9hcHAvS2V5Q2hhaW4vb2F0L3g4Nl82NA==", "L3N5c3RlbS9mcmFtZXdvcmsvb2F0L3g4Ng==", "L3N5c3RlbS9mcmFtZXdvcmsvb2F0L3g4Nl82NA=="})) {
            i += 10;
        }
        if (b(new String[]{"L3N5c3RlbS9ldGMvZXhjbHVkZWQtaW5wdXQtZGV2aWNlcy54bWw="})) {
            i = Build.VERSION.SDK_INT < 26 ? i + 5 : i + 3;
        }
        if (c(new String[]{"L3N5c3RlbS9mcmFtZXdvcmsvYXJt", "L3N5c3RlbS9mcmFtZXdvcmsvYXJtNjQ="})) {
            i += 7;
        }
        return i >= 10;
    }
}
