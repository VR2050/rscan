package io.openinstall.sdk;

import android.text.TextUtils;
import android.util.Base64;
import androidx.core.app.NotificationCompat;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class bd {
    private int a;
    private int b;
    private int c;
    private String d;
    private String e;
    private String f;
    private String g;

    public static bd a(cr crVar) {
        if (crVar != null && crVar.a()) {
            String strC = crVar.e().c();
            if (TextUtils.isEmpty(strC)) {
                return null;
            }
            try {
                String strOptString = new JSONObject(strC).optString(NotificationCompat.CATEGORY_STATUS, "");
                if (TextUtils.isEmpty(strOptString)) {
                    return null;
                }
                String strB = b(strOptString);
                if (TextUtils.isEmpty(strB)) {
                    return null;
                }
                return a(strB);
            } catch (JSONException e) {
            }
        }
        return null;
    }

    private static bd a(String str) {
        try {
            JSONObject jSONObject = new JSONObject(str);
            bd bdVar = new bd();
            bdVar.a = jSONObject.optInt("ac", 1);
            bdVar.b = jSONObject.optInt("cas", 0);
            bdVar.c = jSONObject.optInt("ls", 0);
            bdVar.d = jSONObject.optString("ti", "");
            bdVar.e = jSONObject.optString("ms", "");
            bdVar.f = jSONObject.optString("co", "");
            bdVar.g = jSONObject.optString("ju", "");
            return bdVar;
        } catch (JSONException e) {
            return null;
        }
    }

    private static String b(String str) {
        try {
            if (TextUtils.isEmpty(str) || str.length() <= 19) {
                return "";
            }
            String str2 = new String(Base64.decode(str.substring(19), 0), "UTF-8");
            System.out.println("截取后的Base64数据: " + str2);
            return str2;
        } catch (Exception e) {
            return "";
        }
    }

    public boolean a() {
        return this.a == 2;
    }

    public boolean b() {
        return this.b == 1;
    }

    public boolean c() {
        return this.c == 1;
    }

    public String d() {
        return this.d;
    }

    public String e() {
        return this.e;
    }

    public String f() {
        return this.f;
    }

    public String g() {
        return this.g;
    }
}
