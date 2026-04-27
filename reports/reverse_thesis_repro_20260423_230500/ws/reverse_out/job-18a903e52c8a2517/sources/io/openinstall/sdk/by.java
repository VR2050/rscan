package io.openinstall.sdk;

import android.content.ClipData;
import android.os.Build;
import android.text.TextUtils;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class by {
    private String a;
    private String b;
    private int c = 0;
    private boolean d;

    public static by a(ClipData clipData) {
        String string;
        boolean zD;
        ClipData.Item itemAt;
        if (clipData == null) {
            return null;
        }
        by byVar = new by();
        if (clipData.getItemCount() <= 0 || (itemAt = clipData.getItemAt(0)) == null) {
            string = null;
        } else {
            String htmlText = Build.VERSION.SDK_INT >= 16 ? itemAt.getHtmlText() : null;
            string = itemAt.getText() != null ? itemAt.getText().toString() : null;
            str = htmlText;
        }
        if (str != null) {
            if (str.contains(dx.d)) {
                byVar.b(str);
                byVar.b(2);
            }
            byVar.a(d(str));
        }
        if (string != null) {
            if (string.contains(dx.d)) {
                byVar.a(string);
                byVar.b(1);
                zD = d(string);
            } else {
                String strB = dw.b(string);
                if (strB.contains(dx.d)) {
                    byVar.a(string);
                    byVar.b(1);
                }
                zD = d(strB);
            }
            byVar.a(zD);
        }
        return byVar;
    }

    public static by c(String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        by byVar = new by();
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (jSONObject.has("pbText")) {
                byVar.a(jSONObject.optString("pbText"));
            }
            if (jSONObject.has("pbHtml")) {
                byVar.b(jSONObject.optString("pbHtml"));
            }
            if (jSONObject.has("pbType")) {
                byVar.a(jSONObject.optInt("pbType"));
            }
            return byVar;
        } catch (JSONException e) {
            return null;
        }
    }

    private static boolean d(String str) {
        if (!str.contains(dx.e)) {
            return false;
        }
        long j = 0;
        try {
            int iIndexOf = str.indexOf(dx.e) + dx.e.length();
            j = Long.parseLong(str.substring(iIndexOf, str.indexOf("-", iIndexOf)));
        } catch (Exception e) {
        }
        return System.currentTimeMillis() < j;
    }

    public String a() {
        return this.a;
    }

    public void a(int i) {
        this.c = i;
    }

    public void a(String str) {
        this.a = str;
    }

    public void a(boolean z) {
        this.d = z;
    }

    public String b() {
        return this.b;
    }

    public void b(int i) {
        this.c = i | this.c;
    }

    public void b(String str) {
        this.b = str;
    }

    public int c() {
        return this.c;
    }

    public boolean c(int i) {
        return (i & this.c) != 0;
    }

    public String d() {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("pbText", this.a);
            jSONObject.put("pbHtml", this.b);
            jSONObject.put("pbType", this.c);
        } catch (JSONException e) {
        }
        return jSONObject.toString();
    }
}
