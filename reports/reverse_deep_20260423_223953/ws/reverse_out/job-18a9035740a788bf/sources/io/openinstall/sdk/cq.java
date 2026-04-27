package io.openinstall.sdk;

import androidx.core.app.NotificationCompat;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class cq {
    private int a;
    private String b;
    private String c;
    private String d;

    public static cq a(String str) {
        cq cqVar = new cq();
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (jSONObject.has("code") && !jSONObject.isNull("code")) {
                cqVar.a(jSONObject.optInt("code"));
            }
            if (jSONObject.has("config") && !jSONObject.isNull("config")) {
                cqVar.d(jSONObject.optString("config"));
            }
            if (jSONObject.has(TtmlNode.TAG_BODY) && !jSONObject.isNull(TtmlNode.TAG_BODY)) {
                cqVar.c(jSONObject.optString(TtmlNode.TAG_BODY));
            }
            if (jSONObject.has(NotificationCompat.CATEGORY_MESSAGE) && !jSONObject.isNull(NotificationCompat.CATEGORY_MESSAGE)) {
                cqVar.b(jSONObject.optString(NotificationCompat.CATEGORY_MESSAGE));
            }
        } catch (JSONException e) {
        }
        return cqVar;
    }

    public int a() {
        return this.a;
    }

    public void a(int i) {
        this.a = i;
    }

    public String b() {
        return this.c;
    }

    public void b(String str) {
        this.c = str;
    }

    public String c() {
        return this.b;
    }

    public void c(String str) {
        this.b = str;
    }

    public String d() {
        return this.d;
    }

    public void d(String str) {
        this.d = str;
    }
}
