package io.openinstall.sdk;

import android.text.TextUtils;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class aw {
    private Boolean a;
    private Boolean b;
    private Boolean c;
    private Boolean d;
    private long e = 3600;
    private String f;

    public static aw b(String str) {
        aw awVar = new aw();
        if (TextUtils.isEmpty(str)) {
            return awVar;
        }
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (jSONObject.has("wakeupStatsEnabled")) {
                awVar.a(Boolean.valueOf(jSONObject.optBoolean("wakeupStatsEnabled", true)));
            }
            if (jSONObject.has("aliveStatsEnabled")) {
                awVar.c(Boolean.valueOf(jSONObject.optBoolean("aliveStatsEnabled", true)));
            }
            if (jSONObject.has("registerStatsEnabled")) {
                awVar.b(Boolean.valueOf(jSONObject.optBoolean("registerStatsEnabled", true)));
            }
            if (jSONObject.has("eventStatsEnabled")) {
                awVar.c(Boolean.valueOf(jSONObject.optBoolean("eventStatsEnabled", true)));
            }
            if (jSONObject.has("reportPeriod")) {
                awVar.a(jSONObject.optLong("reportPeriod"));
            }
            if (jSONObject.has("installId")) {
                awVar.a(jSONObject.optString("installId"));
            }
            return awVar;
        } catch (JSONException e) {
            return awVar;
        }
    }

    private boolean d(Boolean bool) {
        if (bool == null) {
            return true;
        }
        return bool.booleanValue();
    }

    public Boolean a() {
        return this.a;
    }

    public void a(long j) {
        this.e = j;
    }

    public void a(aw awVar) {
        this.a = awVar.a();
        this.b = awVar.e();
        this.c = awVar.c();
        this.d = awVar.e();
        this.e = awVar.g();
        this.f = awVar.h();
    }

    public void a(Boolean bool) {
        this.a = bool;
    }

    public void a(String str) {
        this.f = str;
    }

    public void b(Boolean bool) {
        this.c = bool;
    }

    public boolean b() {
        return d(this.a);
    }

    public Boolean c() {
        return this.c;
    }

    public void c(Boolean bool) {
        this.d = bool;
    }

    public boolean d() {
        return d(this.c);
    }

    public Boolean e() {
        return this.d;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        aw awVar = (aw) obj;
        if (this.e != awVar.e) {
            return false;
        }
        Boolean bool = this.a;
        if (bool == null ? awVar.a != null : !bool.equals(awVar.a)) {
            return false;
        }
        Boolean bool2 = this.b;
        if (bool2 == null ? awVar.b != null : !bool2.equals(awVar.b)) {
            return false;
        }
        Boolean bool3 = this.c;
        if (bool3 == null ? awVar.c != null : !bool3.equals(awVar.c)) {
            return false;
        }
        Boolean bool4 = this.d;
        if (bool4 == null ? awVar.d != null : !bool4.equals(awVar.d)) {
            return false;
        }
        String str = this.f;
        return str != null ? str.equals(awVar.f) : awVar.f == null;
    }

    public boolean f() {
        return d(this.d);
    }

    public long g() {
        return this.e;
    }

    public String h() {
        return this.f;
    }

    public int hashCode() {
        Boolean bool = this.a;
        int iHashCode = (bool != null ? bool.hashCode() : 0) * 31;
        Boolean bool2 = this.b;
        int iHashCode2 = (iHashCode + (bool2 != null ? bool2.hashCode() : 0)) * 31;
        Boolean bool3 = this.c;
        int iHashCode3 = (iHashCode2 + (bool3 != null ? bool3.hashCode() : 0)) * 31;
        Boolean bool4 = this.d;
        int iHashCode4 = (iHashCode3 + (bool4 != null ? bool4.hashCode() : 0)) * 31;
        long j = this.e;
        int i = (iHashCode4 + ((int) (j ^ (j >>> 32)))) * 31;
        String str = this.f;
        return i + (str != null ? str.hashCode() : 0);
    }

    public String i() {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("wakeupStatsEnabled", this.a);
            jSONObject.put("registerStatsEnabled", this.c);
            jSONObject.put("eventStatsEnabled", this.d);
            jSONObject.put("reportPeriod", this.e);
            jSONObject.put("installId", this.f);
        } catch (JSONException e) {
        }
        return jSONObject.toString();
    }
}
