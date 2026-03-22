package p005b.p085c.p088b.p095f;

import android.text.TextUtils;
import org.json.JSONObject;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.f.a */
/* loaded from: classes.dex */
public final class C1363a {

    /* renamed from: a */
    public final String f1235a;

    /* renamed from: b */
    public final String f1236b;

    public C1363a(String str, String str2) {
        this.f1235a = str;
        this.f1236b = str2;
    }

    /* renamed from: a */
    public JSONObject m395a() {
        if (TextUtils.isEmpty(this.f1236b)) {
            return null;
        }
        try {
            return new JSONObject(this.f1236b);
        } catch (Exception e2) {
            C4195m.m4816l(e2);
            return null;
        }
    }

    public String toString() {
        return String.format("<Letter envelop=%s body=%s>", this.f1235a, this.f1236b);
    }
}
