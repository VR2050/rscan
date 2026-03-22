package p005b.p325v.p326a;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.v.a.e */
/* loaded from: classes2.dex */
public final class C2818e {

    /* renamed from: a */
    @NonNull
    public static C2819f f7655a = new C2819f();

    /* renamed from: a */
    public static void m3272a(@NonNull String str, @Nullable Object... objArr) {
        f7655a.m3277c(3, null, str, objArr);
    }

    /* renamed from: b */
    public static void m3273b(@NonNull String str, @Nullable Object... objArr) {
        f7655a.m3277c(4, null, str, objArr);
    }

    /* renamed from: c */
    public static void m3274c(@Nullable String str) {
        C2819f c2819f = f7655a;
        Objects.requireNonNull(c2819f);
        if (C2354n.m2405K0(str)) {
            c2819f.m3275a("Empty/Null json content");
            return;
        }
        try {
            String trim = str.trim();
            if (trim.startsWith("{")) {
                c2819f.m3275a(new JSONObject(trim).toString(2));
            } else if (trim.startsWith("[")) {
                c2819f.m3275a(new JSONArray(trim).toString(2));
            } else {
                c2819f.m3277c(6, null, "Invalid Json", new Object[0]);
            }
        } catch (JSONException unused) {
            c2819f.m3277c(6, null, "Invalid Json", new Object[0]);
        }
    }
}
