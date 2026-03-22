package p005b.p113c0.p114a.p116h.p123m;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.File;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.c0.a.h.m.a */
/* loaded from: classes2.dex */
public abstract class AbstractC1451a extends AbstractC1454d {

    /* renamed from: e */
    public final String f1405e;

    public AbstractC1451a() {
        C2354n.m2426R0(!TextUtils.isEmpty("index.html"), "The indexFileName cannot be empty.");
        this.f1405e = "index.html";
    }

    /* renamed from: h */
    public String m514h(@NonNull String str) {
        String str2 = File.separator;
        return !str.endsWith(str2) ? C1499a.m637w(str, str2) : str;
    }

    public AbstractC1451a(@NonNull String str) {
        C2354n.m2426R0(!TextUtils.isEmpty(str), "The indexFileName cannot be empty.");
        this.f1405e = str;
    }
}
