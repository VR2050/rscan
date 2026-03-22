package p005b.p085c.p088b.p098h;

import android.content.Context;
import com.p397ta.utdid2.device.UTDevice;
import p005b.p085c.p088b.p092c.C1359d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.h.b */
/* loaded from: classes.dex */
public class C1374b {

    /* renamed from: a */
    public static C1374b f1258a;

    /* renamed from: b */
    public Context f1259b;

    /* renamed from: a */
    public static C1374b m417a() {
        if (f1258a == null) {
            f1258a = new C1374b();
        }
        return f1258a;
    }

    /* renamed from: b */
    public void m418b(Context context) {
        C1359d.m384d();
        this.f1259b = context.getApplicationContext();
    }

    /* renamed from: c */
    public String m419c() {
        try {
            return UTDevice.getUtdid(this.f1259b);
        } catch (Throwable th) {
            C4195m.m4816l(th);
            return "getUtdidEx";
        }
    }
}
