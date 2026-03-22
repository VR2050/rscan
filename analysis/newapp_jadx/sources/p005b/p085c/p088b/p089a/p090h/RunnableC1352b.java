package p005b.p085c.p088b.p089a.p090h;

import android.content.Context;
import android.text.TextUtils;
import p005b.p085c.p088b.p089a.p090h.C1353c;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.a.h.b */
/* loaded from: classes.dex */
public final class RunnableC1352b implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ String f1182c;

    /* renamed from: e */
    public final /* synthetic */ Context f1183e;

    public RunnableC1352b(String str, Context context) {
        this.f1182c = str;
        this.f1183e = context;
    }

    @Override // java.lang.Runnable
    public void run() {
        String str;
        if (TextUtils.isEmpty(this.f1182c) || C1353c.a.m369b(this.f1183e, this.f1182c)) {
            for (int i2 = 0; i2 < 4; i2++) {
                Context context = this.f1183e;
                synchronized (C4195m.class) {
                    C4195m.m4787T("RecordPref", "stat peek");
                    str = null;
                    if (context != null) {
                        C1351a m4836v = C4195m.m4836v(context);
                        if (!m4836v.f1181a.isEmpty()) {
                            try {
                                str = m4836v.f1181a.entrySet().iterator().next().getValue();
                            } catch (Throwable th) {
                                C4195m.m4816l(th);
                            }
                        }
                    }
                }
                if (TextUtils.isEmpty(str) || !C1353c.a.m369b(this.f1183e, str)) {
                    return;
                }
            }
        }
    }
}
