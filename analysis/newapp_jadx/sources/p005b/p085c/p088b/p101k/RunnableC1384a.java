package p005b.p085c.p088b.p101k;

import androidx.work.WorkRequest;
import p005b.p085c.p088b.p101k.C1385b.c;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.k.a */
/* loaded from: classes.dex */
public class RunnableC1384a implements Runnable {

    /* renamed from: c */
    public final /* synthetic */ C1385b f1308c;

    public RunnableC1384a(C1385b c1385b) {
        this.f1308c = c1385b;
    }

    @Override // java.lang.Runnable
    public void run() {
        C1385b c1385b = this.f1308c;
        if (c1385b.f1309a == null) {
            C1385b c1385b2 = this.f1308c;
            c1385b.f1309a = c1385b2.new c(c1385b2.f1310b);
            this.f1308c.f1309a.setCancelable(false);
        }
        try {
            if (this.f1308c.f1309a.isShowing()) {
                return;
            }
            this.f1308c.f1309a.show();
            this.f1308c.f1312d.sendEmptyMessageDelayed(1, WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS);
        } catch (Exception e2) {
            C4195m.m4816l(e2);
        }
    }
}
