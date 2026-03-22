package p005b.p085c.p088b.p101k;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.res.Resources;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.b.k.b */
/* loaded from: classes.dex */
public class C1385b {

    /* renamed from: a */
    public c f1309a;

    /* renamed from: b */
    public Activity f1310b;

    /* renamed from: c */
    public String f1311c;

    /* renamed from: d */
    public Handler f1312d = new b(Looper.getMainLooper());

    /* renamed from: b.c.b.k.b$a */
    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            c cVar = C1385b.this.f1309a;
            if (cVar == null || !cVar.isShowing()) {
                return;
            }
            try {
                C1385b.this.f1312d.removeMessages(1);
                C1385b.this.f1309a.dismiss();
            } catch (Exception e2) {
                C4195m.m4816l(e2);
            }
        }
    }

    /* renamed from: b.c.b.k.b$b */
    public class b extends Handler {
        public b(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void dispatchMessage(Message message) {
            C1385b.this.m455a();
        }
    }

    /* renamed from: b.c.b.k.b$c */
    public class c extends AlertDialog {
        public c(Context context) {
            super(context);
        }

        /* renamed from: a */
        public final int m456a(Context context, float f2) {
            return (int) (f2 * (context == null ? Resources.getSystem() : context.getResources()).getDisplayMetrics().density);
        }

        /* JADX WARN: Removed duplicated region for block: B:11:0x00fe  */
        /* JADX WARN: Removed duplicated region for block: B:14:0x0140  */
        /* JADX WARN: Removed duplicated region for block: B:17:? A[RETURN, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:18:0x0101  */
        @Override // android.app.AlertDialog, android.app.Dialog
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void onCreate(android.os.Bundle r19) {
            /*
                Method dump skipped, instructions count: 337
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p085c.p088b.p101k.C1385b.c.onCreate(android.os.Bundle):void");
        }
    }

    public C1385b(Activity activity, String str) {
        this.f1310b = activity;
        this.f1311c = str;
    }

    /* renamed from: a */
    public void m455a() {
        Activity activity = this.f1310b;
        if (activity != null) {
            activity.runOnUiThread(new a());
        }
    }
}
