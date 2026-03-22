package p005b.p139f.p140a.p142b;

import android.app.NotificationChannel;
import android.os.Build;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.f.a.b.f */
/* loaded from: classes.dex */
public class C1536f {

    /* renamed from: a */
    public static final C1536f f1732a = new C1536f(C4195m.m4792Y().getPackageName(), C4195m.m4792Y().getPackageName(), 3);

    /* renamed from: b */
    public NotificationChannel f1733b;

    public C1536f(String str, CharSequence charSequence, int i2) {
        if (Build.VERSION.SDK_INT >= 26) {
            this.f1733b = new NotificationChannel(str, charSequence, i2);
        }
    }
}
