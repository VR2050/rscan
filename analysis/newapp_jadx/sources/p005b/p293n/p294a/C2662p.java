package p005b.p293n.p294a;

import android.app.Activity;
import android.content.Intent;
import androidx.annotation.NonNull;

/* renamed from: b.n.a.p */
/* loaded from: classes2.dex */
public class C2662p implements InterfaceC2661o {

    /* renamed from: a */
    public final Activity f7265a;

    public C2662p(Activity activity, C2660n c2660n) {
        this.f7265a = activity;
    }

    @Override // p005b.p293n.p294a.InterfaceC2661o
    /* renamed from: a */
    public void mo3157a(@NonNull Intent intent) {
        this.f7265a.startActivity(intent);
    }

    @Override // p005b.p293n.p294a.InterfaceC2661o
    /* renamed from: b */
    public void mo3158b(@NonNull Intent intent, int i2) {
        this.f7265a.startActivityForResult(intent, i2);
    }
}
