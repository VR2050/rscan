package p005b.p293n.p294a;

import android.app.Fragment;
import android.content.Intent;
import androidx.annotation.NonNull;

/* renamed from: b.n.a.q */
/* loaded from: classes2.dex */
public class C2663q implements InterfaceC2661o {

    /* renamed from: a */
    public final Fragment f7266a;

    public C2663q(Fragment fragment, C2660n c2660n) {
        this.f7266a = fragment;
    }

    @Override // p005b.p293n.p294a.InterfaceC2661o
    /* renamed from: a */
    public void mo3157a(@NonNull Intent intent) {
        this.f7266a.startActivity(intent);
    }

    @Override // p005b.p293n.p294a.InterfaceC2661o
    /* renamed from: b */
    public void mo3158b(@NonNull Intent intent, int i2) {
        this.f7266a.startActivityForResult(intent, i2);
    }
}
