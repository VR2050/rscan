package p005b.p293n.p294a;

import android.content.Intent;
import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

/* renamed from: b.n.a.r */
/* loaded from: classes2.dex */
public class C2664r implements InterfaceC2661o {

    /* renamed from: a */
    public final Fragment f7267a;

    public C2664r(Fragment fragment, C2660n c2660n) {
        this.f7267a = fragment;
    }

    @Override // p005b.p293n.p294a.InterfaceC2661o
    /* renamed from: a */
    public void mo3157a(@NonNull Intent intent) {
        this.f7267a.startActivity(intent);
    }

    @Override // p005b.p293n.p294a.InterfaceC2661o
    /* renamed from: b */
    public void mo3158b(@NonNull Intent intent, int i2) {
        this.f7267a.startActivityForResult(intent, i2);
    }
}
