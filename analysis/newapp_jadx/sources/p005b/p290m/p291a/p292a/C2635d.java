package p005b.p290m.p291a.p292a;

import androidx.fragment.app.Fragment;

/* renamed from: b.m.a.a.d */
/* loaded from: classes2.dex */
public class C2635d {

    /* renamed from: a */
    public Fragment f7181a;

    /* renamed from: b */
    public InterfaceC2634c f7182b;

    /* renamed from: c */
    public boolean f7183c;

    /* JADX WARN: Multi-variable type inference failed */
    public C2635d(Fragment fragment) {
        this.f7181a = fragment;
        this.f7182b = (InterfaceC2634c) fragment;
    }

    /* renamed from: a */
    public final void m3107a() {
        Fragment fragment = this.f7181a;
        if (fragment != null && this.f7183c && fragment.getUserVisibleHint() && this.f7182b.mo3106b()) {
            this.f7182b.m3105a();
        }
    }
}
