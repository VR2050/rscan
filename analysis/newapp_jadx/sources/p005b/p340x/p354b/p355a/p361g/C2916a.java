package p005b.p340x.p354b.p355a.p361g;

import com.google.android.material.appbar.AppBarLayout;
import p005b.p340x.p354b.p355a.p358d.C2905a;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2910a;

/* renamed from: b.x.b.a.g.a */
/* loaded from: classes2.dex */
public final class C2916a implements AppBarLayout.OnOffsetChangedListener {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC2910a f7983a;

    public C2916a(InterfaceC2910a interfaceC2910a) {
        this.f7983a = interfaceC2910a;
    }

    @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
    public void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
        InterfaceC2910a interfaceC2910a = this.f7983a;
        boolean z = i2 >= 0;
        boolean z2 = appBarLayout.getTotalScrollRange() + i2 <= 0;
        C2905a c2905a = (C2905a) interfaceC2910a;
        c2905a.f7968j = z;
        c2905a.f7969k = z2;
    }
}
