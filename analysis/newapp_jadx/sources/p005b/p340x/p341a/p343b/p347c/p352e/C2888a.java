package p005b.p340x.p341a.p343b.p347c.p352e;

import com.google.android.material.appbar.AppBarLayout;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2880a;
import p005b.p340x.p341a.p343b.p347c.p353f.C2890a;

/* renamed from: b.x.a.b.c.e.a */
/* loaded from: classes2.dex */
public class C2888a implements AppBarLayout.OnOffsetChangedListener {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC2880a f7899a;

    public C2888a(InterfaceC2880a interfaceC2880a) {
        this.f7899a = interfaceC2880a;
    }

    @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
    public void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
        InterfaceC2880a interfaceC2880a = this.f7899a;
        boolean z = i2 >= 0;
        boolean z2 = appBarLayout.getTotalScrollRange() + i2 <= 0;
        C2890a c2890a = (C2890a) interfaceC2880a;
        c2890a.f7909j = z;
        c2890a.f7910k = z2;
    }
}
