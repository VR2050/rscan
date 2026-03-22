package p448i.p452b.p453a;

import com.google.android.material.appbar.AppBarLayout;

/* renamed from: i.b.a.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4353a implements AppBarLayout.OnOffsetChangedListener {

    /* renamed from: a */
    public a f11247a = a.IDLE;

    /* renamed from: i.b.a.a$a */
    public enum a {
        EXPANDED,
        COLLAPSED,
        IDLE
    }

    /* renamed from: a */
    public abstract void mo4928a(AppBarLayout appBarLayout, a aVar);

    @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
    public final void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
        if (i2 == 0) {
            a aVar = this.f11247a;
            a aVar2 = a.EXPANDED;
            if (aVar != aVar2) {
                mo4928a(appBarLayout, aVar2);
            }
            this.f11247a = aVar2;
            return;
        }
        if (Math.abs(i2) >= appBarLayout.getTotalScrollRange()) {
            a aVar3 = this.f11247a;
            a aVar4 = a.COLLAPSED;
            if (aVar3 != aVar4) {
                mo4928a(appBarLayout, aVar4);
            }
            this.f11247a = aVar4;
            return;
        }
        a aVar5 = this.f11247a;
        a aVar6 = a.IDLE;
        if (aVar5 != aVar6) {
            mo4928a(appBarLayout, aVar6);
        }
        this.f11247a = aVar6;
    }
}
