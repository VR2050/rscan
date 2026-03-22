package p005b.p006a.p007a.p008a.p009a;

import android.graphics.drawable.Drawable;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p150t.C1650r;
import p005b.p143g.p144a.p166q.InterfaceC1778e;
import p005b.p143g.p144a.p166q.p167i.InterfaceC1790i;

/* renamed from: b.a.a.a.a.x */
/* loaded from: classes2.dex */
public final class C0876x implements InterfaceC1778e<Drawable> {

    /* renamed from: c */
    public final /* synthetic */ InterfaceC0877y f320c;

    public C0876x(InterfaceC0877y interfaceC0877y) {
        this.f320c = interfaceC0877y;
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1778e
    /* renamed from: a */
    public boolean mo207a(@Nullable C1650r c1650r, Object obj, InterfaceC1790i<Drawable> interfaceC1790i, boolean z) {
        InterfaceC0877y interfaceC0877y = this.f320c;
        if (interfaceC0877y == null) {
            return false;
        }
        interfaceC0877y.loadError();
        return false;
    }

    @Override // p005b.p143g.p144a.p166q.InterfaceC1778e
    /* renamed from: b */
    public boolean mo208b(Drawable drawable, Object obj, InterfaceC1790i<Drawable> interfaceC1790i, EnumC1569a enumC1569a, boolean z) {
        Drawable drawable2 = drawable;
        InterfaceC0877y interfaceC0877y = this.f320c;
        if (interfaceC0877y == null || drawable2 == null) {
            return false;
        }
        interfaceC0877y.loadReady(drawable2);
        return false;
    }
}
