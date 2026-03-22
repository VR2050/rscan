package p005b.p340x.p354b.p355a.p358d;

import android.graphics.PointF;
import android.view.View;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2901j;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* renamed from: b.x.b.a.d.b */
/* loaded from: classes2.dex */
public class C2906b implements InterfaceC2901j {

    /* renamed from: a */
    public PointF f7971a;

    /* renamed from: b */
    public InterfaceC2901j f7972b;

    /* renamed from: c */
    public boolean f7973c = true;

    /* renamed from: a */
    public boolean m3368a(View view) {
        InterfaceC2901j interfaceC2901j = this.f7972b;
        return interfaceC2901j != null ? ((C2906b) interfaceC2901j).m3368a(view) : InterpolatorC2917b.m3380a(view, this.f7971a, this.f7973c);
    }

    /* renamed from: b */
    public boolean m3369b(View view) {
        InterfaceC2901j interfaceC2901j = this.f7972b;
        return interfaceC2901j != null ? ((C2906b) interfaceC2901j).m3369b(view) : InterpolatorC2917b.m3381b(view, this.f7971a);
    }
}
