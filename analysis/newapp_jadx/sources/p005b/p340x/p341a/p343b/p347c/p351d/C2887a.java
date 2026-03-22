package p005b.p340x.p341a.p343b.p347c.p351d;

import android.graphics.PointF;
import android.view.View;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2886g;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;

/* renamed from: b.x.a.b.c.d.a */
/* loaded from: classes2.dex */
public class C2887a implements InterfaceC2886g {

    /* renamed from: a */
    public PointF f7896a;

    /* renamed from: b */
    public InterfaceC2886g f7897b;

    /* renamed from: c */
    public boolean f7898c = true;

    @Override // p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2886g
    /* renamed from: a */
    public boolean mo3329a(View view) {
        InterfaceC2886g interfaceC2886g = this.f7897b;
        return interfaceC2886g != null ? interfaceC2886g.mo3329a(view) : InterpolatorC2889b.m3332b(view, this.f7896a);
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2886g
    /* renamed from: b */
    public boolean mo3330b(View view) {
        InterfaceC2886g interfaceC2886g = this.f7897b;
        return interfaceC2886g != null ? interfaceC2886g.mo3330b(view) : InterpolatorC2889b.m3331a(view, this.f7896a, this.f7898c);
    }
}
