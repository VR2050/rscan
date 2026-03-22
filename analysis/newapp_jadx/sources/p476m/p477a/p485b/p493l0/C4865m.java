package p476m.p477a.p485b.p493l0;

import java.io.Serializable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.InterfaceC4801f0;

/* renamed from: m.a.b.l0.m */
/* loaded from: classes3.dex */
public class C4865m implements InterfaceC4801f0, Cloneable, Serializable {
    private static final long serialVersionUID = -2443303766890459269L;

    /* renamed from: c */
    public final C4795c0 f12461c;

    /* renamed from: e */
    public final int f12462e;

    /* renamed from: f */
    public final String f12463f;

    public C4865m(C4795c0 c4795c0, int i2, String str) {
        C2354n.m2470e1(c4795c0, "Version");
        this.f12461c = c4795c0;
        C2354n.m2462c1(i2, "Status code");
        this.f12462e = i2;
        this.f12463f = str;
    }

    @Override // p476m.p477a.p485b.InterfaceC4801f0
    /* renamed from: a */
    public C4795c0 mo5475a() {
        return this.f12461c;
    }

    @Override // p476m.p477a.p485b.InterfaceC4801f0
    /* renamed from: c */
    public int mo5476c() {
        return this.f12462e;
    }

    public Object clone() {
        return super.clone();
    }

    @Override // p476m.p477a.p485b.InterfaceC4801f0
    /* renamed from: d */
    public String mo5477d() {
        return this.f12463f;
    }

    public String toString() {
        return C4860h.f12449a.m5533d(null, this).toString();
    }
}
