package p476m.p477a.p485b.p493l0;

import java.util.Locale;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.C4902v;
import p476m.p477a.p485b.InterfaceC4797d0;
import p476m.p477a.p485b.InterfaceC4801f0;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4898r;

/* renamed from: m.a.b.l0.g */
/* loaded from: classes3.dex */
public class C4859g extends AbstractC4853a implements InterfaceC4898r {

    /* renamed from: b */
    public InterfaceC4801f0 f12442b;

    /* renamed from: c */
    public C4795c0 f12443c;

    /* renamed from: d */
    public int f12444d;

    /* renamed from: e */
    public String f12445e;

    /* renamed from: f */
    public InterfaceC4846k f12446f;

    /* renamed from: g */
    public final InterfaceC4797d0 f12447g;

    /* renamed from: h */
    public Locale f12448h;

    public C4859g(InterfaceC4801f0 interfaceC4801f0, InterfaceC4797d0 interfaceC4797d0, Locale locale) {
        C2354n.m2470e1(interfaceC4801f0, "Status line");
        this.f12442b = interfaceC4801f0;
        C4865m c4865m = (C4865m) interfaceC4801f0;
        this.f12443c = c4865m.f12461c;
        this.f12444d = c4865m.f12462e;
        this.f12445e = c4865m.f12463f;
        this.f12447g = interfaceC4797d0;
        this.f12448h = locale;
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: a */
    public C4795c0 mo5524a() {
        return this.f12443c;
    }

    @Override // p476m.p477a.p485b.InterfaceC4898r
    /* renamed from: b */
    public InterfaceC4846k mo5526b() {
        return this.f12446f;
    }

    @Override // p476m.p477a.p485b.InterfaceC4898r
    /* renamed from: d */
    public void mo5527d(InterfaceC4846k interfaceC4846k) {
        this.f12446f = interfaceC4846k;
    }

    @Override // p476m.p477a.p485b.InterfaceC4898r
    /* renamed from: h */
    public InterfaceC4801f0 mo5528h() {
        if (this.f12442b == null) {
            C4795c0 c4795c0 = this.f12443c;
            if (c4795c0 == null) {
                c4795c0 = C4902v.f12501i;
            }
            int i2 = this.f12444d;
            String str = this.f12445e;
            if (str == null) {
                InterfaceC4797d0 interfaceC4797d0 = this.f12447g;
                if (interfaceC4797d0 != null) {
                    Locale locale = this.f12448h;
                    if (locale == null) {
                        locale = Locale.getDefault();
                    }
                    str = interfaceC4797d0.mo5472a(i2, locale);
                } else {
                    str = null;
                }
            }
            this.f12442b = new C4865m(c4795c0, i2, str);
        }
        return this.f12442b;
    }

    @Override // p476m.p477a.p485b.InterfaceC4898r
    /* renamed from: i */
    public void mo5529i(int i2) {
        C2354n.m2462c1(i2, "Status code");
        this.f12442b = null;
        this.f12444d = i2;
        this.f12445e = null;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(mo5528h());
        sb.append(' ');
        sb.append(this.f12427a);
        if (this.f12446f != null) {
            sb.append(' ');
            sb.append(this.f12446f);
        }
        return sb.toString();
    }
}
