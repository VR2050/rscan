package p476m.p477a.p485b.p493l0;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4804h;
import p476m.p477a.p485b.InterfaceC4891n;

/* renamed from: m.a.b.l0.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4853a implements InterfaceC4891n {

    /* renamed from: a */
    public C4868p f12427a = new C4868p();

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: c */
    public InterfaceC4800f[] mo5513c(String str) {
        C4868p c4868p = this.f12427a;
        ArrayList arrayList = null;
        for (int i2 = 0; i2 < c4868p.f12472e.size(); i2++) {
            InterfaceC4800f interfaceC4800f = c4868p.f12472e.get(i2);
            if (interfaceC4800f.getName().equalsIgnoreCase(str)) {
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                arrayList.add(interfaceC4800f);
            }
        }
        return arrayList != null ? (InterfaceC4800f[]) arrayList.toArray(new InterfaceC4800f[arrayList.size()]) : C4868p.f12471c;
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: f */
    public InterfaceC4804h mo5514f(String str) {
        return new C4862j(this.f12427a.f12472e, str);
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: g */
    public void mo5515g(InterfaceC4800f[] interfaceC4800fArr) {
        C4868p c4868p = this.f12427a;
        c4868p.f12472e.clear();
        Collections.addAll(c4868p.f12472e, interfaceC4800fArr);
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: j */
    public void mo5516j(String str, String str2) {
        C2354n.m2470e1(str, "Header name");
        C4868p c4868p = this.f12427a;
        C4854b c4854b = new C4854b(str, str2);
        Objects.requireNonNull(c4868p);
        c4868p.f12472e.add(c4854b);
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: l */
    public void mo5517l(InterfaceC4800f interfaceC4800f) {
        C4868p c4868p = this.f12427a;
        Objects.requireNonNull(c4868p);
        if (interfaceC4800f == null) {
            return;
        }
        c4868p.f12472e.add(interfaceC4800f);
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: m */
    public boolean mo5518m(String str) {
        C4868p c4868p = this.f12427a;
        for (int i2 = 0; i2 < c4868p.f12472e.size(); i2++) {
            if (c4868p.f12472e.get(i2).getName().equalsIgnoreCase(str)) {
                return true;
            }
        }
        return false;
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: n */
    public InterfaceC4800f mo5519n(String str) {
        C4868p c4868p = this.f12427a;
        for (int i2 = 0; i2 < c4868p.f12472e.size(); i2++) {
            InterfaceC4800f interfaceC4800f = c4868p.f12472e.get(i2);
            if (interfaceC4800f.getName().equalsIgnoreCase(str)) {
                return interfaceC4800f;
            }
        }
        return null;
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: o */
    public void mo5520o(String str, String str2) {
        C2354n.m2470e1(str, "Header name");
        C4868p c4868p = this.f12427a;
        C4854b c4854b = new C4854b(str, str2);
        Objects.requireNonNull(c4868p);
        for (int i2 = 0; i2 < c4868p.f12472e.size(); i2++) {
            if (c4868p.f12472e.get(i2).getName().equalsIgnoreCase(c4854b.getName())) {
                c4868p.f12472e.set(i2, c4854b);
                return;
            }
        }
        c4868p.f12472e.add(c4854b);
    }

    /* renamed from: p */
    public InterfaceC4804h m5521p() {
        return new C4862j(this.f12427a.f12472e, null);
    }
}
