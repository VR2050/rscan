package p476m.p477a.p485b.p487i0;

import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4846k;

/* renamed from: m.a.b.i0.a */
/* loaded from: classes3.dex */
public abstract class AbstractC4808a implements InterfaceC4846k {

    /* renamed from: c */
    public InterfaceC4800f f12295c;

    /* renamed from: e */
    public InterfaceC4800f f12296e;

    /* renamed from: f */
    public boolean f12297f;

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: f */
    public InterfaceC4800f mo543f() {
        return this.f12296e;
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: g */
    public boolean mo544g() {
        return this.f12297f;
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    public InterfaceC4800f getContentType() {
        return this.f12295c;
    }

    public String toString() {
        StringBuilder m584F = C1499a.m584F('[');
        if (this.f12295c != null) {
            m584F.append("Content-Type: ");
            m584F.append(this.f12295c.getValue());
            m584F.append(',');
        }
        if (this.f12296e != null) {
            m584F.append("Content-Encoding: ");
            m584F.append(this.f12296e.getValue());
            m584F.append(',');
        }
        long mo541c = mo541c();
        if (mo541c >= 0) {
            m584F.append("Content-Length: ");
            m584F.append(mo541c);
            m584F.append(',');
        }
        m584F.append("Chunked: ");
        m584F.append(this.f12297f);
        m584F.append(']');
        return m584F.toString();
    }
}
