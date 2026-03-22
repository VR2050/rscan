package p476m.p477a.p485b.p493l0;

import java.net.Socket;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.C4795c0;
import p476m.p477a.p485b.C4902v;
import p476m.p477a.p485b.InterfaceC4799e0;
import p476m.p477a.p485b.InterfaceC4895o;

/* renamed from: m.a.b.l0.f */
/* loaded from: classes3.dex */
public class C4858f extends AbstractC4853a implements InterfaceC4895o {

    /* renamed from: b */
    public final Socket f12438b;

    /* renamed from: c */
    public final String f12439c;

    /* renamed from: d */
    public final String f12440d;

    /* renamed from: e */
    public InterfaceC4799e0 f12441e;

    public C4858f(Socket socket, InterfaceC4799e0 interfaceC4799e0) {
        this.f12438b = socket;
        C2354n.m2470e1(interfaceC4799e0, "Request line");
        this.f12441e = interfaceC4799e0;
        this.f12439c = interfaceC4799e0.mo5474d();
        this.f12440d = interfaceC4799e0.getUri();
    }

    @Override // p476m.p477a.p485b.InterfaceC4891n
    /* renamed from: a */
    public C4795c0 mo5524a() {
        return mo5525k().mo5473a();
    }

    @Override // p476m.p477a.p485b.InterfaceC4895o
    /* renamed from: k */
    public InterfaceC4799e0 mo5525k() {
        if (this.f12441e == null) {
            this.f12441e = new C4864l(this.f12439c, this.f12440d, C4902v.f12501i);
        }
        return this.f12441e;
    }

    public String toString() {
        return this.f12439c + ' ' + this.f12440d + ' ' + this.f12427a;
    }
}
