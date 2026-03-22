package p476m.p477a.p485b.p493l0;

import java.net.Socket;
import p476m.p477a.p485b.InterfaceC4799e0;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4852l;

/* renamed from: m.a.b.l0.e */
/* loaded from: classes3.dex */
public class C4857e extends C4858f implements InterfaceC4852l {

    /* renamed from: f */
    public InterfaceC4846k f12437f;

    public C4857e(Socket socket, InterfaceC4799e0 interfaceC4799e0) {
        super(socket, interfaceC4799e0);
    }

    @Override // p476m.p477a.p485b.InterfaceC4852l
    /* renamed from: b */
    public InterfaceC4846k mo5510b() {
        return this.f12437f;
    }

    @Override // p476m.p477a.p485b.InterfaceC4852l
    /* renamed from: d */
    public void mo5511d(InterfaceC4846k interfaceC4846k) {
        this.f12437f = interfaceC4846k;
    }

    @Override // p476m.p477a.p485b.InterfaceC4852l
    /* renamed from: e */
    public boolean mo5512e() {
        InterfaceC4800f mo5519n = mo5519n("Expect");
        return mo5519n != null && "100-continue".equalsIgnoreCase(mo5519n.getValue());
    }
}
