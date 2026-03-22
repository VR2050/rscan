package p476m.p477a.p485b.p488j0.p489h;

import java.io.IOException;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.InterfaceC4796d;
import p476m.p477a.p485b.InterfaceC4901u;
import p476m.p477a.p485b.p494m0.C4874a;
import p476m.p477a.p485b.p494m0.C4878e;
import p476m.p477a.p485b.p494m0.C4883j;

/* renamed from: m.a.b.j0.h.f */
/* loaded from: classes3.dex */
public class RunnableC4825f implements Runnable {

    /* renamed from: c */
    public final C4883j f12358c;

    /* renamed from: e */
    public final InterfaceC4901u f12359e;

    /* renamed from: f */
    public final InterfaceC4796d f12360f;

    public RunnableC4825f(C4883j c4883j, InterfaceC4901u interfaceC4901u, InterfaceC4796d interfaceC4796d) {
        this.f12358c = c4883j;
        this.f12359e = interfaceC4901u;
        this.f12360f = interfaceC4796d;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.lang.Runnable
    public void run() {
        InterfaceC4901u interfaceC4901u;
        try {
            try {
                try {
                    C4874a c4874a = new C4874a();
                    C2354n.m2470e1(c4874a, "HTTP context");
                    C4878e c4878e = c4874a instanceof C4878e ? (C4878e) c4874a : new C4878e(c4874a);
                    while (!Thread.interrupted() && this.f12359e.isOpen()) {
                        this.f12358c.m5553c(this.f12359e, c4878e);
                        c4874a.f12476a.clear();
                    }
                    this.f12359e.close();
                    interfaceC4901u = this.f12359e;
                } catch (Exception e2) {
                    this.f12360f.mo5471a(e2);
                    interfaceC4901u = this.f12359e;
                }
                interfaceC4901u.shutdown();
            } catch (IOException e3) {
                this.f12360f.mo5471a(e3);
            }
        } catch (Throwable th) {
            try {
                this.f12359e.shutdown();
            } catch (IOException e4) {
                this.f12360f.mo5471a(e4);
            }
            throw th;
        }
    }
}
