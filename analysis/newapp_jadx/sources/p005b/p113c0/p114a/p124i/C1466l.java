package p005b.p113c0.p114a.p124i;

import java.io.InputStream;
import java.io.OutputStream;
import p005b.p113c0.p114a.p124i.p125n.C1470c;
import p005b.p113c0.p114a.p124i.p125n.InterfaceC1469b;
import p005b.p113c0.p114a.p130l.C1495g;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4898r;
import p476m.p477a.p485b.p493l0.C4854b;

/* renamed from: b.c0.a.i.l */
/* loaded from: classes2.dex */
public class C1466l implements InterfaceC1458d {

    /* renamed from: a */
    public static final InterfaceC1469b f1436a = new C1470c();

    /* renamed from: b */
    public InterfaceC4898r f1437b;

    /* renamed from: b.c0.a.i.l$b */
    public static class b implements InterfaceC4846k {

        /* renamed from: c */
        public InterfaceC1463i f1438c;

        public b(InterfaceC1463i interfaceC1463i, a aVar) {
            this.f1438c = interfaceC1463i;
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        /* renamed from: a */
        public void mo540a(OutputStream outputStream) {
            this.f1438c.mo494a(outputStream);
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        /* renamed from: c */
        public long mo541c() {
            return this.f1438c.mo495b();
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        /* renamed from: d */
        public InputStream mo542d() {
            return null;
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        /* renamed from: f */
        public InterfaceC4800f mo543f() {
            return null;
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        /* renamed from: g */
        public boolean mo544g() {
            return false;
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        public InterfaceC4800f getContentType() {
            C1495g mo496c = this.f1438c.mo496c();
            if (mo496c == null) {
                return null;
            }
            return new C4854b("Content-Type", mo496c.toString());
        }

        @Override // p476m.p477a.p485b.InterfaceC4846k
        /* renamed from: h */
        public boolean mo545h() {
            return false;
        }
    }

    public C1466l(InterfaceC4898r interfaceC4898r) {
        this.f1437b = interfaceC4898r;
    }

    /* renamed from: a */
    public void m539a(InterfaceC1463i interfaceC1463i) {
        this.f1437b.mo5527d(new b(interfaceC1463i, null));
    }
}
