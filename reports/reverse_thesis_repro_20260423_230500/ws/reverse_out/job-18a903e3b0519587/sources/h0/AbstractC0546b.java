package h0;

/* JADX INFO: renamed from: h0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0546b implements InterfaceC0549e {
    @Override // h0.InterfaceC0549e
    public void a(InterfaceC0547c interfaceC0547c) {
        boolean zE = interfaceC0547c.e();
        try {
            f(interfaceC0547c);
        } finally {
            if (zE) {
                interfaceC0547c.close();
            }
        }
    }

    @Override // h0.InterfaceC0549e
    public void c(InterfaceC0547c interfaceC0547c) {
        try {
            e(interfaceC0547c);
        } finally {
            interfaceC0547c.close();
        }
    }

    protected abstract void e(InterfaceC0547c interfaceC0547c);

    protected abstract void f(InterfaceC0547c interfaceC0547c);

    @Override // h0.InterfaceC0549e
    public void b(InterfaceC0547c interfaceC0547c) {
    }

    @Override // h0.InterfaceC0549e
    public void d(InterfaceC0547c interfaceC0547c) {
    }
}
