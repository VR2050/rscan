package p476m.p477a.p485b.p488j0.p491j;

import java.io.InputStream;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.p492k0.InterfaceC4847a;
import p476m.p477a.p485b.p492k0.InterfaceC4850d;

/* renamed from: m.a.b.j0.j.m */
/* loaded from: classes3.dex */
public class C4842m extends InputStream {

    /* renamed from: c */
    public final InterfaceC4850d f12406c;

    /* renamed from: e */
    public boolean f12407e = false;

    public C4842m(InterfaceC4850d interfaceC4850d) {
        C2354n.m2470e1(interfaceC4850d, "Session input buffer");
        this.f12406c = interfaceC4850d;
    }

    @Override // java.io.InputStream
    public int available() {
        InterfaceC4850d interfaceC4850d = this.f12406c;
        if (interfaceC4850d instanceof InterfaceC4847a) {
            return ((InterfaceC4847a) interfaceC4850d).length();
        }
        return 0;
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f12407e = true;
    }

    @Override // java.io.InputStream
    public int read() {
        if (this.f12407e) {
            return -1;
        }
        return this.f12406c.read();
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i2, int i3) {
        if (this.f12407e) {
            return -1;
        }
        return this.f12406c.read(bArr, i2, i3);
    }
}
