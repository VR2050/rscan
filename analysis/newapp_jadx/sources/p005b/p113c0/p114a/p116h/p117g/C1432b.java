package p005b.p113c0.p114a.p116h.p117g;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.OutputStream;
import java.nio.charset.Charset;
import p005b.p113c0.p114a.p124i.InterfaceC1463i;
import p005b.p113c0.p114a.p130l.C1495g;
import p476m.p477a.p478a.p483b.C4784a;

/* renamed from: b.c0.a.h.g.b */
/* loaded from: classes2.dex */
public class C1432b implements InterfaceC1463i {

    /* renamed from: a */
    public byte[] f1378a;

    /* renamed from: b */
    public C1495g f1379b;

    public C1432b(String str, C1495g c1495g) {
        if (str == null) {
            throw new IllegalArgumentException("The content cannot be null.");
        }
        this.f1379b = c1495g;
        if (c1495g == null) {
            this.f1379b = new C1495g(C1495g.f1510k, C4784a.m5463a("utf-8"));
        }
        Charset m574d = this.f1379b.m574d();
        this.f1378a = str.getBytes(m574d == null ? C4784a.m5463a("utf-8") : m574d);
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1463i
    /* renamed from: a */
    public void mo494a(@NonNull OutputStream outputStream) {
        byte[] bArr = this.f1378a;
        if (bArr != null) {
            outputStream.write(bArr);
            outputStream.flush();
        }
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1463i
    /* renamed from: b */
    public long mo495b() {
        return this.f1378a.length;
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1463i
    @Nullable
    /* renamed from: c */
    public C1495g mo496c() {
        if (this.f1379b.m574d() != null) {
            return this.f1379b;
        }
        Charset m5463a = C4784a.m5463a("utf-8");
        C1495g c1495g = this.f1379b;
        return new C1495g(c1495g.f1512e, c1495g.f1513f, m5463a);
    }
}
