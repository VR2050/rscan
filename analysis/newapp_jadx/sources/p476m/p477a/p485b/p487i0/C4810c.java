package p476m.p477a.p485b.p487i0;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: m.a.b.i0.c */
/* loaded from: classes3.dex */
public class C4810c extends AbstractC4808a implements Cloneable {

    /* renamed from: g */
    public final byte[] f12300g;

    /* renamed from: h */
    public final int f12301h;

    public C4810c(byte[] bArr) {
        C2354n.m2470e1(bArr, "Source byte array");
        this.f12300g = bArr;
        this.f12301h = bArr.length;
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: a */
    public void mo540a(OutputStream outputStream) {
        C2354n.m2470e1(outputStream, "Output stream");
        outputStream.write(this.f12300g, 0, this.f12301h);
        outputStream.flush();
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: c */
    public long mo541c() {
        return this.f12301h;
    }

    public Object clone() {
        return super.clone();
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: d */
    public InputStream mo542d() {
        return new ByteArrayInputStream(this.f12300g, 0, this.f12301h);
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: h */
    public boolean mo545h() {
        return false;
    }
}
