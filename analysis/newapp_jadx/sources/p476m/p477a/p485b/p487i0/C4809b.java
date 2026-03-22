package p476m.p477a.p485b.p487i0;

import java.io.InputStream;
import java.io.OutputStream;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p477a.p485b.p488j0.p491j.C4840k;

/* renamed from: m.a.b.i0.b */
/* loaded from: classes3.dex */
public class C4809b extends AbstractC4808a {

    /* renamed from: g */
    public InputStream f12298g;

    /* renamed from: h */
    public long f12299h = -1;

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: a */
    public void mo540a(OutputStream outputStream) {
        C2354n.m2470e1(outputStream, "Output stream");
        InputStream mo542d = mo542d();
        try {
            byte[] bArr = new byte[4096];
            while (true) {
                int read = mo542d.read(bArr);
                if (read == -1) {
                    return;
                } else {
                    outputStream.write(bArr, 0, read);
                }
            }
        } finally {
            mo542d.close();
        }
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: c */
    public long mo541c() {
        return this.f12299h;
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: d */
    public InputStream mo542d() {
        InputStream inputStream = this.f12298g;
        if (inputStream != null) {
            return inputStream;
        }
        throw new IllegalStateException("Content has not been provided");
    }

    @Override // p476m.p477a.p485b.InterfaceC4846k
    /* renamed from: h */
    public boolean mo545h() {
        InputStream inputStream = this.f12298g;
        return (inputStream == null || inputStream == C4840k.f12404c) ? false : true;
    }
}
