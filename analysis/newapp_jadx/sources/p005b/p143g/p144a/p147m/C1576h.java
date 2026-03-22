package p005b.p143g.p144a.p147m;

import com.bumptech.glide.load.ImageHeaderParser;
import java.io.FileInputStream;
import java.io.IOException;
import p005b.p143g.p144a.p147m.p148s.C1599m;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p156v.p157c.C1719x;

/* renamed from: b.g.a.m.h */
/* loaded from: classes.dex */
public class C1576h implements InterfaceC1577i {

    /* renamed from: a */
    public final /* synthetic */ C1599m f1986a;

    /* renamed from: b */
    public final /* synthetic */ InterfaceC1612b f1987b;

    public C1576h(C1599m c1599m, InterfaceC1612b interfaceC1612b) {
        this.f1986a = c1599m;
        this.f1987b = interfaceC1612b;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1577i
    /* renamed from: a */
    public int mo824a(ImageHeaderParser imageHeaderParser) {
        C1719x c1719x = null;
        try {
            C1719x c1719x2 = new C1719x(new FileInputStream(this.f1986a.mo841a().getFileDescriptor()), this.f1987b);
            try {
                int mo998c = imageHeaderParser.mo998c(c1719x2, this.f1987b);
                try {
                    c1719x2.close();
                } catch (IOException unused) {
                }
                this.f1986a.mo841a();
                return mo998c;
            } catch (Throwable th) {
                th = th;
                c1719x = c1719x2;
                if (c1719x != null) {
                    try {
                        c1719x.close();
                    } catch (IOException unused2) {
                    }
                }
                this.f1986a.mo841a();
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }
}
