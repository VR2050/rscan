package p005b.p143g.p144a.p147m;

import com.bumptech.glide.load.ImageHeaderParser;
import java.io.FileInputStream;
import java.io.IOException;
import p005b.p143g.p144a.p147m.p148s.C1599m;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p156v.p157c.C1719x;

/* renamed from: b.g.a.m.g */
/* loaded from: classes.dex */
public class C1575g implements InterfaceC1578j {

    /* renamed from: a */
    public final /* synthetic */ C1599m f1984a;

    /* renamed from: b */
    public final /* synthetic */ InterfaceC1612b f1985b;

    public C1575g(C1599m c1599m, InterfaceC1612b interfaceC1612b) {
        this.f1984a = c1599m;
        this.f1985b = interfaceC1612b;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1578j
    /* renamed from: a */
    public ImageHeaderParser.ImageType mo823a(ImageHeaderParser imageHeaderParser) {
        C1719x c1719x = null;
        try {
            C1719x c1719x2 = new C1719x(new FileInputStream(this.f1984a.mo841a().getFileDescriptor()), this.f1985b);
            try {
                ImageHeaderParser.ImageType mo997b = imageHeaderParser.mo997b(c1719x2);
                try {
                    c1719x2.close();
                } catch (IOException unused) {
                }
                this.f1984a.mo841a();
                return mo997b;
            } catch (Throwable th) {
                th = th;
                c1719x = c1719x2;
                if (c1719x != null) {
                    try {
                        c1719x.close();
                    } catch (IOException unused2) {
                    }
                }
                this.f1984a.mo841a();
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }
}
