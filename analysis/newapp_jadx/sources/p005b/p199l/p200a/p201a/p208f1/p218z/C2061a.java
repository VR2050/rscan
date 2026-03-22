package p005b.p199l.p200a.p201a.p208f1.p218z;

import android.util.Pair;
import com.google.android.exoplayer2.Format;
import com.luck.picture.lib.config.PictureMimeType;
import java.util.Collections;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d;
import p005b.p199l.p200a.p201a.p250p1.C2347g;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.z.a */
/* loaded from: classes.dex */
public final class C2061a extends AbstractC2064d {

    /* renamed from: b */
    public static final int[] f4247b = {5512, 11025, 22050, 44100};

    /* renamed from: c */
    public boolean f4248c;

    /* renamed from: d */
    public boolean f4249d;

    /* renamed from: e */
    public int f4250e;

    public C2061a(InterfaceC2052s interfaceC2052s) {
        super(interfaceC2052s);
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d
    /* renamed from: b */
    public boolean mo1644b(C2360t c2360t) {
        if (this.f4248c) {
            c2360t.m2568D(1);
        } else {
            int m2585q = c2360t.m2585q();
            int i2 = (m2585q >> 4) & 15;
            this.f4250e = i2;
            if (i2 == 2) {
                this.f4268a.mo1615d(Format.m4024A(null, PictureMimeType.MIME_TYPE_AUDIO, null, -1, -1, 1, f4247b[(m2585q >> 2) & 3], null, null, 0, null));
                this.f4249d = true;
            } else if (i2 == 7 || i2 == 8) {
                this.f4268a.mo1615d(Format.m4039z(null, i2 == 7 ? "audio/g711-alaw" : "audio/g711-mlaw", null, -1, -1, 1, 8000, -1, null, null, 0, null));
                this.f4249d = true;
            } else if (i2 != 10) {
                StringBuilder m586H = C1499a.m586H("Audio format not supported: ");
                m586H.append(this.f4250e);
                throw new AbstractC2064d.a(m586H.toString());
            }
            this.f4248c = true;
        }
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p218z.AbstractC2064d
    /* renamed from: c */
    public boolean mo1645c(C2360t c2360t, long j2) {
        if (this.f4250e == 2) {
            int m2569a = c2360t.m2569a();
            this.f4268a.mo1613b(c2360t, m2569a);
            this.f4268a.mo1614c(j2, 1, m2569a, 0, null);
            return true;
        }
        int m2585q = c2360t.m2585q();
        if (m2585q != 0 || this.f4249d) {
            if (this.f4250e == 10 && m2585q != 1) {
                return false;
            }
            int m2569a2 = c2360t.m2569a();
            this.f4268a.mo1613b(c2360t, m2569a2);
            this.f4268a.mo1614c(j2, 1, m2569a2, 0, null);
            return true;
        }
        int m2569a3 = c2360t.m2569a();
        byte[] bArr = new byte[m2569a3];
        System.arraycopy(c2360t.f6133a, c2360t.f6134b, bArr, 0, m2569a3);
        c2360t.f6134b += m2569a3;
        Pair<Integer, Integer> m2358d = C2347g.m2358d(new C2359s(bArr), false);
        this.f4268a.mo1615d(Format.m4024A(null, "audio/mp4a-latm", null, -1, -1, ((Integer) m2358d.second).intValue(), ((Integer) m2358d.first).intValue(), Collections.singletonList(bArr), null, 0, null));
        this.f4249d = true;
        return false;
    }
}
