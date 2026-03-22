package p005b.p199l.p200a.p201a.p236l1;

import com.google.android.exoplayer2.Format;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p236l1.p237m.C2218a;
import p005b.p199l.p200a.p201a.p236l1.p237m.C2220c;
import p005b.p199l.p200a.p201a.p236l1.p238n.C2223a;
import p005b.p199l.p200a.p201a.p236l1.p239o.C2226a;
import p005b.p199l.p200a.p201a.p236l1.p240p.C2228a;
import p005b.p199l.p200a.p201a.p236l1.p241q.C2232a;
import p005b.p199l.p200a.p201a.p236l1.p242r.C2234a;
import p005b.p199l.p200a.p201a.p236l1.p243s.C2239a;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2242b;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2247g;

/* renamed from: b.l.a.a.l1.h */
/* loaded from: classes.dex */
public interface InterfaceC2213h {

    /* renamed from: a */
    public static final InterfaceC2213h f5290a = new a();

    /* renamed from: b.l.a.a.l1.h$a */
    public static class a implements InterfaceC2213h {
        /* renamed from: a */
        public InterfaceC2211f m2052a(Format format) {
            String str = format.f9245l;
            if (str != null) {
                str.hashCode();
                switch (str) {
                    case "application/dvbsubs":
                        return new C2223a(format.f9247n);
                    case "application/pgs":
                        return new C2226a();
                    case "application/x-mp4-vtt":
                        return new C2242b();
                    case "text/vtt":
                        return new C2247g();
                    case "application/x-quicktime-tx3g":
                        return new C2239a(format.f9247n);
                    case "text/x-ssa":
                        return new C2228a(format.f9247n);
                    case "application/x-mp4-cea-608":
                    case "application/cea-608":
                        return new C2218a(str, format.f9234E);
                    case "application/cea-708":
                        return new C2220c(format.f9234E);
                    case "application/x-subrip":
                        return new C2232a();
                    case "application/ttml+xml":
                        return new C2234a();
                }
            }
            throw new IllegalArgumentException(C1499a.m637w("Attempted to create decoder for unsupported MIME type: ", str));
        }
    }
}
