package p005b.p199l.p200a.p201a.p220h1;

import com.google.android.exoplayer2.Format;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p220h1.p221g.C2084a;
import p005b.p199l.p200a.p201a.p220h1.p222h.C2086a;
import p005b.p199l.p200a.p201a.p220h1.p223i.C2088b;
import p005b.p199l.p200a.p201a.p220h1.p224j.C2089a;

/* renamed from: b.l.a.a.h1.c */
/* loaded from: classes.dex */
public interface InterfaceC2080c {

    /* renamed from: a */
    public static final InterfaceC2080c f4370a = new a();

    /* renamed from: b.l.a.a.h1.c$a */
    public static class a implements InterfaceC2080c {
        @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2080c
        /* renamed from: a */
        public boolean mo1706a(Format format) {
            String str = format.f9245l;
            return "application/id3".equals(str) || "application/x-emsg".equals(str) || "application/x-scte35".equals(str) || "application/x-icy".equals(str);
        }

        @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2080c
        /* renamed from: b */
        public InterfaceC2079b mo1707b(Format format) {
            String str = format.f9245l;
            if (str != null) {
                str.hashCode();
                switch (str) {
                    case "application/x-icy":
                        return new C2086a();
                    case "application/id3":
                        return new C2088b();
                    case "application/x-emsg":
                        return new C2084a();
                    case "application/x-scte35":
                        return new C2089a();
                }
            }
            throw new IllegalArgumentException(C1499a.m637w("Attempted to create decoder for unsupported MIME type: ", str));
        }
    }

    /* renamed from: a */
    boolean mo1706a(Format format);

    /* renamed from: b */
    InterfaceC2079b mo1707b(Format format);
}
