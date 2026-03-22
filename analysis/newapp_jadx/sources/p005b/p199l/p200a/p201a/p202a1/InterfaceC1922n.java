package p005b.p199l.p200a.p201a.p202a1;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.a.a.a1.n */
/* loaded from: classes.dex */
public interface InterfaceC1922n {

    /* renamed from: b.l.a.a.a1.n$a */
    public static final class a extends Exception {
        public a(Throwable th) {
            super(th);
        }

        public a(String str) {
            super(str);
        }
    }

    /* renamed from: b.l.a.a.a1.n$b */
    public static final class b extends Exception {
        /* JADX WARN: Illegal instructions before constructor call */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public b(int r4, int r5, int r6, int r7) {
            /*
                r3 = this;
                java.lang.String r0 = "AudioTrack init failed: "
                java.lang.String r1 = ", Config("
                java.lang.String r2 = ", "
                java.lang.StringBuilder r4 = p005b.p131d.p132a.p133a.C1499a.m589K(r0, r4, r1, r5, r2)
                r4.append(r6)
                r4.append(r2)
                r4.append(r7)
                java.lang.String r5 = ")"
                r4.append(r5)
                java.lang.String r4 = r4.toString()
                r3.<init>(r4)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p202a1.InterfaceC1922n.b.<init>(int, int, int, int):void");
        }
    }

    /* renamed from: b.l.a.a.a1.n$c */
    public interface c {
    }

    /* renamed from: b.l.a.a.a1.n$d */
    public static final class d extends Exception {
        public d(int i2) {
            super(C1499a.m626l("AudioTrack write failed: ", i2));
        }
    }
}
