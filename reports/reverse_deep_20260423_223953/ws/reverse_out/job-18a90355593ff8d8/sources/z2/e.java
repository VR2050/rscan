package z2;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* JADX INFO: loaded from: classes.dex */
final class e implements y2.c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final CharSequence f10552a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10553b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f10554c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final s2.p f10555d;

    public static final class a implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f10556a = -1;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f10557b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f10558c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private w2.c f10559d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f10560e;

        a() {
            int iF = w2.d.f(e.this.f10553b, 0, e.this.f10552a.length());
            this.f10557b = iF;
            this.f10558c = iF;
        }

        /* JADX WARN: Removed duplicated region for block: B:9:0x0023  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        private final void a() {
            /*
                r6 = this;
                int r0 = r6.f10558c
                r1 = 0
                if (r0 >= 0) goto Lc
                r6.f10556a = r1
                r0 = 0
                r6.f10559d = r0
                goto L9e
            Lc:
                z2.e r0 = z2.e.this
                int r0 = z2.e.d(r0)
                r2 = -1
                r3 = 1
                if (r0 <= 0) goto L23
                int r0 = r6.f10560e
                int r0 = r0 + r3
                r6.f10560e = r0
                z2.e r4 = z2.e.this
                int r4 = z2.e.d(r4)
                if (r0 >= r4) goto L31
            L23:
                int r0 = r6.f10558c
                z2.e r4 = z2.e.this
                java.lang.CharSequence r4 = z2.e.c(r4)
                int r4 = r4.length()
                if (r0 <= r4) goto L47
            L31:
                w2.c r0 = new w2.c
                int r1 = r6.f10557b
                z2.e r4 = z2.e.this
                java.lang.CharSequence r4 = z2.e.c(r4)
                int r4 = z2.q.D(r4)
                r0.<init>(r1, r4)
                r6.f10559d = r0
                r6.f10558c = r2
                goto L9c
            L47:
                z2.e r0 = z2.e.this
                s2.p r0 = z2.e.b(r0)
                z2.e r4 = z2.e.this
                java.lang.CharSequence r4 = z2.e.c(r4)
                int r5 = r6.f10558c
                java.lang.Integer r5 = java.lang.Integer.valueOf(r5)
                java.lang.Object r0 = r0.b(r4, r5)
                h2.i r0 = (h2.C0563i) r0
                if (r0 != 0) goto L77
                w2.c r0 = new w2.c
                int r1 = r6.f10557b
                z2.e r4 = z2.e.this
                java.lang.CharSequence r4 = z2.e.c(r4)
                int r4 = z2.q.D(r4)
                r0.<init>(r1, r4)
                r6.f10559d = r0
                r6.f10558c = r2
                goto L9c
            L77:
                java.lang.Object r2 = r0.a()
                java.lang.Number r2 = (java.lang.Number) r2
                int r2 = r2.intValue()
                java.lang.Object r0 = r0.b()
                java.lang.Number r0 = (java.lang.Number) r0
                int r0 = r0.intValue()
                int r4 = r6.f10557b
                w2.c r4 = w2.d.i(r4, r2)
                r6.f10559d = r4
                int r2 = r2 + r0
                r6.f10557b = r2
                if (r0 != 0) goto L99
                r1 = r3
            L99:
                int r2 = r2 + r1
                r6.f10558c = r2
            L9c:
                r6.f10556a = r3
            L9e:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: z2.e.a.a():void");
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public w2.c next() {
            if (this.f10556a == -1) {
                a();
            }
            if (this.f10556a == 0) {
                throw new NoSuchElementException();
            }
            w2.c cVar = this.f10559d;
            t2.j.d(cVar, "null cannot be cast to non-null type kotlin.ranges.IntRange");
            this.f10559d = null;
            this.f10556a = -1;
            return cVar;
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.f10556a == -1) {
                a();
            }
            return this.f10556a == 1;
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public e(CharSequence charSequence, int i3, int i4, s2.p pVar) {
        t2.j.f(charSequence, "input");
        t2.j.f(pVar, "getNextMatch");
        this.f10552a = charSequence;
        this.f10553b = i3;
        this.f10554c = i4;
        this.f10555d = pVar;
    }

    @Override // y2.c
    public Iterator iterator() {
        return new a();
    }
}
