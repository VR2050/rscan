package p005b.p199l.p258c.p260c0.p261a0;

import java.util.Map;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2493w;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.InterfaceC2469d;
import p005b.p199l.p258c.p260c0.C2449g;
import p005b.p199l.p258c.p260c0.C2457o;
import p005b.p199l.p258c.p260c0.InterfaceC2462t;
import p005b.p199l.p258c.p260c0.p263b0.AbstractC2443b;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.j */
/* loaded from: classes2.dex */
public final class C2430j implements InterfaceC2415a0 {

    /* renamed from: c */
    public final C2449g f6492c;

    /* renamed from: e */
    public final InterfaceC2469d f6493e;

    /* renamed from: f */
    public final C2457o f6494f;

    /* renamed from: g */
    public final C2424d f6495g;

    /* renamed from: h */
    public final AbstractC2443b f6496h = AbstractC2443b.f6583a;

    /* renamed from: b.l.c.c0.a0.j$a */
    public static final class a<T> extends AbstractC2496z<T> {

        /* renamed from: a */
        public final InterfaceC2462t<T> f6497a;

        /* renamed from: b */
        public final Map<String, b> f6498b;

        public a(InterfaceC2462t<T> interfaceC2462t, Map<String, b> map) {
            this.f6497a = interfaceC2462t;
            this.f6498b = map;
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: b */
        public T mo2766b(C2472a c2472a) {
            if (c2472a.mo2777Z() == EnumC2473b.NULL) {
                c2472a.mo2775V();
                return null;
            }
            T mo2810a = this.f6497a.mo2810a();
            try {
                c2472a.mo2779d();
                while (c2472a.mo2787t()) {
                    b bVar = this.f6498b.get(c2472a.mo2774S());
                    if (bVar != null && bVar.f6501c) {
                        bVar.mo2801a(c2472a, mo2810a);
                    }
                    c2472a.mo2780e0();
                }
                c2472a.mo2786q();
                return mo2810a;
            } catch (IllegalAccessException e2) {
                throw new AssertionError(e2);
            } catch (IllegalStateException e3) {
                throw new C2493w(e3);
            }
        }

        @Override // p005b.p199l.p258c.AbstractC2496z
        /* renamed from: c */
        public void mo2767c(C2474c c2474c, T t) {
            if (t == null) {
                c2474c.mo2800v();
                return;
            }
            c2474c.mo2796e();
            try {
                for (b bVar : this.f6498b.values()) {
                    if (bVar.mo2803c(t)) {
                        c2474c.mo2799s(bVar.f6499a);
                        bVar.mo2802b(c2474c, t);
                    }
                }
                c2474c.mo2798q();
            } catch (IllegalAccessException e2) {
                throw new AssertionError(e2);
            }
        }
    }

    /* renamed from: b.l.c.c0.a0.j$b */
    public static abstract class b {

        /* renamed from: a */
        public final String f6499a;

        /* renamed from: b */
        public final boolean f6500b;

        /* renamed from: c */
        public final boolean f6501c;

        public b(String str, boolean z, boolean z2) {
            this.f6499a = str;
            this.f6500b = z;
            this.f6501c = z2;
        }

        /* renamed from: a */
        public abstract void mo2801a(C2472a c2472a, Object obj);

        /* renamed from: b */
        public abstract void mo2802b(C2474c c2474c, Object obj);

        /* renamed from: c */
        public abstract boolean mo2803c(Object obj);
    }

    public C2430j(C2449g c2449g, InterfaceC2469d interfaceC2469d, C2457o c2457o, C2424d c2424d) {
        this.f6492c = c2449g;
        this.f6493e = interfaceC2469d;
        this.f6494f = c2457o;
        this.f6495g = c2424d;
    }

    /*  JADX ERROR: NullPointerException in pass: ConstructorVisitor
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.RegisterArg.sameRegAndSVar(jadx.core.dex.instructions.args.InsnArg)" because "resultArg" is null
        	at jadx.core.dex.visitors.MoveInlineVisitor.processMove(MoveInlineVisitor.java:52)
        	at jadx.core.dex.visitors.MoveInlineVisitor.moveInline(MoveInlineVisitor.java:41)
        	at jadx.core.dex.visitors.ConstructorVisitor.visit(ConstructorVisitor.java:43)
        */
    @Override // p005b.p199l.p258c.InterfaceC2415a0
    /* renamed from: a */
    public <T> p005b.p199l.p258c.AbstractC2496z<T> mo2753a(
    /*  JADX ERROR: Method generation error
        jadx.core.utils.exceptions.JadxRuntimeException: Code variable not set in r36v0 ??
        	at jadx.core.dex.instructions.args.SSAVar.getCodeVar(SSAVar.java:238)
        	at jadx.core.codegen.MethodGen.addMethodArguments(MethodGen.java:223)
        	at jadx.core.codegen.MethodGen.addDefinition(MethodGen.java:168)
        	at jadx.core.codegen.ClassGen.addMethodCode(ClassGen.java:401)
        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:335)
        	at jadx.core.codegen.ClassGen.lambda$addInnerClsAndMethods$3(ClassGen.java:301)
        	at java.base/java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:184)
        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1596)
        	at java.base/java.util.stream.SortedOps$RefSortingSink.end(SortedOps.java:395)
        	at java.base/java.util.stream.Sink$ChainedReference.end(Sink.java:261)
        */
    /*  JADX ERROR: NullPointerException in pass: ConstructorVisitor
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.RegisterArg.sameRegAndSVar(jadx.core.dex.instructions.args.InsnArg)" because "resultArg" is null
        	at jadx.core.dex.visitors.MoveInlineVisitor.processMove(MoveInlineVisitor.java:52)
        	at jadx.core.dex.visitors.MoveInlineVisitor.moveInline(MoveInlineVisitor.java:41)
        */

    /* JADX WARN: Removed duplicated region for block: B:27:? A[RETURN, SYNTHETIC] */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m2804b(java.lang.reflect.Field r6, boolean r7) {
        /*
            r5 = this;
            b.l.c.c0.o r0 = r5.f6494f
            java.lang.Class r1 = r6.getType()
            boolean r2 = r0.m2814d(r1)
            r3 = 1
            r4 = 0
            if (r2 != 0) goto L17
            boolean r1 = r0.m2813c(r1, r7)
            if (r1 == 0) goto L15
            goto L17
        L15:
            r1 = 0
            goto L18
        L17:
            r1 = 1
        L18:
            if (r1 != 0) goto L63
            int r1 = r6.getModifiers()
            r1 = r1 & 136(0x88, float:1.9E-43)
            if (r1 == 0) goto L23
            goto L5d
        L23:
            boolean r1 = r6.isSynthetic()
            if (r1 == 0) goto L2a
            goto L5d
        L2a:
            java.lang.Class r1 = r6.getType()
            boolean r1 = r0.m2814d(r1)
            if (r1 == 0) goto L35
            goto L5d
        L35:
            if (r7 == 0) goto L3a
            java.util.List<b.l.c.a> r7 = r0.f6599e
            goto L3c
        L3a:
            java.util.List<b.l.c.a> r7 = r0.f6600f
        L3c:
            boolean r0 = r7.isEmpty()
            if (r0 != 0) goto L5f
            b.l.c.b r0 = new b.l.c.b
            r0.<init>(r6)
            java.util.Iterator r6 = r7.iterator()
        L4b:
            boolean r7 = r6.hasNext()
            if (r7 == 0) goto L5f
            java.lang.Object r7 = r6.next()
            b.l.c.a r7 = (p005b.p199l.p258c.InterfaceC2414a) r7
            boolean r7 = r7.m2751a(r0)
            if (r7 == 0) goto L4b
        L5d:
            r6 = 1
            goto L60
        L5f:
            r6 = 0
        L60:
            if (r6 != 0) goto L63
            goto L64
        L63:
            r3 = 0
        L64:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.p260c0.p261a0.C2430j.m2804b(java.lang.reflect.Field, boolean):boolean");
    }
}
