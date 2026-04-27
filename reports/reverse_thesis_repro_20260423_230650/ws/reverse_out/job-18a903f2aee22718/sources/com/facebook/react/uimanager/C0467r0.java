package com.facebook.react.uimanager;

import com.facebook.yoga.YogaValue;
import java.util.ArrayList;
import java.util.Arrays;

/* JADX INFO: renamed from: com.facebook.react.uimanager.r0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0467r0 implements InterfaceC0466q0 {

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private static final com.facebook.yoga.c f7733x = C0473u0.f7758a.b();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f7734a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private String f7735b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f7736c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private B0 f7737d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f7738e;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private ArrayList f7740g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private C0467r0 f7741h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private C0467r0 f7742i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f7743j;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private C0467r0 f7745l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private ArrayList f7746m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f7747n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f7748o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f7749p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f7750q;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final float[] f7752s;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private com.facebook.yoga.r f7754u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private Integer f7755v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private Integer f7756w;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f7739f = true;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f7744k = 0;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final boolean[] f7753t = new boolean[9];

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final C0483z0 f7751r = new C0483z0(0.0f);

    public C0467r0() {
        float[] fArr = new float[9];
        this.f7752s = fArr;
        if (R()) {
            this.f7754u = null;
            return;
        }
        com.facebook.yoga.r rVarA = (com.facebook.yoga.r) b1.b().b();
        rVarA = rVarA == null ? com.facebook.yoga.s.a(f7733x) : rVarA;
        this.f7754u = rVarA;
        rVarA.B(this);
        Arrays.fill(fArr, Float.NaN);
    }

    private int n0() {
        EnumC0434a0 enumC0434a0M = m();
        if (enumC0434a0M == EnumC0434a0.f7570d) {
            return this.f7744k;
        }
        if (enumC0434a0M == EnumC0434a0.f7569c) {
            return this.f7744k + 1;
        }
        return 1;
    }

    private void t1(int i3) {
        if (m() != EnumC0434a0.f7568b) {
            for (C0467r0 parent = getParent(); parent != null; parent = parent.getParent()) {
                parent.f7744k += i3;
                if (parent.m() == EnumC0434a0.f7568b) {
                    return;
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0091  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void u1() {
        /*
            r4 = this;
            r0 = 0
        L1:
            r1 = 8
            if (r0 > r1) goto Lb6
            if (r0 == 0) goto L62
            r2 = 2
            if (r0 == r2) goto L62
            r2 = 4
            if (r0 == r2) goto L62
            r2 = 5
            if (r0 != r2) goto L11
            goto L62
        L11:
            r2 = 1
            if (r0 == r2) goto L33
            r2 = 3
            if (r0 != r2) goto L18
            goto L33
        L18:
            float[] r1 = r4.f7752s
            r1 = r1[r0]
            boolean r1 = com.facebook.yoga.g.a(r1)
            if (r1 == 0) goto L91
            com.facebook.yoga.r r1 = r4.f7754u
            com.facebook.yoga.j r2 = com.facebook.yoga.j.b(r0)
            com.facebook.react.uimanager.z0 r3 = r4.f7751r
            float r3 = r3.b(r0)
            r1.e0(r2, r3)
            goto Lb2
        L33:
            float[] r2 = r4.f7752s
            r2 = r2[r0]
            boolean r2 = com.facebook.yoga.g.a(r2)
            if (r2 == 0) goto L91
            float[] r2 = r4.f7752s
            r3 = 7
            r2 = r2[r3]
            boolean r2 = com.facebook.yoga.g.a(r2)
            if (r2 == 0) goto L91
            float[] r2 = r4.f7752s
            r1 = r2[r1]
            boolean r1 = com.facebook.yoga.g.a(r1)
            if (r1 == 0) goto L91
            com.facebook.yoga.r r1 = r4.f7754u
            com.facebook.yoga.j r2 = com.facebook.yoga.j.b(r0)
            com.facebook.react.uimanager.z0 r3 = r4.f7751r
            float r3 = r3.b(r0)
            r1.e0(r2, r3)
            goto Lb2
        L62:
            float[] r2 = r4.f7752s
            r2 = r2[r0]
            boolean r2 = com.facebook.yoga.g.a(r2)
            if (r2 == 0) goto L91
            float[] r2 = r4.f7752s
            r3 = 6
            r2 = r2[r3]
            boolean r2 = com.facebook.yoga.g.a(r2)
            if (r2 == 0) goto L91
            float[] r2 = r4.f7752s
            r1 = r2[r1]
            boolean r1 = com.facebook.yoga.g.a(r1)
            if (r1 == 0) goto L91
            com.facebook.yoga.r r1 = r4.f7754u
            com.facebook.yoga.j r2 = com.facebook.yoga.j.b(r0)
            com.facebook.react.uimanager.z0 r3 = r4.f7751r
            float r3 = r3.b(r0)
            r1.e0(r2, r3)
            goto Lb2
        L91:
            boolean[] r1 = r4.f7753t
            boolean r1 = r1[r0]
            if (r1 == 0) goto La5
            com.facebook.yoga.r r1 = r4.f7754u
            com.facebook.yoga.j r2 = com.facebook.yoga.j.b(r0)
            float[] r3 = r4.f7752s
            r3 = r3[r0]
            r1.f0(r2, r3)
            goto Lb2
        La5:
            com.facebook.yoga.r r1 = r4.f7754u
            com.facebook.yoga.j r2 = com.facebook.yoga.j.b(r0)
            float[] r3 = r4.f7752s
            r3 = r3[r0]
            r1.e0(r2, r3)
        Lb2:
            int r0 = r0 + 1
            goto L1
        Lb6:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.uimanager.C0467r0.u1():void");
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final float A() {
        return this.f7754u.l();
    }

    public void A0(M0 m02) {
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void B(float f3, float f4) {
        this.f7754u.c(f3, f4);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: B0, reason: merged with bridge method [inline-methods] */
    public C0467r0 e(int i3) {
        ArrayList arrayList = this.f7740g;
        if (arrayList == null) {
            throw new ArrayIndexOutOfBoundsException("Index " + i3 + " out of bounds: node has no children");
        }
        C0467r0 c0467r0 = (C0467r0) arrayList.remove(i3);
        c0467r0.f7741h = null;
        if (this.f7754u != null && !w0()) {
            this.f7754u.t(i3);
        }
        y0();
        int iN0 = c0467r0.n0();
        this.f7744k -= iN0;
        t1(-iN0);
        return c0467r0;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final int C() {
        ArrayList arrayList = this.f7740g;
        if (arrayList == null) {
            return 0;
        }
        return arrayList.size();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: C0, reason: merged with bridge method [inline-methods] */
    public final C0467r0 I(int i3) {
        Z0.a.c(this.f7746m);
        C0467r0 c0467r0 = (C0467r0) this.f7746m.remove(i3);
        c0467r0.f7745l = null;
        return c0467r0;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public int D() {
        return this.f7747n;
    }

    public void D0(com.facebook.yoga.a aVar) {
        this.f7754u.v(aVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public Iterable E() {
        if (v0()) {
            return null;
        }
        return this.f7740g;
    }

    public void E0(com.facebook.yoga.a aVar) {
        this.f7754u.w(aVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void F(float f3, float f4, M0 m02, C0438c0 c0438c0) {
        if (this.f7739f) {
            A0(m02);
        }
        if (o0()) {
            float fJ = J();
            float fA = A();
            float f5 = f3 + fJ;
            int iRound = Math.round(f5);
            float f6 = f4 + fA;
            int iRound2 = Math.round(f6);
            int iRound3 = Math.round(f5 + e0());
            int iRound4 = Math.round(f6 + u());
            int iRound5 = Math.round(fJ);
            int iRound6 = Math.round(fA);
            int i3 = iRound3 - iRound;
            int i4 = iRound4 - iRound2;
            boolean z3 = (iRound5 == this.f7747n && iRound6 == this.f7748o && i3 == this.f7749p && i4 == this.f7750q) ? false : true;
            this.f7747n = iRound5;
            this.f7748o = iRound6;
            this.f7749p = i3;
            this.f7750q = i4;
            if (z3) {
                if (c0438c0 != null) {
                    c0438c0.l(this);
                } else {
                    m02.P(getParent().H(), H(), D(), j(), a(), b(), getLayoutDirection());
                }
            }
        }
    }

    public void F0(com.facebook.yoga.a aVar) {
        this.f7754u.x(aVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void G() {
        if (C() == 0) {
            return;
        }
        int iN0 = 0;
        for (int iC = C() - 1; iC >= 0; iC--) {
            if (this.f7754u != null && !w0()) {
                this.f7754u.t(iC);
            }
            C0467r0 c0467r0N = N(iC);
            c0467r0N.f7741h = null;
            iN0 += c0467r0N.n0();
            c0467r0N.f();
        }
        ((ArrayList) Z0.a.c(this.f7740g)).clear();
        y0();
        this.f7744k -= iN0;
        t1(-iN0);
    }

    public void G0(com.facebook.yoga.b bVar) {
        this.f7754u.z(bVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final int H() {
        return this.f7734a;
    }

    public void H0(int i3, float f3) {
        this.f7754u.A(com.facebook.yoga.j.b(i3), f3);
    }

    public void I0(float f3) {
        this.f7754u.L(com.facebook.yoga.m.COLUMN, f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final float J() {
        return this.f7754u.k();
    }

    public void J0(float f3) {
        this.f7754u.M(com.facebook.yoga.m.COLUMN, f3);
    }

    public void K0(int i3, float f3) {
        this.f7751r.c(i3, f3);
        u1();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final void L() {
        ArrayList arrayList = this.f7746m;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((C0467r0) this.f7746m.get(size)).f7745l = null;
            }
            this.f7746m.clear();
        }
    }

    public void L0(com.facebook.yoga.i iVar) {
        this.f7754u.D(iVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void M() {
        B(Float.NaN, Float.NaN);
    }

    public void M0(float f3) {
        this.f7754u.F(f3);
    }

    public void N0() {
        this.f7754u.G();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void O(C0438c0 c0438c0) {
    }

    public void O0(float f3) {
        this.f7754u.H(f3);
    }

    public void P0(com.facebook.yoga.l lVar) {
        this.f7754u.I(lVar);
    }

    public void Q0(com.facebook.yoga.x xVar) {
        this.f7754u.m0(xVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public boolean R() {
        return false;
    }

    public void R0(float f3) {
        this.f7754u.L(com.facebook.yoga.m.ALL, f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void S(int i3, float f3) {
        this.f7752s[i3] = f3;
        this.f7753t[i3] = false;
        u1();
    }

    public void S0(float f3) {
        this.f7754u.L(com.facebook.yoga.m.ALL, f3);
    }

    public void T0(com.facebook.yoga.n nVar) {
        this.f7754u.Q(nVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final int U() {
        ArrayList arrayList = this.f7746m;
        if (arrayList == null) {
            return 0;
        }
        return arrayList.size();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: U0, reason: merged with bridge method [inline-methods] */
    public final void w(C0467r0 c0467r0) {
        this.f7742i = c0467r0;
    }

    public void V0(int i3, float f3) {
        this.f7754u.R(com.facebook.yoga.j.b(i3), f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final void W(boolean z3) {
        Z0.a.b(getParent() == null, "Must remove from no opt parent first");
        Z0.a.b(this.f7745l == null, "Must remove from native parent first");
        Z0.a.b(U() == 0, "Must remove all native children first");
        this.f7743j = z3;
    }

    public void W0(int i3) {
        this.f7754u.S(com.facebook.yoga.j.b(i3));
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final void X(C0469s0 c0469s0) {
        R0.g(this, c0469s0);
        z0();
    }

    public void X0(int i3, float f3) {
        this.f7754u.T(com.facebook.yoga.j.b(i3), f3);
    }

    public void Y0(com.facebook.yoga.o oVar) {
        this.f7754u.Y(oVar);
    }

    public void Z0(com.facebook.yoga.u uVar) {
        this.f7754u.d0(uVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public int a() {
        return this.f7749p;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final boolean a0() {
        return this.f7743j;
    }

    public void a1(int i3, float f3) {
        this.f7752s[i3] = f3;
        this.f7753t[i3] = !com.facebook.yoga.g.a(f3);
        u1();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public int b() {
        return this.f7750q;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final void b0(int i3) {
        this.f7736c = i3;
    }

    public void b1(int i3, float f3) {
        this.f7754u.g0(com.facebook.yoga.j.b(i3), f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final YogaValue c() {
        return this.f7754u.m();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void c0(B0 b02) {
        this.f7737d = b02;
    }

    public void c1(int i3, float f3) {
        this.f7754u.h0(com.facebook.yoga.j.b(i3), f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final void d() {
        this.f7739f = false;
        if (o0()) {
            x0();
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void d0(float f3) {
        this.f7754u.j0(f3);
    }

    public void d1(com.facebook.yoga.v vVar) {
        this.f7754u.i0(vVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final float e0() {
        return this.f7754u.j();
    }

    public void e1(float f3) {
        this.f7754u.L(com.facebook.yoga.m.ROW, f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void f() {
        com.facebook.yoga.r rVar = this.f7754u;
        if (rVar != null) {
            rVar.u();
            b1.b().a(this.f7754u);
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: f0, reason: merged with bridge method [inline-methods] */
    public void o(C0467r0 c0467r0, int i3) {
        if (this.f7740g == null) {
            this.f7740g = new ArrayList(4);
        }
        this.f7740g.add(i3, c0467r0);
        c0467r0.f7741h = this;
        if (this.f7754u != null && !w0()) {
            com.facebook.yoga.r rVar = c0467r0.f7754u;
            if (rVar == null) {
                throw new RuntimeException("Cannot add a child that doesn't have a YogaNode to a parent without a measure function! (Trying to add a '" + c0467r0.toString() + "' to a '" + toString() + "')");
            }
            this.f7754u.a(rVar, i3);
        }
        y0();
        int iN0 = c0467r0.n0();
        this.f7744k += iN0;
        t1(iN0);
    }

    public void f1(float f3) {
        this.f7754u.M(com.facebook.yoga.m.ROW, f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void g(float f3) {
        this.f7754u.N(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: g0, reason: merged with bridge method [inline-methods] */
    public final void Z(C0467r0 c0467r0, int i3) {
        Z0.a.a(m() == EnumC0434a0.f7568b);
        Z0.a.a(c0467r0.m() != EnumC0434a0.f7570d);
        if (this.f7746m == null) {
            this.f7746m = new ArrayList(4);
        }
        this.f7746m.add(i3, c0467r0);
        c0467r0.f7745l = this;
    }

    public void g1(float f3) {
        this.f7754u.y(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public Integer getHeightMeasureSpec() {
        return this.f7756w;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final com.facebook.yoga.h getLayoutDirection() {
        return this.f7754u.f();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public Integer getWidthMeasureSpec() {
        return this.f7755v;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void h(int i3, int i4) {
        this.f7755v = Integer.valueOf(i3);
        this.f7756w = Integer.valueOf(i4);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: h0, reason: merged with bridge method [inline-methods] */
    public final C0467r0 N(int i3) {
        ArrayList arrayList = this.f7740g;
        if (arrayList != null) {
            return (C0467r0) arrayList.get(i3);
        }
        throw new ArrayIndexOutOfBoundsException("Index " + i3 + " out of bounds: node has no children");
    }

    public void h1() {
        this.f7754u.O();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void i() {
        if (!R()) {
            this.f7754u.d();
        } else if (getParent() != null) {
            getParent().i();
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: i0, reason: merged with bridge method [inline-methods] */
    public final C0467r0 P() {
        C0467r0 c0467r0 = this.f7742i;
        return c0467r0 != null ? c0467r0 : V();
    }

    public void i1(float f3) {
        this.f7754u.P(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public int j() {
        return this.f7748o;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: j0, reason: merged with bridge method [inline-methods] */
    public final int T(C0467r0 c0467r0) {
        int iN0 = 0;
        for (int i3 = 0; i3 < C(); i3++) {
            C0467r0 c0467r0N = N(i3);
            if (c0467r0 == c0467r0N) {
                return iN0;
            }
            iN0 += c0467r0N.n0();
        }
        throw new RuntimeException("Child " + c0467r0.H() + " was not a child of " + this.f7734a);
    }

    public void j1(float f3) {
        this.f7754u.U(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void k(Object obj) {
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: k0, reason: merged with bridge method [inline-methods] */
    public final C0467r0 V() {
        return this.f7745l;
    }

    public void k1(float f3) {
        this.f7754u.V(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final B0 l() {
        return (B0) Z0.a.c(this.f7737d);
    }

    public final float l0(int i3) {
        return this.f7754u.h(com.facebook.yoga.j.b(i3));
    }

    public void l1(float f3) {
        this.f7754u.W(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public EnumC0434a0 m() {
        return (R() || a0()) ? EnumC0434a0.f7570d : p0() ? EnumC0434a0.f7569c : EnumC0434a0.f7568b;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: m0, reason: merged with bridge method [inline-methods] */
    public final C0467r0 getParent() {
        return this.f7741h;
    }

    public void m1(float f3) {
        this.f7754u.X(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final int n() {
        Z0.a.a(this.f7736c != 0);
        return this.f7736c;
    }

    public void n1(float f3) {
        this.f7754u.Z(f3);
    }

    public final boolean o0() {
        com.facebook.yoga.r rVar = this.f7754u;
        return rVar != null && rVar.n();
    }

    public void o1(float f3) {
        this.f7754u.a0(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final void p(String str) {
        this.f7735b = str;
    }

    public boolean p0() {
        return false;
    }

    public void p1(float f3) {
        this.f7754u.b0(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public boolean q(float f3, float f4) {
        if (!o0()) {
            return false;
        }
        float fJ = J();
        float fA = A();
        float f5 = f3 + fJ;
        int iRound = Math.round(f5);
        float f6 = f4 + fA;
        int iRound2 = Math.round(f6);
        return (Math.round(fJ) == this.f7747n && Math.round(fA) == this.f7748o && Math.round(f5 + e0()) - iRound == this.f7749p && Math.round(f6 + u()) - iRound2 == this.f7750q) ? false : true;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: q0, reason: merged with bridge method [inline-methods] */
    public final int t(C0467r0 c0467r0) {
        ArrayList arrayList = this.f7740g;
        if (arrayList == null) {
            return -1;
        }
        return arrayList.indexOf(c0467r0);
    }

    public void q1(float f3) {
        this.f7754u.c0(f3);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final boolean r() {
        return this.f7738e;
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: r0, reason: merged with bridge method [inline-methods] */
    public final int Y(C0467r0 c0467r0) {
        Z0.a.c(this.f7746m);
        return this.f7746m.indexOf(c0467r0);
    }

    public void r1() {
        this.f7754u.k0();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void s(com.facebook.yoga.h hVar) {
        this.f7754u.C(hVar);
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    /* JADX INFO: renamed from: s0, reason: merged with bridge method [inline-methods] */
    public boolean Q(C0467r0 c0467r0) {
        for (C0467r0 parent = getParent(); parent != null; parent = parent.getParent()) {
            if (parent == c0467r0) {
                return true;
            }
        }
        return false;
    }

    public void s1(float f3) {
        this.f7754u.l0(f3);
    }

    public void setFlex(float f3) {
        this.f7754u.E(f3);
    }

    public void setFlexGrow(float f3) {
        this.f7754u.J(f3);
    }

    public void setFlexShrink(float f3) {
        this.f7754u.K(f3);
    }

    public void setShouldNotifyOnLayout(boolean z3) {
        this.f7738e = z3;
    }

    public final boolean t0() {
        com.facebook.yoga.r rVar = this.f7754u;
        return rVar != null && rVar.o();
    }

    public String toString() {
        return "[" + this.f7735b + " " + H() + "]";
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final float u() {
        return this.f7754u.g();
    }

    public boolean u0() {
        return this.f7754u.q();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final String v() {
        return (String) Z0.a.c(this.f7735b);
    }

    public boolean v0() {
        return false;
    }

    public boolean w0() {
        return u0();
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final boolean x() {
        return this.f7739f || o0() || t0();
    }

    public final void x0() {
        com.facebook.yoga.r rVar = this.f7754u;
        if (rVar != null) {
            rVar.s();
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public void y(int i3) {
        this.f7734a = i3;
    }

    public void y0() {
        if (this.f7739f) {
            return;
        }
        this.f7739f = true;
        C0467r0 parent = getParent();
        if (parent != null) {
            parent.y0();
        }
    }

    @Override // com.facebook.react.uimanager.InterfaceC0466q0
    public final YogaValue z() {
        return this.f7754u.e();
    }

    public void z0() {
    }
}
