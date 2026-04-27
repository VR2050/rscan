package com.facebook.react.uimanager;

import android.util.SparseBooleanArray;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.views.view.ReactViewManager;

/* JADX INFO: renamed from: com.facebook.react.uimanager.c0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0438c0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final M0 f7593a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0481y0 f7594b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final SparseBooleanArray f7595c = new SparseBooleanArray();

    /* JADX INFO: renamed from: com.facebook.react.uimanager.c0$a */
    private static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final InterfaceC0466q0 f7596a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final int f7597b;

        a(InterfaceC0466q0 interfaceC0466q0, int i3) {
            this.f7596a = interfaceC0466q0;
            this.f7597b = i3;
        }
    }

    public C0438c0(M0 m02, C0481y0 c0481y0) {
        this.f7593a = m02;
        this.f7594b = c0481y0;
    }

    private void a(InterfaceC0466q0 interfaceC0466q0, InterfaceC0466q0 interfaceC0466q02, int i3) {
        Z0.a.a(interfaceC0466q02.m() != EnumC0434a0.f7568b);
        for (int i4 = 0; i4 < interfaceC0466q02.C(); i4++) {
            InterfaceC0466q0 interfaceC0466q0N = interfaceC0466q02.N(i4);
            Z0.a.a(interfaceC0466q0N.V() == null);
            int iU = interfaceC0466q0.U();
            if (interfaceC0466q0N.m() == EnumC0434a0.f7570d) {
                d(interfaceC0466q0, interfaceC0466q0N, i3);
            } else {
                b(interfaceC0466q0, interfaceC0466q0N, i3);
            }
            i3 += interfaceC0466q0.U() - iU;
        }
    }

    private void b(InterfaceC0466q0 interfaceC0466q0, InterfaceC0466q0 interfaceC0466q02, int i3) {
        interfaceC0466q0.Z(interfaceC0466q02, i3);
        this.f7593a.G(interfaceC0466q0.H(), null, new O0[]{new O0(interfaceC0466q02.H(), i3)}, null);
        if (interfaceC0466q02.m() != EnumC0434a0.f7568b) {
            a(interfaceC0466q0, interfaceC0466q02, i3 + 1);
        }
    }

    private void c(InterfaceC0466q0 interfaceC0466q0, InterfaceC0466q0 interfaceC0466q02, int i3) {
        int iT = interfaceC0466q0.T(interfaceC0466q0.N(i3));
        if (interfaceC0466q0.m() != EnumC0434a0.f7568b) {
            a aVarS = s(interfaceC0466q0, iT);
            if (aVarS == null) {
                return;
            }
            InterfaceC0466q0 interfaceC0466q03 = aVarS.f7596a;
            iT = aVarS.f7597b;
            interfaceC0466q0 = interfaceC0466q03;
        }
        if (interfaceC0466q02.m() != EnumC0434a0.f7570d) {
            b(interfaceC0466q0, interfaceC0466q02, iT);
        } else {
            d(interfaceC0466q0, interfaceC0466q02, iT);
        }
    }

    private void d(InterfaceC0466q0 interfaceC0466q0, InterfaceC0466q0 interfaceC0466q02, int i3) {
        a(interfaceC0466q0, interfaceC0466q02, i3);
    }

    private void e(InterfaceC0466q0 interfaceC0466q0) {
        int iH = interfaceC0466q0.H();
        if (this.f7595c.get(iH)) {
            return;
        }
        this.f7595c.put(iH, true);
        int iD = interfaceC0466q0.D();
        int iJ = interfaceC0466q0.j();
        for (InterfaceC0466q0 parent = interfaceC0466q0.getParent(); parent != null && parent.m() != EnumC0434a0.f7568b; parent = parent.getParent()) {
            if (!parent.R()) {
                iD += Math.round(parent.J());
                iJ += Math.round(parent.A());
            }
        }
        f(interfaceC0466q0, iD, iJ);
    }

    private void f(InterfaceC0466q0 interfaceC0466q0, int i3, int i4) {
        if (interfaceC0466q0.m() != EnumC0434a0.f7570d && interfaceC0466q0.V() != null) {
            this.f7593a.P(interfaceC0466q0.P().H(), interfaceC0466q0.H(), i3, i4, interfaceC0466q0.a(), interfaceC0466q0.b(), interfaceC0466q0.getLayoutDirection());
            return;
        }
        for (int i5 = 0; i5 < interfaceC0466q0.C(); i5++) {
            InterfaceC0466q0 interfaceC0466q0N = interfaceC0466q0.N(i5);
            int iH = interfaceC0466q0N.H();
            if (!this.f7595c.get(iH)) {
                this.f7595c.put(iH, true);
                f(interfaceC0466q0N, interfaceC0466q0N.D() + i3, interfaceC0466q0N.j() + i4);
            }
        }
    }

    public static void j(InterfaceC0466q0 interfaceC0466q0) {
        interfaceC0466q0.L();
    }

    private static boolean n(C0469s0 c0469s0) {
        if (c0469s0 == null) {
            return true;
        }
        if (c0469s0.c("collapsable") && !c0469s0.a("collapsable", true)) {
            return false;
        }
        ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = c0469s0.f7757a.keySetIterator();
        while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
            if (!Z0.a(c0469s0.f7757a, readableMapKeySetIteratorKeySetIterator.nextKey())) {
                return false;
            }
        }
        return true;
    }

    private void q(InterfaceC0466q0 interfaceC0466q0, boolean z3) {
        if (interfaceC0466q0.m() != EnumC0434a0.f7568b) {
            for (int iC = interfaceC0466q0.C() - 1; iC >= 0; iC--) {
                q(interfaceC0466q0.N(iC), z3);
            }
        }
        InterfaceC0466q0 interfaceC0466q0V = interfaceC0466q0.V();
        if (interfaceC0466q0V != null) {
            int iY = interfaceC0466q0V.Y(interfaceC0466q0);
            interfaceC0466q0V.I(iY);
            this.f7593a.G(interfaceC0466q0V.H(), new int[]{iY}, null, z3 ? new int[]{interfaceC0466q0.H()} : null);
        }
    }

    private void r(InterfaceC0466q0 interfaceC0466q0, C0469s0 c0469s0) {
        InterfaceC0466q0 parent = interfaceC0466q0.getParent();
        if (parent == null) {
            interfaceC0466q0.W(false);
            return;
        }
        int iT = parent.t(interfaceC0466q0);
        parent.e(iT);
        q(interfaceC0466q0, false);
        interfaceC0466q0.W(false);
        this.f7593a.C(interfaceC0466q0.l(), interfaceC0466q0.H(), interfaceC0466q0.v(), c0469s0);
        parent.o(interfaceC0466q0, iT);
        c(parent, interfaceC0466q0, iT);
        for (int i3 = 0; i3 < interfaceC0466q0.C(); i3++) {
            c(interfaceC0466q0, interfaceC0466q0.N(i3), i3);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Transitioning LayoutOnlyView - tag: ");
        sb.append(interfaceC0466q0.H());
        sb.append(" - rootTag: ");
        sb.append(interfaceC0466q0.n());
        sb.append(" - hasProps: ");
        sb.append(c0469s0 != null);
        sb.append(" - tagsWithLayout.size: ");
        sb.append(this.f7595c.size());
        Y.a.s("NativeViewHierarchyOptimizer", sb.toString());
        Z0.a.a(this.f7595c.size() == 0);
        e(interfaceC0466q0);
        for (int i4 = 0; i4 < interfaceC0466q0.C(); i4++) {
            e(interfaceC0466q0.N(i4));
        }
        this.f7595c.clear();
    }

    private a s(InterfaceC0466q0 interfaceC0466q0, int i3) {
        while (interfaceC0466q0.m() != EnumC0434a0.f7568b) {
            InterfaceC0466q0 parent = interfaceC0466q0.getParent();
            if (parent == null) {
                return null;
            }
            i3 = i3 + (interfaceC0466q0.m() == EnumC0434a0.f7569c ? 1 : 0) + parent.T(interfaceC0466q0);
            interfaceC0466q0 = parent;
        }
        return new a(interfaceC0466q0, i3);
    }

    public void g(InterfaceC0466q0 interfaceC0466q0, B0 b02, C0469s0 c0469s0) {
        interfaceC0466q0.W(interfaceC0466q0.v().equals(ReactViewManager.REACT_CLASS) && n(c0469s0));
        if (interfaceC0466q0.m() != EnumC0434a0.f7570d) {
            this.f7593a.C(b02, interfaceC0466q0.H(), interfaceC0466q0.v(), c0469s0);
        }
    }

    public void h(InterfaceC0466q0 interfaceC0466q0) {
        if (interfaceC0466q0.a0()) {
            r(interfaceC0466q0, null);
        }
    }

    public void i(InterfaceC0466q0 interfaceC0466q0, int[] iArr, int[] iArr2, O0[] o0Arr, int[] iArr3) {
        boolean z3;
        for (int i3 : iArr2) {
            int i4 = 0;
            while (true) {
                if (i4 >= iArr3.length) {
                    z3 = false;
                    break;
                } else {
                    if (iArr3[i4] == i3) {
                        z3 = true;
                        break;
                    }
                    i4++;
                }
            }
            q(this.f7594b.c(i3), z3);
        }
        for (O0 o02 : o0Arr) {
            c(interfaceC0466q0, this.f7594b.c(o02.f7479a), o02.f7480b);
        }
    }

    public void k(InterfaceC0466q0 interfaceC0466q0, ReadableArray readableArray) {
        for (int i3 = 0; i3 < readableArray.size(); i3++) {
            c(interfaceC0466q0, this.f7594b.c(readableArray.getInt(i3)), i3);
        }
    }

    public void l(InterfaceC0466q0 interfaceC0466q0) {
        e(interfaceC0466q0);
    }

    public void m(InterfaceC0466q0 interfaceC0466q0, String str, C0469s0 c0469s0) {
        if (interfaceC0466q0.a0() && !n(c0469s0)) {
            r(interfaceC0466q0, c0469s0);
        } else {
            if (interfaceC0466q0.a0()) {
                return;
            }
            this.f7593a.Q(interfaceC0466q0.H(), str, c0469s0);
        }
    }

    public void o() {
        this.f7595c.clear();
    }

    void p(InterfaceC0466q0 interfaceC0466q0) {
        this.f7595c.clear();
    }
}
