package com.facebook.react.uimanager;

import android.os.SystemClock;
import android.view.View;
import c2.C0353a;
import c2.C0354b;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.uimanager.events.EventDispatcher;
import f1.C0527a;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class G0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected Object f7369a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected final EventDispatcher f7370b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected final ReactApplicationContext f7371c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected final C0481y0 f7372d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final U0 f7373e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final M0 f7374f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final C0438c0 f7375g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int[] f7376h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private long f7377i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private volatile boolean f7378j;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ InterfaceC0466q0 f7379b;

        a(InterfaceC0466q0 interfaceC0466q0) {
            this.f7379b = interfaceC0466q0;
        }

        @Override // java.lang.Runnable
        public void run() {
            G0.this.f7372d.b(this.f7379b);
        }
    }

    G0(ReactApplicationContext reactApplicationContext, U0 u02, EventDispatcher eventDispatcher, int i3) {
        this(reactApplicationContext, u02, new M0(reactApplicationContext, new C0436b0(u02), i3), eventDispatcher);
    }

    private void A(InterfaceC0466q0 interfaceC0466q0) {
        if (interfaceC0466q0.x()) {
            for (int i3 = 0; i3 < interfaceC0466q0.C(); i3++) {
                A(interfaceC0466q0.N(i3));
            }
            interfaceC0466q0.O(this.f7375g);
        }
    }

    private void L(InterfaceC0466q0 interfaceC0466q0) {
        C0438c0.j(interfaceC0466q0);
        this.f7372d.g(interfaceC0466q0.H());
        for (int iC = interfaceC0466q0.C() - 1; iC >= 0; iC--) {
            L(interfaceC0466q0.N(iC));
        }
        interfaceC0466q0.G();
    }

    private void c(InterfaceC0466q0 interfaceC0466q0) {
        NativeModule nativeModule = (ViewManager) Z0.a.c(this.f7373e.c(interfaceC0466q0.v()));
        if (!(nativeModule instanceof O)) {
            throw new P("Trying to use view " + interfaceC0466q0.v() + " as a parent, but its Manager doesn't extends ViewGroupManager");
        }
        O o3 = (O) nativeModule;
        if (o3 == null || !o3.needsCustomLayoutForChildren()) {
            return;
        }
        throw new P("Trying to measure a view using measureLayout/measureLayoutRelativeToParent relative to an ancestor that requires custom layout for it's children (" + interfaceC0466q0.v() + "). Use measure instead.");
    }

    private boolean e(int i3, String str) {
        if (this.f7372d.c(i3) != null) {
            return true;
        }
        String str2 = "Unable to execute operation " + str + " on view with tag: " + i3 + ", since the view does not exist";
        if (C0527a.f9198b) {
            throw new P(str2);
        }
        Y.a.I("ReactNative", str2);
        return false;
    }

    private void n() {
        if (this.f7374f.U()) {
            m(-1);
        }
    }

    private void y(int i3, int i4, int[] iArr) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        InterfaceC0466q0 interfaceC0466q0C2 = this.f7372d.c(i4);
        if (interfaceC0466q0C == null || interfaceC0466q0C2 == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("Tag ");
            if (interfaceC0466q0C != null) {
                i3 = i4;
            }
            sb.append(i3);
            sb.append(" does not exist");
            throw new P(sb.toString());
        }
        if (interfaceC0466q0C != interfaceC0466q0C2) {
            for (InterfaceC0466q0 parent = interfaceC0466q0C.getParent(); parent != interfaceC0466q0C2; parent = parent.getParent()) {
                if (parent == null) {
                    throw new P("Tag " + i4 + " is not an ancestor of tag " + i3);
                }
            }
        }
        z(interfaceC0466q0C, interfaceC0466q0C2, iArr);
    }

    private void z(InterfaceC0466q0 interfaceC0466q0, InterfaceC0466q0 interfaceC0466q02, int[] iArr) {
        int iRound;
        int iRound2;
        if (interfaceC0466q0 == interfaceC0466q02 || interfaceC0466q0.R()) {
            iRound = 0;
            iRound2 = 0;
        } else {
            iRound = Math.round(interfaceC0466q0.J());
            iRound2 = Math.round(interfaceC0466q0.A());
            for (InterfaceC0466q0 parent = interfaceC0466q0.getParent(); parent != interfaceC0466q02; parent = parent.getParent()) {
                Z0.a.c(parent);
                c(parent);
                iRound += Math.round(parent.J());
                iRound2 += Math.round(parent.A());
            }
            c(interfaceC0466q02);
        }
        iArr[0] = iRound;
        iArr[1] = iRound2;
        iArr[2] = interfaceC0466q0.a();
        iArr[3] = interfaceC0466q0.b();
    }

    public void B() {
        this.f7378j = false;
        this.f7373e.f();
    }

    public void C() {
    }

    public void D() {
        this.f7374f.V();
    }

    public void E() {
        this.f7374f.Y();
    }

    public void F(F0 f02) {
        this.f7374f.W(f02);
    }

    public void G() {
        this.f7374f.X();
    }

    public void H(View view, int i3, B0 b02) {
        synchronized (this.f7369a) {
            InterfaceC0466q0 interfaceC0466q0H = h();
            interfaceC0466q0H.y(i3);
            interfaceC0466q0H.c0(b02);
            b02.runOnNativeModulesQueueThread(new a(interfaceC0466q0H));
            this.f7374f.y(i3, view);
        }
    }

    public void I(int i3) {
        synchronized (this.f7369a) {
            this.f7372d.h(i3);
        }
    }

    public void J(int i3) {
        I(i3);
        this.f7374f.J(i3);
    }

    protected final void K(InterfaceC0466q0 interfaceC0466q0) {
        L(interfaceC0466q0);
        interfaceC0466q0.f();
    }

    public int M(int i3) {
        if (this.f7372d.f(i3)) {
            return i3;
        }
        InterfaceC0466q0 interfaceC0466q0N = N(i3);
        if (interfaceC0466q0N != null) {
            return interfaceC0466q0N.n();
        }
        Y.a.I("ReactNative", "Warning : attempted to resolve a non-existent react shadow node. reactTag=" + i3);
        return 0;
    }

    public final InterfaceC0466q0 N(int i3) {
        return this.f7372d.c(i3);
    }

    protected final ViewManager O(String str) {
        return this.f7373e.e(str);
    }

    public void P(int i3, int i4) {
        this.f7374f.K(i3, i4);
    }

    public void Q(int i3, ReadableArray readableArray) {
        if (this.f7378j) {
            synchronized (this.f7369a) {
                try {
                    InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
                    for (int i4 = 0; i4 < readableArray.size(); i4++) {
                        InterfaceC0466q0 interfaceC0466q0C2 = this.f7372d.c(readableArray.getInt(i4));
                        if (interfaceC0466q0C2 == null) {
                            throw new P("Trying to add unknown view tag: " + readableArray.getInt(i4));
                        }
                        interfaceC0466q0C.o(interfaceC0466q0C2, i4);
                    }
                    this.f7375g.k(interfaceC0466q0C, readableArray);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public void R(int i3, boolean z3) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        if (interfaceC0466q0C == null) {
            return;
        }
        while (interfaceC0466q0C.m() == EnumC0434a0.f7570d) {
            interfaceC0466q0C = interfaceC0466q0C.getParent();
        }
        this.f7374f.L(interfaceC0466q0C.H(), i3, z3);
    }

    public void S(boolean z3) {
        this.f7374f.M(z3);
    }

    public void T(M1.a aVar) {
        this.f7374f.Z(aVar);
    }

    public void U(int i3, Object obj) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        if (interfaceC0466q0C != null) {
            interfaceC0466q0C.k(obj);
            n();
        } else {
            Y.a.I("ReactNative", "Attempt to set local data for view with unknown tag: " + i3);
        }
    }

    public void V(int i3, C0469s0 c0469s0) {
        UiThreadUtil.assertOnUiThread();
        this.f7374f.S().C(i3, c0469s0);
    }

    public void W(int i3, int i4, int i5, int i6, int i7) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        if (interfaceC0466q0C == null) {
            Y.a.I("ReactNative", "Tried to update size of non-existent tag: " + i3);
            return;
        }
        interfaceC0466q0C.S(4, i5);
        interfaceC0466q0C.S(1, i4);
        interfaceC0466q0C.S(5, i7);
        interfaceC0466q0C.S(3, i6);
        n();
    }

    public void X(int i3, int i4, int i5) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        if (interfaceC0466q0C != null) {
            interfaceC0466q0C.d0(i4);
            interfaceC0466q0C.g(i5);
            n();
        } else {
            Y.a.I("ReactNative", "Tried to update size of non-existent tag: " + i3);
        }
    }

    public void Y(int i3, int i4, int i5) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        if (interfaceC0466q0C != null) {
            Z(interfaceC0466q0C, i4, i5);
            return;
        }
        Y.a.I("ReactNative", "Tried to update non-existent root tag: " + i3);
    }

    public void Z(InterfaceC0466q0 interfaceC0466q0, int i3, int i4) {
        interfaceC0466q0.h(i3, i4);
    }

    public void a(F0 f02) {
        this.f7374f.N(f02);
    }

    public void a0(int i3, String str, ReadableMap readableMap) {
        if (this.f7378j) {
            if (this.f7373e.c(str) == null) {
                throw new P("Got unknown view type: " + str);
            }
            InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
            if (interfaceC0466q0C == null) {
                throw new P("Trying to update non-existent view with tag " + i3);
            }
            if (readableMap != null) {
                C0469s0 c0469s0 = new C0469s0(readableMap);
                interfaceC0466q0C.X(c0469s0);
                t(interfaceC0466q0C, str, c0469s0);
            }
        }
    }

    protected void b(InterfaceC0466q0 interfaceC0466q0, float f3, float f4, List list) {
        if (interfaceC0466q0.x()) {
            if (interfaceC0466q0.q(f3, f4) && interfaceC0466q0.r() && !this.f7372d.f(interfaceC0466q0.H())) {
                list.add(interfaceC0466q0);
            }
            Iterable iterableE = interfaceC0466q0.E();
            if (iterableE != null) {
                Iterator it = iterableE.iterator();
                while (it.hasNext()) {
                    b((InterfaceC0466q0) it.next(), interfaceC0466q0.J() + f3, interfaceC0466q0.A() + f4, list);
                }
            }
            interfaceC0466q0.F(f3, f4, this.f7374f, this.f7375g);
            interfaceC0466q0.d();
            this.f7375g.p(interfaceC0466q0);
        }
    }

    protected void b0() {
        C0353a.c(0L, "UIImplementation.updateViewHierarchy");
        for (int i3 = 0; i3 < this.f7372d.d(); i3++) {
            try {
                InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(this.f7372d.e(i3));
                if (interfaceC0466q0C.getWidthMeasureSpec() != null && interfaceC0466q0C.getHeightMeasureSpec() != null) {
                    C0354b.a(0L, "UIImplementation.notifyOnBeforeLayoutRecursive").a("rootTag", interfaceC0466q0C.H()).c();
                    try {
                        A(interfaceC0466q0C);
                        C0353a.i(0L);
                        d(interfaceC0466q0C);
                        C0354b.a(0L, "UIImplementation.applyUpdatesRecursive").a("rootTag", interfaceC0466q0C.H()).c();
                        try {
                            ArrayList<InterfaceC0466q0> arrayList = new ArrayList();
                            b(interfaceC0466q0C, 0.0f, 0.0f, arrayList);
                            for (InterfaceC0466q0 interfaceC0466q0 : arrayList) {
                                this.f7370b.g(C0442e0.v(-1, interfaceC0466q0.H(), interfaceC0466q0.D(), interfaceC0466q0.j(), interfaceC0466q0.a(), interfaceC0466q0.b()));
                            }
                            C0353a.i(0L);
                        } finally {
                        }
                    } finally {
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void c0(int i3, int i4, Callback callback) {
        InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
        InterfaceC0466q0 interfaceC0466q0C2 = this.f7372d.c(i4);
        if (interfaceC0466q0C == null || interfaceC0466q0C2 == null) {
            callback.invoke(Boolean.FALSE);
        } else {
            callback.invoke(Boolean.valueOf(interfaceC0466q0C.Q(interfaceC0466q0C2)));
        }
    }

    protected void d(InterfaceC0466q0 interfaceC0466q0) {
        C0354b.a(0L, "cssRoot.calculateLayout").a("rootTag", interfaceC0466q0.H()).c();
        long jUptimeMillis = SystemClock.uptimeMillis();
        try {
            int iIntValue = interfaceC0466q0.getWidthMeasureSpec().intValue();
            int iIntValue2 = interfaceC0466q0.getHeightMeasureSpec().intValue();
            float size = Float.NaN;
            float size2 = View.MeasureSpec.getMode(iIntValue) == 0 ? Float.NaN : View.MeasureSpec.getSize(iIntValue);
            if (View.MeasureSpec.getMode(iIntValue2) != 0) {
                size = View.MeasureSpec.getSize(iIntValue2);
            }
            interfaceC0466q0.B(size2, size);
        } finally {
            C0353a.i(0L);
            this.f7377i = SystemClock.uptimeMillis() - jUptimeMillis;
        }
    }

    public void f() {
        this.f7374f.A();
    }

    public void g(ReadableMap readableMap, Callback callback) {
        this.f7374f.B(readableMap, callback);
    }

    protected InterfaceC0466q0 h() {
        C0467r0 c0467r0 = new C0467r0();
        if (com.facebook.react.modules.i18nmanager.a.f().i(this.f7371c)) {
            c0467r0.s(com.facebook.yoga.h.RTL);
        }
        c0467r0.p("Root");
        return c0467r0;
    }

    protected InterfaceC0466q0 i(String str) {
        return this.f7373e.c(str).createShadowNodeInstance(this.f7371c);
    }

    public void j(int i3, String str, int i4, ReadableMap readableMap) {
        C0469s0 c0469s0;
        if (this.f7378j) {
            synchronized (this.f7369a) {
                try {
                    InterfaceC0466q0 interfaceC0466q0I = i(str);
                    InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i4);
                    Z0.a.d(interfaceC0466q0C, "Root node with tag " + i4 + " doesn't exist");
                    interfaceC0466q0I.y(i3);
                    interfaceC0466q0I.p(str);
                    interfaceC0466q0I.b0(interfaceC0466q0C.H());
                    interfaceC0466q0I.c0(interfaceC0466q0C.l());
                    this.f7372d.a(interfaceC0466q0I);
                    if (readableMap != null) {
                        c0469s0 = new C0469s0(readableMap);
                        interfaceC0466q0I.X(c0469s0);
                    } else {
                        c0469s0 = null;
                    }
                    s(interfaceC0466q0I, i4, c0469s0);
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public void k(int i3, int i4, ReadableArray readableArray) {
        if (e(i3, "dispatchViewManagerCommand: " + i4)) {
            this.f7374f.D(i3, i4, readableArray);
        }
    }

    public void l(int i3, String str, ReadableArray readableArray) {
        if (e(i3, "dispatchViewManagerCommand: " + str)) {
            this.f7374f.E(i3, str, readableArray);
        }
    }

    public void m(int i3) {
        C0354b.a(0L, "UIImplementation.dispatchViewUpdates").a("batchId", i3).c();
        long jUptimeMillis = SystemClock.uptimeMillis();
        try {
            b0();
            this.f7375g.o();
            this.f7374f.z(i3, jUptimeMillis, this.f7377i);
        } finally {
            C0353a.i(0L);
        }
    }

    public void o(int i3, float f3, float f4, Callback callback) {
        this.f7374f.F(i3, f3, f4, callback);
    }

    public Map p() {
        return this.f7374f.T();
    }

    public int q() {
        return this.f7374f.S().p();
    }

    M0 r() {
        return this.f7374f;
    }

    protected void s(InterfaceC0466q0 interfaceC0466q0, int i3, C0469s0 c0469s0) {
        if (interfaceC0466q0.R()) {
            return;
        }
        this.f7375g.g(interfaceC0466q0, interfaceC0466q0.l(), c0469s0);
    }

    protected void t(InterfaceC0466q0 interfaceC0466q0, String str, C0469s0 c0469s0) {
        if (interfaceC0466q0.R()) {
            return;
        }
        this.f7375g.m(interfaceC0466q0, str, c0469s0);
    }

    public void u(int i3, ReadableArray readableArray, ReadableArray readableArray2, ReadableArray readableArray3, ReadableArray readableArray4, ReadableArray readableArray5) {
        ReadableArray readableArray6 = readableArray;
        if (!this.f7378j) {
            return;
        }
        synchronized (this.f7369a) {
            try {
                InterfaceC0466q0 interfaceC0466q0C = this.f7372d.c(i3);
                int size = readableArray6 == null ? 0 : readableArray.size();
                int size2 = readableArray3 == null ? 0 : readableArray3.size();
                int size3 = readableArray5 == null ? 0 : readableArray5.size();
                if (size != 0 && (readableArray2 == null || size != readableArray2.size())) {
                    throw new P("Size of moveFrom != size of moveTo!");
                }
                if (size2 != 0 && (readableArray4 == null || size2 != readableArray4.size())) {
                    throw new P("Size of addChildTags != size of addAtIndices!");
                }
                int i4 = size + size2;
                O0[] o0Arr = new O0[i4];
                int i5 = size + size3;
                int[] iArr = new int[i5];
                try {
                    int[] iArr2 = new int[i5];
                    int[] iArr3 = new int[size3];
                    if (size > 0) {
                        Z0.a.c(readableArray);
                        Z0.a.c(readableArray2);
                        int i6 = 0;
                        while (i6 < size) {
                            int i7 = i5;
                            int i8 = readableArray6.getInt(i6);
                            int iH = interfaceC0466q0C.N(i8).H();
                            o0Arr[i6] = new O0(iH, readableArray2.getInt(i6));
                            iArr[i6] = i8;
                            iArr2[i6] = iH;
                            i6++;
                            readableArray6 = readableArray;
                            i5 = i7;
                            iArr3 = iArr3;
                            interfaceC0466q0C = interfaceC0466q0C;
                        }
                    }
                    InterfaceC0466q0 interfaceC0466q0 = interfaceC0466q0C;
                    int[] iArr4 = iArr3;
                    int i9 = i5;
                    if (size2 > 0) {
                        Z0.a.c(readableArray3);
                        Z0.a.c(readableArray4);
                        for (int i10 = 0; i10 < size2; i10++) {
                            o0Arr[size + i10] = new O0(readableArray3.getInt(i10), readableArray4.getInt(i10));
                        }
                    }
                    if (size3 > 0) {
                        Z0.a.c(readableArray5);
                        int i11 = 0;
                        while (i11 < size3) {
                            int i12 = readableArray5.getInt(i11);
                            InterfaceC0466q0 interfaceC0466q02 = interfaceC0466q0;
                            int iH2 = interfaceC0466q02.N(i12).H();
                            int i13 = size + i11;
                            iArr[i13] = i12;
                            iArr2[i13] = iH2;
                            iArr4[i11] = iH2;
                            i11++;
                            interfaceC0466q0 = interfaceC0466q02;
                        }
                    }
                    InterfaceC0466q0 interfaceC0466q03 = interfaceC0466q0;
                    Arrays.sort(o0Arr, O0.f7478c);
                    Arrays.sort(iArr);
                    int i14 = -1;
                    for (int i15 = i9 - 1; i15 >= 0; i15--) {
                        int i16 = iArr[i15];
                        if (i16 == i14) {
                            throw new P("Repeated indices in Removal list for view tag: " + i3);
                        }
                        interfaceC0466q03.e(i16);
                        i14 = iArr[i15];
                    }
                    int i17 = 0;
                    while (i17 < i4) {
                        O0 o02 = o0Arr[i17];
                        int[] iArr5 = iArr2;
                        InterfaceC0466q0 interfaceC0466q0C2 = this.f7372d.c(o02.f7479a);
                        if (interfaceC0466q0C2 == null) {
                            throw new P("Trying to add unknown view tag: " + o02.f7479a);
                        }
                        interfaceC0466q03.o(interfaceC0466q0C2, o02.f7480b);
                        i17++;
                        iArr2 = iArr5;
                    }
                    this.f7375g.i(interfaceC0466q03, iArr, iArr2, o0Arr, iArr4);
                    for (int i18 = 0; i18 < size3; i18++) {
                        K(this.f7372d.c(iArr4[i18]));
                    }
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    public void v(int i3, Callback callback) {
        if (this.f7378j) {
            this.f7374f.H(i3, callback);
        }
    }

    public void w(int i3, Callback callback) {
        if (this.f7378j) {
            this.f7374f.I(i3, callback);
        }
    }

    public void x(int i3, int i4, Callback callback, Callback callback2) {
        if (this.f7378j) {
            try {
                y(i3, i4, this.f7376h);
                callback2.invoke(Float.valueOf(C0444f0.f(this.f7376h[0])), Float.valueOf(C0444f0.f(this.f7376h[1])), Float.valueOf(C0444f0.f(this.f7376h[2])), Float.valueOf(C0444f0.f(this.f7376h[3])));
            } catch (P e3) {
                callback.invoke(e3.getMessage());
            }
        }
    }

    protected G0(ReactApplicationContext reactApplicationContext, U0 u02, M0 m02, EventDispatcher eventDispatcher) {
        this.f7369a = new Object();
        C0481y0 c0481y0 = new C0481y0();
        this.f7372d = c0481y0;
        this.f7376h = new int[4];
        this.f7377i = 0L;
        this.f7378j = true;
        this.f7371c = reactApplicationContext;
        this.f7373e = u02;
        this.f7374f = m02;
        this.f7375g = new C0438c0(m02, c0481y0);
        this.f7370b = eventDispatcher;
    }
}
