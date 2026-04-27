package androidx.fragment.app;

import B.c;
import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Looper;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.OnBackPressedDispatcher;
import androidx.core.view.InterfaceC0284v;
import androidx.core.view.InterfaceC0287y;
import androidx.fragment.app.F;
import androidx.lifecycle.f;
import androidx.savedstate.a;
import b.AbstractC0308a;
import b.C0309b;
import b.C0310c;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import q.InterfaceC0651a;

/* JADX INFO: loaded from: classes.dex */
public abstract class x {

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    private static boolean f5024S = false;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private androidx.activity.result.c f5028D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private androidx.activity.result.c f5029E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private androidx.activity.result.c f5030F;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private boolean f5032H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private boolean f5033I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private boolean f5034J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private boolean f5035K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private boolean f5036L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private ArrayList f5037M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    private ArrayList f5038N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    private ArrayList f5039O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private A f5040P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private c.C0001c f5041Q;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f5044b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    ArrayList f5046d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private ArrayList f5047e;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private OnBackPressedDispatcher f5049g;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private ArrayList f5055m;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private p f5064v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private AbstractC0300l f5065w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private Fragment f5066x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    Fragment f5067y;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ArrayList f5043a = new ArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final E f5045c = new E();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final q f5048f = new q(this);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final androidx.activity.m f5050h = new b(false);

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final AtomicInteger f5051i = new AtomicInteger();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Map f5052j = Collections.synchronizedMap(new HashMap());

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final Map f5053k = Collections.synchronizedMap(new HashMap());

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final Map f5054l = Collections.synchronizedMap(new HashMap());

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final r f5056n = new r(this);

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final CopyOnWriteArrayList f5057o = new CopyOnWriteArrayList();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final InterfaceC0651a f5058p = new InterfaceC0651a() { // from class: androidx.fragment.app.s
        @Override // q.InterfaceC0651a
        public final void a(Object obj) {
            this.f5019a.P0((Configuration) obj);
        }
    };

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final InterfaceC0651a f5059q = new InterfaceC0651a() { // from class: androidx.fragment.app.t
        @Override // q.InterfaceC0651a
        public final void a(Object obj) {
            this.f5020a.Q0((Integer) obj);
        }
    };

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final InterfaceC0651a f5060r = new InterfaceC0651a() { // from class: androidx.fragment.app.u
        @Override // q.InterfaceC0651a
        public final void a(Object obj) {
            this.f5021a.R0((androidx.core.app.g) obj);
        }
    };

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final InterfaceC0651a f5061s = new InterfaceC0651a() { // from class: androidx.fragment.app.v
        @Override // q.InterfaceC0651a
        public final void a(Object obj) {
            this.f5022a.S0((androidx.core.app.l) obj);
        }
    };

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final InterfaceC0287y f5062t = new c();

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    int f5063u = -1;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private o f5068z = null;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private o f5025A = new d();

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private M f5026B = null;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private M f5027C = new e();

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    ArrayDeque f5031G = new ArrayDeque();

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    private Runnable f5042R = new f();

    class a implements androidx.activity.result.b {
        a() {
        }

        @Override // androidx.activity.result.b
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(Map map) {
            String[] strArr = (String[]) map.keySet().toArray(new String[0]);
            ArrayList arrayList = new ArrayList(map.values());
            int[] iArr = new int[arrayList.size()];
            for (int i3 = 0; i3 < arrayList.size(); i3++) {
                iArr[i3] = ((Boolean) arrayList.get(i3)).booleanValue() ? 0 : -1;
            }
            k kVar = (k) x.this.f5031G.pollFirst();
            if (kVar == null) {
                Log.w("FragmentManager", "No permissions were requested for " + this);
                return;
            }
            String str = kVar.f5079a;
            int i4 = kVar.f5080b;
            Fragment fragmentI = x.this.f5045c.i(str);
            if (fragmentI != null) {
                fragmentI.D0(i4, strArr, iArr);
                return;
            }
            Log.w("FragmentManager", "Permission request result delivered for unknown Fragment " + str);
        }
    }

    class b extends androidx.activity.m {
        b(boolean z3) {
            super(z3);
        }

        @Override // androidx.activity.m
        public void b() {
            x.this.C0();
        }
    }

    class c implements InterfaceC0287y {
        c() {
        }

        @Override // androidx.core.view.InterfaceC0287y
        public boolean a(MenuItem menuItem) {
            return x.this.J(menuItem);
        }

        @Override // androidx.core.view.InterfaceC0287y
        public void b(Menu menu) {
            x.this.K(menu);
        }

        @Override // androidx.core.view.InterfaceC0287y
        public void c(Menu menu, MenuInflater menuInflater) {
            x.this.C(menu, menuInflater);
        }

        @Override // androidx.core.view.InterfaceC0287y
        public void d(Menu menu) {
            x.this.O(menu);
        }
    }

    class d extends o {
        d() {
        }

        @Override // androidx.fragment.app.o
        public Fragment a(ClassLoader classLoader, String str) {
            return x.this.t0().e(x.this.t0().k(), str, null);
        }
    }

    class e implements M {
        e() {
        }

        @Override // androidx.fragment.app.M
        public L a(ViewGroup viewGroup) {
            return new C0292d(viewGroup);
        }
    }

    class f implements Runnable {
        f() {
        }

        @Override // java.lang.Runnable
        public void run() {
            x.this.a0(true);
        }
    }

    class g implements B {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Fragment f5075b;

        g(Fragment fragment) {
            this.f5075b = fragment;
        }

        @Override // androidx.fragment.app.B
        public void c(x xVar, Fragment fragment) {
            this.f5075b.h0(fragment);
        }
    }

    class h implements androidx.activity.result.b {
        h() {
        }

        @Override // androidx.activity.result.b
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(androidx.activity.result.a aVar) {
            k kVar = (k) x.this.f5031G.pollFirst();
            if (kVar == null) {
                Log.w("FragmentManager", "No Activities were started for result for " + this);
                return;
            }
            String str = kVar.f5079a;
            int i3 = kVar.f5080b;
            Fragment fragmentI = x.this.f5045c.i(str);
            if (fragmentI != null) {
                fragmentI.e0(i3, aVar.b(), aVar.a());
                return;
            }
            Log.w("FragmentManager", "Activity result delivered for unknown Fragment " + str);
        }
    }

    class i implements androidx.activity.result.b {
        i() {
        }

        @Override // androidx.activity.result.b
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(androidx.activity.result.a aVar) {
            k kVar = (k) x.this.f5031G.pollFirst();
            if (kVar == null) {
                Log.w("FragmentManager", "No IntentSenders were started for " + this);
                return;
            }
            String str = kVar.f5079a;
            int i3 = kVar.f5080b;
            Fragment fragmentI = x.this.f5045c.i(str);
            if (fragmentI != null) {
                fragmentI.e0(i3, aVar.b(), aVar.a());
                return;
            }
            Log.w("FragmentManager", "Intent Sender result delivered for unknown Fragment " + str);
        }
    }

    static class j extends AbstractC0308a {
        j() {
        }

        @Override // b.AbstractC0308a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public androidx.activity.result.a a(int i3, Intent intent) {
            return new androidx.activity.result.a(i3, intent);
        }
    }

    static class k implements Parcelable {
        public static final Parcelable.Creator<k> CREATOR = new a();

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        String f5079a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f5080b;

        class a implements Parcelable.Creator {
            a() {
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
            public k createFromParcel(Parcel parcel) {
                return new k(parcel);
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
            public k[] newArray(int i3) {
                return new k[i3];
            }
        }

        k(Parcel parcel) {
            this.f5079a = parcel.readString();
            this.f5080b = parcel.readInt();
        }

        @Override // android.os.Parcelable
        public int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i3) {
            parcel.writeString(this.f5079a);
            parcel.writeInt(this.f5080b);
        }
    }

    interface l {
        boolean a(ArrayList arrayList, ArrayList arrayList2);
    }

    private class m implements l {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final String f5081a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final int f5082b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final int f5083c;

        m(String str, int i3, int i4) {
            this.f5081a = str;
            this.f5082b = i3;
            this.f5083c = i4;
        }

        @Override // androidx.fragment.app.x.l
        public boolean a(ArrayList arrayList, ArrayList arrayList2) {
            Fragment fragment = x.this.f5067y;
            if (fragment == null || this.f5082b >= 0 || this.f5081a != null || !fragment.n().Y0()) {
                return x.this.b1(arrayList, arrayList2, this.f5081a, this.f5082b, this.f5083c);
            }
            return false;
        }
    }

    static Fragment A0(View view) {
        Object tag = view.getTag(A.b.f6a);
        if (tag instanceof Fragment) {
            return (Fragment) tag;
        }
        return null;
    }

    public static boolean G0(int i3) {
        return f5024S || Log.isLoggable("FragmentManager", i3);
    }

    private boolean H0(Fragment fragment) {
        return (fragment.f4760F && fragment.f4761G) || fragment.f4804w.p();
    }

    private boolean I0() {
        Fragment fragment = this.f5066x;
        if (fragment == null) {
            return true;
        }
        return fragment.V() && this.f5066x.D().I0();
    }

    private void L(Fragment fragment) {
        if (fragment == null || !fragment.equals(e0(fragment.f4788g))) {
            return;
        }
        fragment.c1();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void P0(Configuration configuration) {
        if (I0()) {
            z(configuration, false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void Q0(Integer num) {
        if (I0() && num.intValue() == 80) {
            F(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void R0(androidx.core.app.g gVar) {
        if (I0()) {
            G(gVar.a(), false);
        }
    }

    private void S(int i3) {
        try {
            this.f5044b = true;
            this.f5045c.d(i3);
            T0(i3, false);
            Iterator it = t().iterator();
            while (it.hasNext()) {
                ((L) it.next()).j();
            }
            this.f5044b = false;
            a0(true);
        } catch (Throwable th) {
            this.f5044b = false;
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void S0(androidx.core.app.l lVar) {
        if (I0()) {
            N(lVar.a(), false);
        }
    }

    private void V() {
        if (this.f5036L) {
            this.f5036L = false;
            o1();
        }
    }

    private void X() {
        Iterator it = t().iterator();
        while (it.hasNext()) {
            ((L) it.next()).j();
        }
    }

    private void Z(boolean z3) {
        if (this.f5044b) {
            throw new IllegalStateException("FragmentManager is already executing transactions");
        }
        if (this.f5064v == null) {
            if (!this.f5035K) {
                throw new IllegalStateException("FragmentManager has not been attached to a host.");
            }
            throw new IllegalStateException("FragmentManager has been destroyed");
        }
        if (Looper.myLooper() != this.f5064v.o().getLooper()) {
            throw new IllegalStateException("Must be called from main thread of fragment host");
        }
        if (!z3) {
            q();
        }
        if (this.f5037M == null) {
            this.f5037M = new ArrayList();
            this.f5038N = new ArrayList();
        }
    }

    private boolean a1(String str, int i3, int i4) {
        a0(false);
        Z(true);
        Fragment fragment = this.f5067y;
        if (fragment != null && i3 < 0 && str == null && fragment.n().Y0()) {
            return true;
        }
        boolean zB1 = b1(this.f5037M, this.f5038N, str, i3, i4);
        if (zB1) {
            this.f5044b = true;
            try {
                d1(this.f5037M, this.f5038N);
            } finally {
                r();
            }
        }
        q1();
        V();
        this.f5045c.b();
        return zB1;
    }

    private static void c0(ArrayList arrayList, ArrayList arrayList2, int i3, int i4) {
        while (i3 < i4) {
            C0289a c0289a = (C0289a) arrayList.get(i3);
            if (((Boolean) arrayList2.get(i3)).booleanValue()) {
                c0289a.n(-1);
                c0289a.s();
            } else {
                c0289a.n(1);
                c0289a.r();
            }
            i3++;
        }
    }

    private void d0(ArrayList arrayList, ArrayList arrayList2, int i3, int i4) {
        boolean z3 = ((C0289a) arrayList.get(i3)).f4743r;
        ArrayList arrayList3 = this.f5039O;
        if (arrayList3 == null) {
            this.f5039O = new ArrayList();
        } else {
            arrayList3.clear();
        }
        this.f5039O.addAll(this.f5045c.o());
        Fragment fragmentX0 = x0();
        boolean z4 = false;
        for (int i5 = i3; i5 < i4; i5++) {
            C0289a c0289a = (C0289a) arrayList.get(i5);
            fragmentX0 = !((Boolean) arrayList2.get(i5)).booleanValue() ? c0289a.t(this.f5039O, fragmentX0) : c0289a.w(this.f5039O, fragmentX0);
            z4 = z4 || c0289a.f4734i;
        }
        this.f5039O.clear();
        if (!z3 && this.f5063u >= 1) {
            for (int i6 = i3; i6 < i4; i6++) {
                Iterator it = ((C0289a) arrayList.get(i6)).f4728c.iterator();
                while (it.hasNext()) {
                    Fragment fragment = ((F.a) it.next()).f4746b;
                    if (fragment != null && fragment.f4802u != null) {
                        this.f5045c.r(v(fragment));
                    }
                }
            }
        }
        c0(arrayList, arrayList2, i3, i4);
        boolean zBooleanValue = ((Boolean) arrayList2.get(i4 - 1)).booleanValue();
        for (int i7 = i3; i7 < i4; i7++) {
            C0289a c0289a2 = (C0289a) arrayList.get(i7);
            if (zBooleanValue) {
                for (int size = c0289a2.f4728c.size() - 1; size >= 0; size--) {
                    Fragment fragment2 = ((F.a) c0289a2.f4728c.get(size)).f4746b;
                    if (fragment2 != null) {
                        v(fragment2).m();
                    }
                }
            } else {
                Iterator it2 = c0289a2.f4728c.iterator();
                while (it2.hasNext()) {
                    Fragment fragment3 = ((F.a) it2.next()).f4746b;
                    if (fragment3 != null) {
                        v(fragment3).m();
                    }
                }
            }
        }
        T0(this.f5063u, true);
        for (L l3 : u(arrayList, i3, i4)) {
            l3.r(zBooleanValue);
            l3.p();
            l3.g();
        }
        while (i3 < i4) {
            C0289a c0289a3 = (C0289a) arrayList.get(i3);
            if (((Boolean) arrayList2.get(i3)).booleanValue() && c0289a3.f4899v >= 0) {
                c0289a3.f4899v = -1;
            }
            c0289a3.v();
            i3++;
        }
        if (z4) {
            e1();
        }
    }

    private void d1(ArrayList arrayList, ArrayList arrayList2) {
        if (arrayList.isEmpty()) {
            return;
        }
        if (arrayList.size() != arrayList2.size()) {
            throw new IllegalStateException("Internal error with the back stack records");
        }
        int size = arrayList.size();
        int i3 = 0;
        int i4 = 0;
        while (i3 < size) {
            if (!((C0289a) arrayList.get(i3)).f4743r) {
                if (i4 != i3) {
                    d0(arrayList, arrayList2, i4, i3);
                }
                i4 = i3 + 1;
                if (((Boolean) arrayList2.get(i3)).booleanValue()) {
                    while (i4 < size && ((Boolean) arrayList2.get(i4)).booleanValue() && !((C0289a) arrayList.get(i4)).f4743r) {
                        i4++;
                    }
                }
                d0(arrayList, arrayList2, i3, i4);
                i3 = i4 - 1;
            }
            i3++;
        }
        if (i4 != size) {
            d0(arrayList, arrayList2, i4, size);
        }
    }

    private void e1() {
        ArrayList arrayList = this.f5055m;
        if (arrayList == null || arrayList.size() <= 0) {
            return;
        }
        androidx.activity.result.d.a(this.f5055m.get(0));
        throw null;
    }

    private int f0(String str, int i3, boolean z3) {
        ArrayList arrayList = this.f5046d;
        if (arrayList == null || arrayList.isEmpty()) {
            return -1;
        }
        if (str == null && i3 < 0) {
            if (z3) {
                return 0;
            }
            return this.f5046d.size() - 1;
        }
        int size = this.f5046d.size() - 1;
        while (size >= 0) {
            C0289a c0289a = (C0289a) this.f5046d.get(size);
            if ((str != null && str.equals(c0289a.u())) || (i3 >= 0 && i3 == c0289a.f4899v)) {
                break;
            }
            size--;
        }
        if (size < 0) {
            return size;
        }
        if (!z3) {
            if (size == this.f5046d.size() - 1) {
                return -1;
            }
            return size + 1;
        }
        while (size > 0) {
            C0289a c0289a2 = (C0289a) this.f5046d.get(size - 1);
            if ((str == null || !str.equals(c0289a2.u())) && (i3 < 0 || i3 != c0289a2.f4899v)) {
                return size;
            }
            size--;
        }
        return size;
    }

    static int g1(int i3) {
        int i4 = 4097;
        if (i3 == 4097) {
            return 8194;
        }
        if (i3 != 8194) {
            i4 = 8197;
            if (i3 == 8197) {
                return 4100;
            }
            if (i3 == 4099) {
                return 4099;
            }
            if (i3 != 4100) {
                return 0;
            }
        }
        return i4;
    }

    static x j0(View view) {
        AbstractActivityC0298j abstractActivityC0298j;
        Fragment fragmentK0 = k0(view);
        if (fragmentK0 != null) {
            if (fragmentK0.V()) {
                return fragmentK0.n();
            }
            throw new IllegalStateException("The Fragment " + fragmentK0 + " that owns View " + view + " has already been destroyed. Nested fragments should always use the child FragmentManager.");
        }
        Context context = view.getContext();
        while (true) {
            if (!(context instanceof ContextWrapper)) {
                abstractActivityC0298j = null;
                break;
            }
            if (context instanceof AbstractActivityC0298j) {
                abstractActivityC0298j = (AbstractActivityC0298j) context;
                break;
            }
            context = ((ContextWrapper) context).getBaseContext();
        }
        if (abstractActivityC0298j != null) {
            return abstractActivityC0298j.S();
        }
        throw new IllegalStateException("View " + view + " is not within a subclass of FragmentActivity.");
    }

    private static Fragment k0(View view) {
        while (view != null) {
            Fragment fragmentA0 = A0(view);
            if (fragmentA0 != null) {
                return fragmentA0;
            }
            Object parent = view.getParent();
            view = parent instanceof View ? (View) parent : null;
        }
        return null;
    }

    private void l0() {
        Iterator it = t().iterator();
        while (it.hasNext()) {
            ((L) it.next()).k();
        }
    }

    private boolean m0(ArrayList arrayList, ArrayList arrayList2) {
        synchronized (this.f5043a) {
            if (this.f5043a.isEmpty()) {
                return false;
            }
            try {
                int size = this.f5043a.size();
                boolean zA = false;
                for (int i3 = 0; i3 < size; i3++) {
                    zA |= ((l) this.f5043a.get(i3)).a(arrayList, arrayList2);
                }
                return zA;
            } finally {
                this.f5043a.clear();
                this.f5064v.o().removeCallbacks(this.f5042R);
            }
        }
    }

    private void m1(Fragment fragment) {
        ViewGroup viewGroupQ0 = q0(fragment);
        if (viewGroupQ0 == null || fragment.p() + fragment.u() + fragment.F() + fragment.G() <= 0) {
            return;
        }
        if (viewGroupQ0.getTag(A.b.f8c) == null) {
            viewGroupQ0.setTag(A.b.f8c, fragment);
        }
        ((Fragment) viewGroupQ0.getTag(A.b.f8c)).u1(fragment.E());
    }

    private A o0(Fragment fragment) {
        return this.f5040P.j(fragment);
    }

    private void o1() {
        Iterator it = this.f5045c.k().iterator();
        while (it.hasNext()) {
            W0((D) it.next());
        }
    }

    private void p1(RuntimeException runtimeException) {
        Log.e("FragmentManager", runtimeException.getMessage());
        Log.e("FragmentManager", "Activity state:");
        PrintWriter printWriter = new PrintWriter(new K("FragmentManager"));
        p pVar = this.f5064v;
        if (pVar != null) {
            try {
                pVar.v("  ", null, printWriter, new String[0]);
                throw runtimeException;
            } catch (Exception e3) {
                Log.e("FragmentManager", "Failed dumping state", e3);
                throw runtimeException;
            }
        }
        try {
            W("  ", null, printWriter, new String[0]);
            throw runtimeException;
        } catch (Exception e4) {
            Log.e("FragmentManager", "Failed dumping state", e4);
            throw runtimeException;
        }
    }

    private void q() {
        if (N0()) {
            throw new IllegalStateException("Can not perform this action after onSaveInstanceState");
        }
    }

    private ViewGroup q0(Fragment fragment) {
        ViewGroup viewGroup = fragment.f4763I;
        if (viewGroup != null) {
            return viewGroup;
        }
        if (fragment.f4807z > 0 && this.f5065w.h()) {
            View viewF = this.f5065w.f(fragment.f4807z);
            if (viewF instanceof ViewGroup) {
                return (ViewGroup) viewF;
            }
        }
        return null;
    }

    private void q1() {
        synchronized (this.f5043a) {
            try {
                if (this.f5043a.isEmpty()) {
                    this.f5050h.f(n0() > 0 && L0(this.f5066x));
                } else {
                    this.f5050h.f(true);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private void r() {
        this.f5044b = false;
        this.f5038N.clear();
        this.f5037M.clear();
    }

    private void s() {
        p pVar = this.f5064v;
        if (pVar instanceof androidx.lifecycle.C ? this.f5045c.p().n() : pVar.k() instanceof Activity ? !((Activity) this.f5064v.k()).isChangingConfigurations() : true) {
            Iterator it = this.f5052j.values().iterator();
            while (it.hasNext()) {
                Iterator it2 = ((C0291c) it.next()).f4915a.iterator();
                while (it2.hasNext()) {
                    this.f5045c.p().g((String) it2.next());
                }
            }
        }
    }

    private Set t() {
        HashSet hashSet = new HashSet();
        Iterator it = this.f5045c.k().iterator();
        while (it.hasNext()) {
            ViewGroup viewGroup = ((D) it.next()).k().f4763I;
            if (viewGroup != null) {
                hashSet.add(L.o(viewGroup, y0()));
            }
        }
        return hashSet;
    }

    private Set u(ArrayList arrayList, int i3, int i4) {
        ViewGroup viewGroup;
        HashSet hashSet = new HashSet();
        while (i3 < i4) {
            Iterator it = ((C0289a) arrayList.get(i3)).f4728c.iterator();
            while (it.hasNext()) {
                Fragment fragment = ((F.a) it.next()).f4746b;
                if (fragment != null && (viewGroup = fragment.f4763I) != null) {
                    hashSet.add(L.n(viewGroup, this));
                }
            }
            i3++;
        }
        return hashSet;
    }

    boolean A(MenuItem menuItem) {
        if (this.f5063u < 1) {
            return false;
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null && fragment.N0(menuItem)) {
                return true;
            }
        }
        return false;
    }

    void B() {
        this.f5033I = false;
        this.f5034J = false;
        this.f5040P.p(false);
        S(1);
    }

    androidx.lifecycle.B B0(Fragment fragment) {
        return this.f5040P.m(fragment);
    }

    boolean C(Menu menu, MenuInflater menuInflater) {
        if (this.f5063u < 1) {
            return false;
        }
        ArrayList arrayList = null;
        boolean z3 = false;
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null && K0(fragment) && fragment.P0(menu, menuInflater)) {
                if (arrayList == null) {
                    arrayList = new ArrayList();
                }
                arrayList.add(fragment);
                z3 = true;
            }
        }
        if (this.f5047e != null) {
            for (int i3 = 0; i3 < this.f5047e.size(); i3++) {
                Fragment fragment2 = (Fragment) this.f5047e.get(i3);
                if (arrayList == null || !arrayList.contains(fragment2)) {
                    fragment2.p0();
                }
            }
        }
        this.f5047e = arrayList;
        return z3;
    }

    void C0() {
        a0(true);
        if (this.f5050h.c()) {
            Y0();
        } else {
            this.f5049g.e();
        }
    }

    void D() {
        this.f5035K = true;
        a0(true);
        X();
        s();
        S(-1);
        Object obj = this.f5064v;
        if (obj instanceof androidx.core.content.d) {
            ((androidx.core.content.d) obj).u(this.f5059q);
        }
        Object obj2 = this.f5064v;
        if (obj2 instanceof androidx.core.content.c) {
            ((androidx.core.content.c) obj2).j(this.f5058p);
        }
        Object obj3 = this.f5064v;
        if (obj3 instanceof androidx.core.app.j) {
            ((androidx.core.app.j) obj3).g(this.f5060r);
        }
        Object obj4 = this.f5064v;
        if (obj4 instanceof androidx.core.app.k) {
            ((androidx.core.app.k) obj4).t(this.f5061s);
        }
        Object obj5 = this.f5064v;
        if (obj5 instanceof InterfaceC0284v) {
            ((InterfaceC0284v) obj5).d(this.f5062t);
        }
        this.f5064v = null;
        this.f5065w = null;
        this.f5066x = null;
        if (this.f5049g != null) {
            this.f5050h.d();
            this.f5049g = null;
        }
        androidx.activity.result.c cVar = this.f5028D;
        if (cVar != null) {
            cVar.a();
            this.f5029E.a();
            this.f5030F.a();
        }
    }

    void D0(Fragment fragment) {
        if (G0(2)) {
            Log.v("FragmentManager", "hide: " + fragment);
        }
        if (fragment.f4756B) {
            return;
        }
        fragment.f4756B = true;
        fragment.f4769O = true ^ fragment.f4769O;
        m1(fragment);
    }

    void E() {
        S(1);
    }

    void E0(Fragment fragment) {
        if (fragment.f4794m && H0(fragment)) {
            this.f5032H = true;
        }
    }

    void F(boolean z3) {
        if (z3 && (this.f5064v instanceof androidx.core.content.d)) {
            p1(new IllegalStateException("Do not call dispatchLowMemory() on host. Host implements OnTrimMemoryProvider and automatically dispatches low memory callbacks to fragments."));
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null) {
                fragment.V0();
                if (z3) {
                    fragment.f4804w.F(true);
                }
            }
        }
    }

    public boolean F0() {
        return this.f5035K;
    }

    void G(boolean z3, boolean z4) {
        if (z4 && (this.f5064v instanceof androidx.core.app.j)) {
            p1(new IllegalStateException("Do not call dispatchMultiWindowModeChanged() on host. Host implements OnMultiWindowModeChangedProvider and automatically dispatches multi-window mode changes to fragments."));
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null) {
                fragment.W0(z3);
                if (z4) {
                    fragment.f4804w.G(z3, true);
                }
            }
        }
    }

    void H(Fragment fragment) {
        Iterator it = this.f5057o.iterator();
        while (it.hasNext()) {
            ((B) it.next()).c(this, fragment);
        }
    }

    void I() {
        for (Fragment fragment : this.f5045c.l()) {
            if (fragment != null) {
                fragment.t0(fragment.W());
                fragment.f4804w.I();
            }
        }
    }

    boolean J(MenuItem menuItem) {
        if (this.f5063u < 1) {
            return false;
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null && fragment.X0(menuItem)) {
                return true;
            }
        }
        return false;
    }

    boolean J0(Fragment fragment) {
        if (fragment == null) {
            return false;
        }
        return fragment.W();
    }

    void K(Menu menu) {
        if (this.f5063u < 1) {
            return;
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null) {
                fragment.Y0(menu);
            }
        }
    }

    boolean K0(Fragment fragment) {
        if (fragment == null) {
            return true;
        }
        return fragment.Y();
    }

    boolean L0(Fragment fragment) {
        if (fragment == null) {
            return true;
        }
        x xVar = fragment.f4802u;
        return fragment.equals(xVar.x0()) && L0(xVar.f5066x);
    }

    void M() {
        S(5);
    }

    boolean M0(int i3) {
        return this.f5063u >= i3;
    }

    void N(boolean z3, boolean z4) {
        if (z4 && (this.f5064v instanceof androidx.core.app.k)) {
            p1(new IllegalStateException("Do not call dispatchPictureInPictureModeChanged() on host. Host implements OnPictureInPictureModeChangedProvider and automatically dispatches picture-in-picture mode changes to fragments."));
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null) {
                fragment.a1(z3);
                if (z4) {
                    fragment.f4804w.N(z3, true);
                }
            }
        }
    }

    public boolean N0() {
        return this.f5033I || this.f5034J;
    }

    boolean O(Menu menu) {
        boolean z3 = false;
        if (this.f5063u < 1) {
            return false;
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null && K0(fragment) && fragment.b1(menu)) {
                z3 = true;
            }
        }
        return z3;
    }

    void P() {
        q1();
        L(this.f5067y);
    }

    void Q() {
        this.f5033I = false;
        this.f5034J = false;
        this.f5040P.p(false);
        S(7);
    }

    void R() {
        this.f5033I = false;
        this.f5034J = false;
        this.f5040P.p(false);
        S(5);
    }

    void T() {
        this.f5034J = true;
        this.f5040P.p(true);
        S(4);
    }

    void T0(int i3, boolean z3) {
        p pVar;
        if (this.f5064v == null && i3 != -1) {
            throw new IllegalStateException("No activity");
        }
        if (z3 || i3 != this.f5063u) {
            this.f5063u = i3;
            this.f5045c.t();
            o1();
            if (this.f5032H && (pVar = this.f5064v) != null && this.f5063u == 7) {
                pVar.z();
                this.f5032H = false;
            }
        }
    }

    void U() {
        S(2);
    }

    void U0() {
        if (this.f5064v == null) {
            return;
        }
        this.f5033I = false;
        this.f5034J = false;
        this.f5040P.p(false);
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null) {
                fragment.c0();
            }
        }
    }

    void V0(C0301m c0301m) {
        View view;
        for (D d3 : this.f5045c.k()) {
            Fragment fragmentK = d3.k();
            if (fragmentK.f4807z == c0301m.getId() && (view = fragmentK.f4764J) != null && view.getParent() == null) {
                fragmentK.f4763I = c0301m;
                d3.b();
            }
        }
    }

    public void W(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        int size;
        int size2;
        String str2 = str + "    ";
        this.f5045c.e(str, fileDescriptor, printWriter, strArr);
        ArrayList arrayList = this.f5047e;
        if (arrayList != null && (size2 = arrayList.size()) > 0) {
            printWriter.print(str);
            printWriter.println("Fragments Created Menus:");
            for (int i3 = 0; i3 < size2; i3++) {
                Fragment fragment = (Fragment) this.f5047e.get(i3);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i3);
                printWriter.print(": ");
                printWriter.println(fragment.toString());
            }
        }
        ArrayList arrayList2 = this.f5046d;
        if (arrayList2 != null && (size = arrayList2.size()) > 0) {
            printWriter.print(str);
            printWriter.println("Back Stack:");
            for (int i4 = 0; i4 < size; i4++) {
                C0289a c0289a = (C0289a) this.f5046d.get(i4);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i4);
                printWriter.print(": ");
                printWriter.println(c0289a.toString());
                c0289a.p(str2, printWriter);
            }
        }
        printWriter.print(str);
        printWriter.println("Back Stack Index: " + this.f5051i.get());
        synchronized (this.f5043a) {
            try {
                int size3 = this.f5043a.size();
                if (size3 > 0) {
                    printWriter.print(str);
                    printWriter.println("Pending Actions:");
                    for (int i5 = 0; i5 < size3; i5++) {
                        l lVar = (l) this.f5043a.get(i5);
                        printWriter.print(str);
                        printWriter.print("  #");
                        printWriter.print(i5);
                        printWriter.print(": ");
                        printWriter.println(lVar);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        printWriter.print(str);
        printWriter.println("FragmentManager misc state:");
        printWriter.print(str);
        printWriter.print("  mHost=");
        printWriter.println(this.f5064v);
        printWriter.print(str);
        printWriter.print("  mContainer=");
        printWriter.println(this.f5065w);
        if (this.f5066x != null) {
            printWriter.print(str);
            printWriter.print("  mParent=");
            printWriter.println(this.f5066x);
        }
        printWriter.print(str);
        printWriter.print("  mCurState=");
        printWriter.print(this.f5063u);
        printWriter.print(" mStateSaved=");
        printWriter.print(this.f5033I);
        printWriter.print(" mStopped=");
        printWriter.print(this.f5034J);
        printWriter.print(" mDestroyed=");
        printWriter.println(this.f5035K);
        if (this.f5032H) {
            printWriter.print(str);
            printWriter.print("  mNeedMenuInvalidate=");
            printWriter.println(this.f5032H);
        }
    }

    void W0(D d3) {
        Fragment fragmentK = d3.k();
        if (fragmentK.f4765K) {
            if (this.f5044b) {
                this.f5036L = true;
            } else {
                fragmentK.f4765K = false;
                d3.m();
            }
        }
    }

    void X0(int i3, int i4, boolean z3) {
        if (i3 >= 0) {
            Y(new m(null, i3, i4), z3);
            return;
        }
        throw new IllegalArgumentException("Bad id: " + i3);
    }

    void Y(l lVar, boolean z3) {
        if (!z3) {
            if (this.f5064v == null) {
                if (!this.f5035K) {
                    throw new IllegalStateException("FragmentManager has not been attached to a host.");
                }
                throw new IllegalStateException("FragmentManager has been destroyed");
            }
            q();
        }
        synchronized (this.f5043a) {
            try {
                if (this.f5064v == null) {
                    if (!z3) {
                        throw new IllegalStateException("Activity has been destroyed");
                    }
                } else {
                    this.f5043a.add(lVar);
                    i1();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public boolean Y0() {
        return a1(null, -1, 0);
    }

    public boolean Z0(int i3, int i4) {
        if (i3 >= 0) {
            return a1(null, i3, i4);
        }
        throw new IllegalArgumentException("Bad id: " + i3);
    }

    boolean a0(boolean z3) {
        Z(z3);
        boolean z4 = false;
        while (m0(this.f5037M, this.f5038N)) {
            z4 = true;
            this.f5044b = true;
            try {
                d1(this.f5037M, this.f5038N);
            } finally {
                r();
            }
        }
        q1();
        V();
        this.f5045c.b();
        return z4;
    }

    void b0(l lVar, boolean z3) {
        if (z3 && (this.f5064v == null || this.f5035K)) {
            return;
        }
        Z(z3);
        if (lVar.a(this.f5037M, this.f5038N)) {
            this.f5044b = true;
            try {
                d1(this.f5037M, this.f5038N);
            } finally {
                r();
            }
        }
        q1();
        V();
        this.f5045c.b();
    }

    boolean b1(ArrayList arrayList, ArrayList arrayList2, String str, int i3, int i4) {
        int iF0 = f0(str, i3, (i4 & 1) != 0);
        if (iF0 < 0) {
            return false;
        }
        for (int size = this.f5046d.size() - 1; size >= iF0; size--) {
            arrayList.add((C0289a) this.f5046d.remove(size));
            arrayList2.add(Boolean.TRUE);
        }
        return true;
    }

    void c1(Fragment fragment) {
        if (G0(2)) {
            Log.v("FragmentManager", "remove: " + fragment + " nesting=" + fragment.f4801t);
        }
        boolean zX = fragment.X();
        if (fragment.f4757C && zX) {
            return;
        }
        this.f5045c.u(fragment);
        if (H0(fragment)) {
            this.f5032H = true;
        }
        fragment.f4795n = true;
        m1(fragment);
    }

    Fragment e0(String str) {
        return this.f5045c.f(str);
    }

    void f1(Parcelable parcelable) {
        D d3;
        Bundle bundle;
        Bundle bundle2;
        if (parcelable == null) {
            return;
        }
        Bundle bundle3 = (Bundle) parcelable;
        for (String str : bundle3.keySet()) {
            if (str.startsWith("result_") && (bundle2 = bundle3.getBundle(str)) != null) {
                bundle2.setClassLoader(this.f5064v.k().getClassLoader());
                this.f5053k.put(str.substring(7), bundle2);
            }
        }
        ArrayList arrayList = new ArrayList();
        for (String str2 : bundle3.keySet()) {
            if (str2.startsWith("fragment_") && (bundle = bundle3.getBundle(str2)) != null) {
                bundle.setClassLoader(this.f5064v.k().getClassLoader());
                arrayList.add((C) bundle.getParcelable("state"));
            }
        }
        this.f5045c.x(arrayList);
        z zVar = (z) bundle3.getParcelable("state");
        if (zVar == null) {
            return;
        }
        this.f5045c.v();
        Iterator it = zVar.f5085a.iterator();
        while (it.hasNext()) {
            C cB = this.f5045c.B((String) it.next(), null);
            if (cB != null) {
                Fragment fragmentI = this.f5040P.i(cB.f4702b);
                if (fragmentI != null) {
                    if (G0(2)) {
                        Log.v("FragmentManager", "restoreSaveState: re-attaching retained " + fragmentI);
                    }
                    d3 = new D(this.f5056n, this.f5045c, fragmentI, cB);
                } else {
                    d3 = new D(this.f5056n, this.f5045c, this.f5064v.k().getClassLoader(), r0(), cB);
                }
                Fragment fragmentK = d3.k();
                fragmentK.f4802u = this;
                if (G0(2)) {
                    Log.v("FragmentManager", "restoreSaveState: active (" + fragmentK.f4788g + "): " + fragmentK);
                }
                d3.o(this.f5064v.k().getClassLoader());
                this.f5045c.r(d3);
                d3.t(this.f5063u);
            }
        }
        for (Fragment fragment : this.f5040P.l()) {
            if (!this.f5045c.c(fragment.f4788g)) {
                if (G0(2)) {
                    Log.v("FragmentManager", "Discarding retained Fragment " + fragment + " that was not found in the set of active Fragments " + zVar.f5085a);
                }
                this.f5040P.o(fragment);
                fragment.f4802u = this;
                D d4 = new D(this.f5056n, this.f5045c, fragment);
                d4.t(1);
                d4.m();
                fragment.f4795n = true;
                d4.m();
            }
        }
        this.f5045c.w(zVar.f5086b);
        if (zVar.f5087c != null) {
            this.f5046d = new ArrayList(zVar.f5087c.length);
            int i3 = 0;
            while (true) {
                C0290b[] c0290bArr = zVar.f5087c;
                if (i3 >= c0290bArr.length) {
                    break;
                }
                C0289a c0289aB = c0290bArr[i3].b(this);
                if (G0(2)) {
                    Log.v("FragmentManager", "restoreAllState: back stack #" + i3 + " (index " + c0289aB.f4899v + "): " + c0289aB);
                    PrintWriter printWriter = new PrintWriter(new K("FragmentManager"));
                    c0289aB.q("  ", printWriter, false);
                    printWriter.close();
                }
                this.f5046d.add(c0289aB);
                i3++;
            }
        } else {
            this.f5046d = null;
        }
        this.f5051i.set(zVar.f5088d);
        String str3 = zVar.f5089e;
        if (str3 != null) {
            Fragment fragmentE0 = e0(str3);
            this.f5067y = fragmentE0;
            L(fragmentE0);
        }
        ArrayList arrayList2 = zVar.f5090f;
        if (arrayList2 != null) {
            for (int i4 = 0; i4 < arrayList2.size(); i4++) {
                this.f5052j.put((String) arrayList2.get(i4), (C0291c) zVar.f5091g.get(i4));
            }
        }
        this.f5031G = new ArrayDeque(zVar.f5092h);
    }

    public Fragment g0(int i3) {
        return this.f5045c.g(i3);
    }

    public Fragment h0(String str) {
        return this.f5045c.h(str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX INFO: renamed from: h1, reason: merged with bridge method [inline-methods] */
    public Bundle O0() {
        C0290b[] c0290bArr;
        int size;
        Bundle bundle = new Bundle();
        l0();
        X();
        a0(true);
        this.f5033I = true;
        this.f5040P.p(true);
        ArrayList arrayListY = this.f5045c.y();
        ArrayList<C> arrayListM = this.f5045c.m();
        if (!arrayListM.isEmpty()) {
            ArrayList arrayListZ = this.f5045c.z();
            ArrayList arrayList = this.f5046d;
            if (arrayList == null || (size = arrayList.size()) <= 0) {
                c0290bArr = null;
            } else {
                c0290bArr = new C0290b[size];
                for (int i3 = 0; i3 < size; i3++) {
                    c0290bArr[i3] = new C0290b((C0289a) this.f5046d.get(i3));
                    if (G0(2)) {
                        Log.v("FragmentManager", "saveAllState: adding back stack #" + i3 + ": " + this.f5046d.get(i3));
                    }
                }
            }
            z zVar = new z();
            zVar.f5085a = arrayListY;
            zVar.f5086b = arrayListZ;
            zVar.f5087c = c0290bArr;
            zVar.f5088d = this.f5051i.get();
            Fragment fragment = this.f5067y;
            if (fragment != null) {
                zVar.f5089e = fragment.f4788g;
            }
            zVar.f5090f.addAll(this.f5052j.keySet());
            zVar.f5091g.addAll(this.f5052j.values());
            zVar.f5092h = new ArrayList(this.f5031G);
            bundle.putParcelable("state", zVar);
            for (String str : this.f5053k.keySet()) {
                bundle.putBundle("result_" + str, (Bundle) this.f5053k.get(str));
            }
            for (C c3 : arrayListM) {
                Bundle bundle2 = new Bundle();
                bundle2.putParcelable("state", c3);
                bundle.putBundle("fragment_" + c3.f4702b, bundle2);
            }
        } else if (G0(2)) {
            Log.v("FragmentManager", "saveAllState: no fragments!");
        }
        return bundle;
    }

    void i(C0289a c0289a) {
        if (this.f5046d == null) {
            this.f5046d = new ArrayList();
        }
        this.f5046d.add(c0289a);
    }

    Fragment i0(String str) {
        return this.f5045c.i(str);
    }

    void i1() {
        synchronized (this.f5043a) {
            try {
                if (this.f5043a.size() == 1) {
                    this.f5064v.o().removeCallbacks(this.f5042R);
                    this.f5064v.o().post(this.f5042R);
                    q1();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    D j(Fragment fragment) {
        String str = fragment.f4772R;
        if (str != null) {
            B.c.f(fragment, str);
        }
        if (G0(2)) {
            Log.v("FragmentManager", "add: " + fragment);
        }
        D dV = v(fragment);
        fragment.f4802u = this;
        this.f5045c.r(dV);
        if (!fragment.f4757C) {
            this.f5045c.a(fragment);
            fragment.f4795n = false;
            if (fragment.f4764J == null) {
                fragment.f4769O = false;
            }
            if (H0(fragment)) {
                this.f5032H = true;
            }
        }
        return dV;
    }

    void j1(Fragment fragment, boolean z3) {
        ViewGroup viewGroupQ0 = q0(fragment);
        if (viewGroupQ0 == null || !(viewGroupQ0 instanceof C0301m)) {
            return;
        }
        ((C0301m) viewGroupQ0).setDrawDisappearingViewsLast(!z3);
    }

    public void k(B b3) {
        this.f5057o.add(b3);
    }

    void k1(Fragment fragment, f.b bVar) {
        if (fragment.equals(e0(fragment.f4788g)) && (fragment.f4803v == null || fragment.f4802u == this)) {
            fragment.f4773S = bVar;
            return;
        }
        throw new IllegalArgumentException("Fragment " + fragment + " is not an active fragment of FragmentManager " + this);
    }

    int l() {
        return this.f5051i.getAndIncrement();
    }

    void l1(Fragment fragment) {
        if (fragment == null || (fragment.equals(e0(fragment.f4788g)) && (fragment.f4803v == null || fragment.f4802u == this))) {
            Fragment fragment2 = this.f5067y;
            this.f5067y = fragment;
            L(fragment2);
            L(this.f5067y);
            return;
        }
        throw new IllegalArgumentException("Fragment " + fragment + " is not an active fragment of FragmentManager " + this);
    }

    /* JADX WARN: Multi-variable type inference failed */
    void m(p pVar, AbstractC0300l abstractC0300l, Fragment fragment) {
        String str;
        if (this.f5064v != null) {
            throw new IllegalStateException("Already attached");
        }
        this.f5064v = pVar;
        this.f5065w = abstractC0300l;
        this.f5066x = fragment;
        if (fragment != null) {
            k(new g(fragment));
        } else if (pVar instanceof B) {
            k((B) pVar);
        }
        if (this.f5066x != null) {
            q1();
        }
        if (pVar instanceof androidx.activity.o) {
            androidx.activity.o oVar = (androidx.activity.o) pVar;
            OnBackPressedDispatcher onBackPressedDispatcherA = oVar.a();
            this.f5049g = onBackPressedDispatcherA;
            androidx.lifecycle.k kVar = oVar;
            if (fragment != null) {
                kVar = fragment;
            }
            onBackPressedDispatcherA.b(kVar, this.f5050h);
        }
        if (fragment != null) {
            this.f5040P = fragment.f4802u.o0(fragment);
        } else if (pVar instanceof androidx.lifecycle.C) {
            this.f5040P = A.k(((androidx.lifecycle.C) pVar).r());
        } else {
            this.f5040P = new A(false);
        }
        this.f5040P.p(N0());
        this.f5045c.A(this.f5040P);
        Object obj = this.f5064v;
        if ((obj instanceof F.d) && fragment == null) {
            androidx.savedstate.a aVarB = ((F.d) obj).b();
            aVarB.h("android:support:fragments", new a.c() { // from class: androidx.fragment.app.w
                @Override // androidx.savedstate.a.c
                public final Bundle a() {
                    return this.f5023a.O0();
                }
            });
            Bundle bundleB = aVarB.b("android:support:fragments");
            if (bundleB != null) {
                f1(bundleB);
            }
        }
        Object obj2 = this.f5064v;
        if (obj2 instanceof androidx.activity.result.f) {
            androidx.activity.result.e eVarN = ((androidx.activity.result.f) obj2).n();
            if (fragment != null) {
                str = fragment.f4788g + ":";
            } else {
                str = "";
            }
            String str2 = "FragmentManager:" + str;
            this.f5028D = eVarN.g(str2 + "StartActivityForResult", new C0310c(), new h());
            this.f5029E = eVarN.g(str2 + "StartIntentSenderForResult", new j(), new i());
            this.f5030F = eVarN.g(str2 + "RequestPermissions", new C0309b(), new a());
        }
        Object obj3 = this.f5064v;
        if (obj3 instanceof androidx.core.content.c) {
            ((androidx.core.content.c) obj3).q(this.f5058p);
        }
        Object obj4 = this.f5064v;
        if (obj4 instanceof androidx.core.content.d) {
            ((androidx.core.content.d) obj4).w(this.f5059q);
        }
        Object obj5 = this.f5064v;
        if (obj5 instanceof androidx.core.app.j) {
            ((androidx.core.app.j) obj5).p(this.f5060r);
        }
        Object obj6 = this.f5064v;
        if (obj6 instanceof androidx.core.app.k) {
            ((androidx.core.app.k) obj6).l(this.f5061s);
        }
        Object obj7 = this.f5064v;
        if ((obj7 instanceof InterfaceC0284v) && fragment == null) {
            ((InterfaceC0284v) obj7).m(this.f5062t);
        }
    }

    void n(Fragment fragment) {
        if (G0(2)) {
            Log.v("FragmentManager", "attach: " + fragment);
        }
        if (fragment.f4757C) {
            fragment.f4757C = false;
            if (fragment.f4794m) {
                return;
            }
            this.f5045c.a(fragment);
            if (G0(2)) {
                Log.v("FragmentManager", "add from attach: " + fragment);
            }
            if (H0(fragment)) {
                this.f5032H = true;
            }
        }
    }

    public int n0() {
        ArrayList arrayList = this.f5046d;
        if (arrayList != null) {
            return arrayList.size();
        }
        return 0;
    }

    void n1(Fragment fragment) {
        if (G0(2)) {
            Log.v("FragmentManager", "show: " + fragment);
        }
        if (fragment.f4756B) {
            fragment.f4756B = false;
            fragment.f4769O = !fragment.f4769O;
        }
    }

    public F o() {
        return new C0289a(this);
    }

    boolean p() {
        boolean zH0 = false;
        for (Fragment fragment : this.f5045c.l()) {
            if (fragment != null) {
                zH0 = H0(fragment);
            }
            if (zH0) {
                return true;
            }
        }
        return false;
    }

    AbstractC0300l p0() {
        return this.f5065w;
    }

    public o r0() {
        o oVar = this.f5068z;
        if (oVar != null) {
            return oVar;
        }
        Fragment fragment = this.f5066x;
        return fragment != null ? fragment.f4802u.r0() : this.f5025A;
    }

    public List s0() {
        return this.f5045c.o();
    }

    public p t0() {
        return this.f5064v;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append("FragmentManager{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append(" in ");
        Fragment fragment = this.f5066x;
        if (fragment != null) {
            sb.append(fragment.getClass().getSimpleName());
            sb.append("{");
            sb.append(Integer.toHexString(System.identityHashCode(this.f5066x)));
            sb.append("}");
        } else {
            p pVar = this.f5064v;
            if (pVar != null) {
                sb.append(pVar.getClass().getSimpleName());
                sb.append("{");
                sb.append(Integer.toHexString(System.identityHashCode(this.f5064v)));
                sb.append("}");
            } else {
                sb.append("null");
            }
        }
        sb.append("}}");
        return sb.toString();
    }

    LayoutInflater.Factory2 u0() {
        return this.f5048f;
    }

    D v(Fragment fragment) {
        D dN = this.f5045c.n(fragment.f4788g);
        if (dN != null) {
            return dN;
        }
        D d3 = new D(this.f5056n, this.f5045c, fragment);
        d3.o(this.f5064v.k().getClassLoader());
        d3.t(this.f5063u);
        return d3;
    }

    r v0() {
        return this.f5056n;
    }

    void w(Fragment fragment) {
        if (G0(2)) {
            Log.v("FragmentManager", "detach: " + fragment);
        }
        if (fragment.f4757C) {
            return;
        }
        fragment.f4757C = true;
        if (fragment.f4794m) {
            if (G0(2)) {
                Log.v("FragmentManager", "remove from detach: " + fragment);
            }
            this.f5045c.u(fragment);
            if (H0(fragment)) {
                this.f5032H = true;
            }
            m1(fragment);
        }
    }

    Fragment w0() {
        return this.f5066x;
    }

    void x() {
        this.f5033I = false;
        this.f5034J = false;
        this.f5040P.p(false);
        S(4);
    }

    public Fragment x0() {
        return this.f5067y;
    }

    void y() {
        this.f5033I = false;
        this.f5034J = false;
        this.f5040P.p(false);
        S(0);
    }

    M y0() {
        M m3 = this.f5026B;
        if (m3 != null) {
            return m3;
        }
        Fragment fragment = this.f5066x;
        return fragment != null ? fragment.f4802u.y0() : this.f5027C;
    }

    void z(Configuration configuration, boolean z3) {
        if (z3 && (this.f5064v instanceof androidx.core.content.c)) {
            p1(new IllegalStateException("Do not call dispatchConfigurationChanged() on host. Host implements OnConfigurationChangedProvider and automatically dispatches configuration changes to fragments."));
        }
        for (Fragment fragment : this.f5045c.o()) {
            if (fragment != null) {
                fragment.M0(configuration);
                if (z3) {
                    fragment.f4804w.z(configuration, true);
                }
            }
        }
    }

    public c.C0001c z0() {
        return this.f5041Q;
    }
}
