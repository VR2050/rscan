package androidx.fragment.app;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.content.Context;
import android.graphics.Rect;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import androidx.core.os.b;
import androidx.core.view.AbstractC0253a0;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC0299k;
import androidx.fragment.app.L;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import l.C0606a;

/* JADX INFO: renamed from: androidx.fragment.app.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0292d extends L {

    /* JADX INFO: renamed from: androidx.fragment.app.d$a */
    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f4917a;

        static {
            int[] iArr = new int[L.e.c.values().length];
            f4917a = iArr;
            try {
                iArr[L.e.c.GONE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f4917a[L.e.c.INVISIBLE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f4917a[L.e.c.REMOVED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f4917a[L.e.c.VISIBLE.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$b */
    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ List f4918b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ L.e f4919c;

        b(List list, L.e eVar) {
            this.f4918b = list;
            this.f4919c = eVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.f4918b.contains(this.f4919c)) {
                this.f4918b.remove(this.f4919c);
                C0292d.this.s(this.f4919c);
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$c */
    class c extends AnimatorListenerAdapter {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ ViewGroup f4921a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ View f4922b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ boolean f4923c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ L.e f4924d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ k f4925e;

        c(ViewGroup viewGroup, View view, boolean z3, L.e eVar, k kVar) {
            this.f4921a = viewGroup;
            this.f4922b = view;
            this.f4923c = z3;
            this.f4924d = eVar;
            this.f4925e = kVar;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            this.f4921a.endViewTransition(this.f4922b);
            if (this.f4923c) {
                this.f4924d.e().a(this.f4922b);
            }
            this.f4925e.a();
            if (x.G0(2)) {
                Log.v("FragmentManager", "Animator from operation " + this.f4924d + " has ended.");
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$d, reason: collision with other inner class name */
    class C0071d implements b.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Animator f4927a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ L.e f4928b;

        C0071d(Animator animator, L.e eVar) {
            this.f4927a = animator;
            this.f4928b = eVar;
        }

        @Override // androidx.core.os.b.a
        public void a() {
            this.f4927a.end();
            if (x.G0(2)) {
                Log.v("FragmentManager", "Animator from operation " + this.f4928b + " has been canceled.");
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$e */
    class e implements Animation.AnimationListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ L.e f4930a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ViewGroup f4931b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ View f4932c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ k f4933d;

        /* JADX INFO: renamed from: androidx.fragment.app.d$e$a */
        class a implements Runnable {
            a() {
            }

            @Override // java.lang.Runnable
            public void run() {
                e eVar = e.this;
                eVar.f4931b.endViewTransition(eVar.f4932c);
                e.this.f4933d.a();
            }
        }

        e(L.e eVar, ViewGroup viewGroup, View view, k kVar) {
            this.f4930a = eVar;
            this.f4931b = viewGroup;
            this.f4932c = view;
            this.f4933d = kVar;
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            this.f4931b.post(new a());
            if (x.G0(2)) {
                Log.v("FragmentManager", "Animation from operation " + this.f4930a + " has ended.");
            }
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
            if (x.G0(2)) {
                Log.v("FragmentManager", "Animation from operation " + this.f4930a + " has reached onAnimationStart.");
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$f */
    class f implements b.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ View f4936a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ViewGroup f4937b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ k f4938c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ L.e f4939d;

        f(View view, ViewGroup viewGroup, k kVar, L.e eVar) {
            this.f4936a = view;
            this.f4937b = viewGroup;
            this.f4938c = kVar;
            this.f4939d = eVar;
        }

        @Override // androidx.core.os.b.a
        public void a() {
            this.f4936a.clearAnimation();
            this.f4937b.endViewTransition(this.f4936a);
            this.f4938c.a();
            if (x.G0(2)) {
                Log.v("FragmentManager", "Animation from operation " + this.f4939d + " has been cancelled.");
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$g */
    class g implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ L.e f4941b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ L.e f4942c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f4943d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ C0606a f4944e;

        g(L.e eVar, L.e eVar2, boolean z3, C0606a c0606a) {
            this.f4941b = eVar;
            this.f4942c = eVar2;
            this.f4943d = z3;
            this.f4944e = c0606a;
        }

        @Override // java.lang.Runnable
        public void run() {
            G.a(this.f4941b.f(), this.f4942c.f(), this.f4943d, this.f4944e, false);
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$h */
    class h implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ I f4946b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ View f4947c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Rect f4948d;

        h(I i3, View view, Rect rect) {
            this.f4946b = i3;
            this.f4947c = view;
            this.f4948d = rect;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f4946b.h(this.f4947c, this.f4948d);
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$i */
    class i implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ArrayList f4950b;

        i(ArrayList arrayList) {
            this.f4950b = arrayList;
        }

        @Override // java.lang.Runnable
        public void run() {
            G.d(this.f4950b, 4);
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$j */
    class j implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ m f4952b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ L.e f4953c;

        j(m mVar, L.e eVar) {
            this.f4952b = mVar;
            this.f4953c = eVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f4952b.a();
            if (x.G0(2)) {
                Log.v("FragmentManager", "Transition for operation " + this.f4953c + "has completed");
            }
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$k */
    private static class k extends l {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f4955c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f4956d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private AbstractC0299k.a f4957e;

        k(L.e eVar, androidx.core.os.b bVar, boolean z3) {
            super(eVar, bVar);
            this.f4956d = false;
            this.f4955c = z3;
        }

        AbstractC0299k.a e(Context context) {
            if (this.f4956d) {
                return this.f4957e;
            }
            AbstractC0299k.a aVarB = AbstractC0299k.b(context, b().f(), b().e() == L.e.c.VISIBLE, this.f4955c);
            this.f4957e = aVarB;
            this.f4956d = true;
            return aVarB;
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$l */
    private static class l {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final L.e f4958a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final androidx.core.os.b f4959b;

        l(L.e eVar, androidx.core.os.b bVar) {
            this.f4958a = eVar;
            this.f4959b = bVar;
        }

        void a() {
            this.f4958a.d(this.f4959b);
        }

        L.e b() {
            return this.f4958a;
        }

        androidx.core.os.b c() {
            return this.f4959b;
        }

        boolean d() {
            L.e.c cVar;
            L.e.c cVarC = L.e.c.c(this.f4958a.f().f4764J);
            L.e.c cVarE = this.f4958a.e();
            return cVarC == cVarE || !(cVarC == (cVar = L.e.c.VISIBLE) || cVarE == cVar);
        }
    }

    /* JADX INFO: renamed from: androidx.fragment.app.d$m */
    private static class m extends l {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Object f4960c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final boolean f4961d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final Object f4962e;

        m(L.e eVar, androidx.core.os.b bVar, boolean z3, boolean z4) {
            super(eVar, bVar);
            if (eVar.e() == L.e.c.VISIBLE) {
                this.f4960c = z3 ? eVar.f().I() : eVar.f().q();
                this.f4961d = z3 ? eVar.f().j() : eVar.f().i();
            } else {
                this.f4960c = z3 ? eVar.f().K() : eVar.f().v();
                this.f4961d = true;
            }
            if (!z4) {
                this.f4962e = null;
            } else if (z3) {
                this.f4962e = eVar.f().M();
            } else {
                this.f4962e = eVar.f().L();
            }
        }

        private I f(Object obj) {
            if (obj == null) {
                return null;
            }
            I i3 = G.f4838a;
            if (i3 != null && i3.e(obj)) {
                return i3;
            }
            I i4 = G.f4839b;
            if (i4 != null && i4.e(obj)) {
                return i4;
            }
            throw new IllegalArgumentException("Transition " + obj + " for fragment " + b().f() + " is not a valid framework Transition or AndroidX Transition");
        }

        I e() {
            I iF = f(this.f4960c);
            I iF2 = f(this.f4962e);
            if (iF == null || iF2 == null || iF == iF2) {
                return iF != null ? iF : iF2;
            }
            throw new IllegalArgumentException("Mixing framework transitions and AndroidX transitions is not allowed. Fragment " + b().f() + " returned Transition " + this.f4960c + " which uses a different Transition  type than its shared element transition " + this.f4962e);
        }

        public Object g() {
            return this.f4962e;
        }

        Object h() {
            return this.f4960c;
        }

        public boolean i() {
            return this.f4962e != null;
        }

        boolean j() {
            return this.f4961d;
        }
    }

    C0292d(ViewGroup viewGroup) {
        super(viewGroup);
    }

    private void w(List list, List list2, boolean z3, Map map) {
        int i3;
        boolean z4;
        Context context;
        View view;
        int i4;
        L.e eVar;
        ViewGroup viewGroupM = m();
        Context context2 = viewGroupM.getContext();
        ArrayList<k> arrayList = new ArrayList();
        Iterator it = list.iterator();
        boolean z5 = false;
        while (true) {
            i3 = 2;
            if (!it.hasNext()) {
                break;
            }
            k kVar = (k) it.next();
            if (kVar.d()) {
                kVar.a();
            } else {
                AbstractC0299k.a aVarE = kVar.e(context2);
                if (aVarE == null) {
                    kVar.a();
                } else {
                    Animator animator = aVarE.f4996b;
                    if (animator == null) {
                        arrayList.add(kVar);
                    } else {
                        L.e eVarB = kVar.b();
                        Fragment fragmentF = eVarB.f();
                        if (Boolean.TRUE.equals(map.get(eVarB))) {
                            if (x.G0(2)) {
                                Log.v("FragmentManager", "Ignoring Animator set on " + fragmentF + " as this Fragment was involved in a Transition.");
                            }
                            kVar.a();
                        } else {
                            boolean z6 = eVarB.e() == L.e.c.GONE;
                            if (z6) {
                                list2.remove(eVarB);
                            }
                            View view2 = fragmentF.f4764J;
                            viewGroupM.startViewTransition(view2);
                            animator.addListener(new c(viewGroupM, view2, z6, eVarB, kVar));
                            animator.setTarget(view2);
                            animator.start();
                            if (x.G0(2)) {
                                StringBuilder sb = new StringBuilder();
                                sb.append("Animator from operation ");
                                eVar = eVarB;
                                sb.append(eVar);
                                sb.append(" has started.");
                                Log.v("FragmentManager", sb.toString());
                            } else {
                                eVar = eVarB;
                            }
                            kVar.c().b(new C0071d(animator, eVar));
                            z5 = true;
                        }
                    }
                }
            }
        }
        for (k kVar2 : arrayList) {
            L.e eVarB2 = kVar2.b();
            Fragment fragmentF2 = eVarB2.f();
            if (z3) {
                if (x.G0(i3)) {
                    Log.v("FragmentManager", "Ignoring Animation set on " + fragmentF2 + " as Animations cannot run alongside Transitions.");
                }
                kVar2.a();
            } else if (z5) {
                if (x.G0(i3)) {
                    Log.v("FragmentManager", "Ignoring Animation set on " + fragmentF2 + " as Animations cannot run alongside Animators.");
                }
                kVar2.a();
            } else {
                View view3 = fragmentF2.f4764J;
                Animation animation = (Animation) q.g.f(((AbstractC0299k.a) q.g.f(kVar2.e(context2))).f4995a);
                if (eVarB2.e() != L.e.c.REMOVED) {
                    view3.startAnimation(animation);
                    kVar2.a();
                    z4 = z5;
                    context = context2;
                    i4 = i3;
                    view = view3;
                } else {
                    viewGroupM.startViewTransition(view3);
                    AbstractC0299k.b bVar = new AbstractC0299k.b(animation, viewGroupM, view3);
                    z4 = z5;
                    context = context2;
                    view = view3;
                    bVar.setAnimationListener(new e(eVarB2, viewGroupM, view3, kVar2));
                    view.startAnimation(bVar);
                    i4 = 2;
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "Animation from operation " + eVarB2 + " has started.");
                    }
                }
                kVar2.c().b(new f(view, viewGroupM, kVar2, eVarB2));
                i3 = i4;
                z5 = z4;
                context2 = context;
            }
        }
    }

    private Map x(List list, List list2, boolean z3, L.e eVar, L.e eVar2) {
        String str;
        String str2;
        String str3;
        View view;
        Object obj;
        ArrayList arrayList;
        Object obj2;
        ArrayList arrayList2;
        HashMap map;
        View view2;
        Object objK;
        C0606a c0606a;
        ArrayList arrayList3;
        L.e eVar3;
        ArrayList arrayList4;
        Rect rect;
        I i3;
        HashMap map2;
        L.e eVar4;
        View view3;
        View view4;
        View view5;
        boolean z4 = z3;
        L.e eVar5 = eVar;
        L.e eVar6 = eVar2;
        HashMap map3 = new HashMap();
        Iterator it = list.iterator();
        I i4 = null;
        while (it.hasNext()) {
            m mVar = (m) it.next();
            if (!mVar.d()) {
                I iE = mVar.e();
                if (i4 == null) {
                    i4 = iE;
                } else if (iE != null && i4 != iE) {
                    throw new IllegalArgumentException("Mixing framework transitions and AndroidX transitions is not allowed. Fragment " + mVar.b().f() + " returned Transition " + mVar.h() + " which uses a different Transition  type than other Fragments.");
                }
            }
        }
        if (i4 == null) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                m mVar2 = (m) it2.next();
                map3.put(mVar2.b(), Boolean.FALSE);
                mVar2.a();
            }
            return map3;
        }
        View view6 = new View(m().getContext());
        Rect rect2 = new Rect();
        ArrayList arrayList5 = new ArrayList();
        ArrayList arrayList6 = new ArrayList();
        C0606a c0606a2 = new C0606a();
        Iterator it3 = list.iterator();
        Object obj3 = null;
        View view7 = null;
        boolean z5 = false;
        while (true) {
            str = "FragmentManager";
            if (!it3.hasNext()) {
                break;
            }
            m mVar3 = (m) it3.next();
            if (!mVar3.i() || eVar5 == null || eVar6 == null) {
                c0606a = c0606a2;
                arrayList3 = arrayList6;
                eVar3 = eVar5;
                arrayList4 = arrayList5;
                rect = rect2;
                i3 = i4;
                map2 = map3;
                View view8 = view6;
                eVar4 = eVar6;
                view3 = view8;
                view7 = view7;
            } else {
                Object objU = i4.u(i4.f(mVar3.g()));
                ArrayList arrayListN = eVar2.f().N();
                ArrayList arrayListN2 = eVar.f().N();
                ArrayList arrayListO = eVar.f().O();
                View view9 = view7;
                int i5 = 0;
                while (i5 < arrayListO.size()) {
                    int iIndexOf = arrayListN.indexOf(arrayListO.get(i5));
                    ArrayList arrayList7 = arrayListO;
                    if (iIndexOf != -1) {
                        arrayListN.set(iIndexOf, (String) arrayListN2.get(i5));
                    }
                    i5++;
                    arrayListO = arrayList7;
                }
                ArrayList arrayListO2 = eVar2.f().O();
                if (z4) {
                    eVar.f().t();
                    eVar2.f().w();
                } else {
                    eVar.f().w();
                    eVar2.f().t();
                }
                int i6 = 0;
                for (int size = arrayListN.size(); i6 < size; size = size) {
                    c0606a2.put((String) arrayListN.get(i6), (String) arrayListO2.get(i6));
                    i6++;
                }
                if (x.G0(2)) {
                    Log.v("FragmentManager", ">>> entering view names <<<");
                    for (Iterator it4 = arrayListO2.iterator(); it4.hasNext(); it4 = it4) {
                        Log.v("FragmentManager", "Name: " + ((String) it4.next()));
                    }
                    Log.v("FragmentManager", ">>> exiting view names <<<");
                    for (Iterator it5 = arrayListN.iterator(); it5.hasNext(); it5 = it5) {
                        Log.v("FragmentManager", "Name: " + ((String) it5.next()));
                    }
                }
                C0606a c0606a3 = new C0606a();
                u(c0606a3, eVar.f().f4764J);
                c0606a3.n(arrayListN);
                c0606a2.n(c0606a3.keySet());
                C0606a c0606a4 = new C0606a();
                u(c0606a4, eVar2.f().f4764J);
                c0606a4.n(arrayListO2);
                c0606a4.n(c0606a2.values());
                G.c(c0606a2, c0606a4);
                v(c0606a3, c0606a2.keySet());
                v(c0606a4, c0606a2.values());
                if (c0606a2.isEmpty()) {
                    arrayList5.clear();
                    arrayList6.clear();
                    c0606a = c0606a2;
                    arrayList3 = arrayList6;
                    eVar3 = eVar5;
                    arrayList4 = arrayList5;
                    rect = rect2;
                    view3 = view6;
                    i3 = i4;
                    view7 = view9;
                    obj3 = null;
                    eVar4 = eVar2;
                    map2 = map3;
                } else {
                    G.a(eVar2.f(), eVar.f(), z4, c0606a3, true);
                    HashMap map4 = map3;
                    View view10 = view6;
                    c0606a = c0606a2;
                    ArrayList arrayList8 = arrayList6;
                    androidx.core.view.H.a(m(), new g(eVar2, eVar, z3, c0606a4));
                    arrayList5.addAll(c0606a3.values());
                    if (arrayListN.isEmpty()) {
                        view7 = view9;
                    } else {
                        view7 = (View) c0606a3.get((String) arrayListN.get(0));
                        i4.p(objU, view7);
                    }
                    arrayList3 = arrayList8;
                    arrayList3.addAll(c0606a4.values());
                    if (arrayListO2.isEmpty() || (view5 = (View) c0606a4.get((String) arrayListO2.get(0))) == null) {
                        view4 = view10;
                    } else {
                        androidx.core.view.H.a(m(), new h(i4, view5, rect2));
                        view4 = view10;
                        z5 = true;
                    }
                    i4.s(objU, view4, arrayList5);
                    arrayList4 = arrayList5;
                    rect = rect2;
                    view3 = view4;
                    i3 = i4;
                    i4.n(objU, null, null, null, null, objU, arrayList3);
                    Boolean bool = Boolean.TRUE;
                    eVar3 = eVar;
                    map2 = map4;
                    map2.put(eVar3, bool);
                    eVar4 = eVar2;
                    map2.put(eVar4, bool);
                    obj3 = objU;
                }
            }
            eVar5 = eVar3;
            arrayList5 = arrayList4;
            rect2 = rect;
            map3 = map2;
            c0606a2 = c0606a;
            z4 = z3;
            arrayList6 = arrayList3;
            i4 = i3;
            L.e eVar7 = eVar4;
            view6 = view3;
            eVar6 = eVar7;
        }
        View view11 = view7;
        C0606a c0606a5 = c0606a2;
        ArrayList arrayList9 = arrayList6;
        L.e eVar8 = eVar5;
        ArrayList arrayList10 = arrayList5;
        Rect rect3 = rect2;
        I i7 = i4;
        HashMap map5 = map3;
        View view12 = view6;
        L.e eVar9 = eVar6;
        View view13 = view12;
        ArrayList arrayList11 = new ArrayList();
        Iterator it6 = list.iterator();
        Object obj4 = null;
        Object objK2 = null;
        while (it6.hasNext()) {
            m mVar4 = (m) it6.next();
            if (mVar4.d()) {
                map5.put(mVar4.b(), Boolean.FALSE);
                mVar4.a();
            } else {
                Object objF = i7.f(mVar4.h());
                L.e eVarB = mVar4.b();
                boolean z6 = obj3 != null && (eVarB == eVar8 || eVarB == eVar9);
                if (objF == null) {
                    if (!z6) {
                        map5.put(eVarB, Boolean.FALSE);
                        mVar4.a();
                    }
                    arrayList2 = arrayList9;
                    str3 = str;
                    arrayList = arrayList10;
                    view = view13;
                    objK = obj4;
                    map = map5;
                    view2 = view11;
                } else {
                    str3 = str;
                    ArrayList arrayList12 = new ArrayList();
                    Object obj5 = obj4;
                    t(arrayList12, eVarB.f().f4764J);
                    if (z6) {
                        if (eVarB == eVar8) {
                            arrayList12.removeAll(arrayList10);
                        } else {
                            arrayList12.removeAll(arrayList9);
                        }
                    }
                    if (arrayList12.isEmpty()) {
                        i7.a(objF, view13);
                        arrayList2 = arrayList9;
                        arrayList = arrayList10;
                        view = view13;
                        obj2 = objK2;
                        map = map5;
                        obj = obj5;
                    } else {
                        i7.b(objF, arrayList12);
                        view = view13;
                        obj = obj5;
                        arrayList = arrayList10;
                        obj2 = objK2;
                        arrayList2 = arrayList9;
                        map = map5;
                        i7.n(objF, objF, arrayList12, null, null, null, null);
                        if (eVarB.e() == L.e.c.GONE) {
                            list2.remove(eVarB);
                            ArrayList arrayList13 = new ArrayList(arrayList12);
                            arrayList13.remove(eVarB.f().f4764J);
                            i7.m(objF, eVarB.f().f4764J, arrayList13);
                            androidx.core.view.H.a(m(), new i(arrayList12));
                        }
                    }
                    if (eVarB.e() == L.e.c.VISIBLE) {
                        arrayList11.addAll(arrayList12);
                        if (z5) {
                            i7.o(objF, rect3);
                        }
                        view2 = view11;
                    } else {
                        view2 = view11;
                        i7.p(objF, view2);
                    }
                    map.put(eVarB, Boolean.TRUE);
                    if (mVar4.j()) {
                        objK2 = i7.k(obj2, objF, null);
                        objK = obj;
                    } else {
                        objK = i7.k(obj, objF, null);
                        objK2 = obj2;
                    }
                }
                eVar9 = eVar2;
                map5 = map;
                obj4 = objK;
                view11 = view2;
                str = str3;
                view13 = view;
                arrayList10 = arrayList;
                arrayList9 = arrayList2;
            }
        }
        ArrayList<View> arrayList14 = arrayList9;
        String str4 = str;
        ArrayList<View> arrayList15 = arrayList10;
        HashMap map6 = map5;
        Object objJ = i7.j(objK2, obj4, obj3);
        if (objJ == null) {
            return map6;
        }
        Iterator it7 = list.iterator();
        while (it7.hasNext()) {
            m mVar5 = (m) it7.next();
            if (!mVar5.d()) {
                Object objH = mVar5.h();
                L.e eVarB2 = mVar5.b();
                HashMap map7 = map6;
                boolean z7 = obj3 != null && (eVarB2 == eVar8 || eVarB2 == eVar2);
                if (objH == null && !z7) {
                    str2 = str4;
                } else if (V.F(m())) {
                    str2 = str4;
                    i7.q(mVar5.b().f(), objJ, mVar5.c(), new j(mVar5, eVarB2));
                } else {
                    if (x.G0(2)) {
                        str2 = str4;
                        Log.v(str2, "SpecialEffectsController: Container " + m() + " has not been laid out. Completing operation " + eVarB2);
                    } else {
                        str2 = str4;
                    }
                    mVar5.a();
                }
                map6 = map7;
                str4 = str2;
            }
        }
        HashMap map8 = map6;
        String str5 = str4;
        if (!V.F(m())) {
            return map8;
        }
        G.d(arrayList11, 4);
        ArrayList arrayListL = i7.l(arrayList14);
        if (x.G0(2)) {
            Log.v(str5, ">>>>> Beginning transition <<<<<");
            Log.v(str5, ">>>>> SharedElementFirstOutViews <<<<<");
            for (View view14 : arrayList15) {
                Log.v(str5, "View: " + view14 + " Name: " + V.A(view14));
            }
            Log.v(str5, ">>>>> SharedElementLastInViews <<<<<");
            for (View view15 : arrayList14) {
                Log.v(str5, "View: " + view15 + " Name: " + V.A(view15));
            }
        }
        i7.c(m(), objJ);
        i7.r(m(), arrayList15, arrayList14, arrayListL, c0606a5);
        G.d(arrayList11, 0);
        i7.t(obj3, arrayList15, arrayList14);
        return map8;
    }

    private void y(List list) {
        Fragment fragmentF = ((L.e) list.get(list.size() - 1)).f();
        Iterator it = list.iterator();
        while (it.hasNext()) {
            L.e eVar = (L.e) it.next();
            eVar.f().f4767M.f4817c = fragmentF.f4767M.f4817c;
            eVar.f().f4767M.f4818d = fragmentF.f4767M.f4818d;
            eVar.f().f4767M.f4819e = fragmentF.f4767M.f4819e;
            eVar.f().f4767M.f4820f = fragmentF.f4767M.f4820f;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00a8  */
    @Override // androidx.fragment.app.L
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    void f(java.util.List r14, boolean r15) {
        /*
            Method dump skipped, instruction units count: 263
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.C0292d.f(java.util.List, boolean):void");
    }

    void s(L.e eVar) {
        eVar.e().a(eVar.f().f4764J);
    }

    void t(ArrayList arrayList, View view) {
        if (!(view instanceof ViewGroup)) {
            if (arrayList.contains(view)) {
                return;
            }
            arrayList.add(view);
            return;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        if (AbstractC0253a0.a(viewGroup)) {
            if (arrayList.contains(view)) {
                return;
            }
            arrayList.add(viewGroup);
            return;
        }
        int childCount = viewGroup.getChildCount();
        for (int i3 = 0; i3 < childCount; i3++) {
            View childAt = viewGroup.getChildAt(i3);
            if (childAt.getVisibility() == 0) {
                t(arrayList, childAt);
            }
        }
    }

    void u(Map map, View view) {
        String strA = V.A(view);
        if (strA != null) {
            map.put(strA, view);
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            for (int i3 = 0; i3 < childCount; i3++) {
                View childAt = viewGroup.getChildAt(i3);
                if (childAt.getVisibility() == 0) {
                    u(map, childAt);
                }
            }
        }
    }

    void v(C0606a c0606a, Collection collection) {
        Iterator it = c0606a.entrySet().iterator();
        while (it.hasNext()) {
            if (!collection.contains(V.A((View) ((Map.Entry) it.next()).getValue()))) {
                it.remove();
            }
        }
    }
}
