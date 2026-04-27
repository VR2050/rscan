package com.facebook.react.uimanager;

import O1.n;
import O1.o;
import android.graphics.Rect;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import com.facebook.react.uimanager.C0;
import com.facebook.react.uimanager.events.EventDispatcher;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class Q {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final int[] f7486j = {0, 0};

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Map f7487a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Map f7488b;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final ViewGroup f7495i;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Set f7490d = new HashSet();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f7491e = -1;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f7492f = -1;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f7493g = 0;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f7494h = 0;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Map f7489c = new HashMap();

    public Q(ViewGroup viewGroup) {
        this.f7495i = viewGroup;
    }

    private MotionEvent a(View view, MotionEvent motionEvent) {
        MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
        this.f7495i.getLocationOnScreen(new int[2]);
        motionEventObtain.setLocation(motionEvent.getRawX() - r0[0], motionEvent.getRawY() - r0[1]);
        return motionEventObtain;
    }

    private n.b b(int i3, MotionEvent motionEvent) {
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        HashMap map3 = new HashMap();
        HashMap map4 = new HashMap();
        for (int i4 = 0; i4 < motionEvent.getPointerCount(); i4++) {
            float[] fArr = new float[2];
            float[] fArr2 = {motionEvent.getX(i4), motionEvent.getY(i4)};
            List listB = C0.b(fArr2[0], fArr2[1], this.f7495i, fArr);
            int pointerId = motionEvent.getPointerId(i4);
            map.put(Integer.valueOf(pointerId), fArr);
            map2.put(Integer.valueOf(pointerId), listB);
            map3.put(Integer.valueOf(pointerId), fArr2);
            map4.put(Integer.valueOf(pointerId), e(fArr2));
        }
        return new n.b(this.f7492f, i3, this.f7494h, H0.f(this.f7495i), map, map2, map3, map4, this.f7490d);
    }

    private void c(View view, n.b bVar, MotionEvent motionEvent, EventDispatcher eventDispatcher) {
        Z0.a.b(this.f7491e == -1, "Expected to not have already sent a cancel for this gesture");
        List list = (List) bVar.d().get(Integer.valueOf(bVar.b()));
        if (list.isEmpty() || view == null) {
            return;
        }
        if (m(list, o.a.f2105b, o.a.f2106c)) {
            int iB = ((C0.b) list.get(0)).b();
            int[] iArrH = h(view);
            ((EventDispatcher) Z0.a.c(eventDispatcher)).g(O1.n.C("topPointerCancel", iB, n(bVar, iArrH[0], iArrH[1]), motionEvent));
        }
        l();
        this.f7492f = -1;
    }

    private static void d(String str, n.b bVar, MotionEvent motionEvent, List list, EventDispatcher eventDispatcher) {
        Iterator it = list.iterator();
        while (it.hasNext()) {
            eventDispatcher.g(O1.n.C(str, ((C0.b) it.next()).b(), bVar, motionEvent));
        }
    }

    private float[] e(float[] fArr) {
        this.f7495i.getLocationOnScreen(f7486j);
        return new float[]{fArr[0] + r1[0], fArr[1] + r1[1]};
    }

    private static List f(List list, o.a aVar, o.a aVar2, boolean z3) {
        ArrayList arrayList = new ArrayList(list);
        if (z3) {
            return arrayList;
        }
        boolean z4 = false;
        for (int size = list.size() - 1; size >= 0; size--) {
            View viewA = ((C0.b) list.get(size)).a();
            if (!z4 && !O1.o.h(viewA, aVar2) && !O1.o.h(viewA, aVar)) {
                arrayList.remove(size);
            } else if (!z4 && O1.o.h(viewA, aVar2)) {
                z4 = true;
            }
        }
        return arrayList;
    }

    private static List g(List list, List list2) {
        if (list.isEmpty()) {
            return new ArrayList();
        }
        if (list2.isEmpty()) {
            return new ArrayList();
        }
        HashSet hashSet = new HashSet(list);
        ArrayList arrayList = new ArrayList();
        Iterator it = list2.iterator();
        while (it.hasNext()) {
            C0.b bVar = (C0.b) it.next();
            if (hashSet.contains(bVar)) {
                arrayList.add(bVar);
            }
        }
        return arrayList;
    }

    private int[] h(View view) {
        Rect rect = new Rect(0, 0, 1, 1);
        this.f7495i.offsetDescendantRectToMyCoords(view, rect);
        return new int[]{rect.top, rect.left};
    }

    private short i() {
        return (short) (65535 & this.f7493g);
    }

    private void j(int i3, n.b bVar, MotionEvent motionEvent, EventDispatcher eventDispatcher) {
        int iB = bVar.b();
        List arrayList = i3 != -1 ? (List) bVar.d().get(Integer.valueOf(iB)) : new ArrayList();
        Map map = this.f7487a;
        List arrayList2 = (map == null || !map.containsKey(Integer.valueOf(iB))) ? new ArrayList() : (List) this.f7487a.get(Integer.valueOf(iB));
        int i4 = 0;
        boolean z3 = false;
        boolean z4 = false;
        while (i4 < Math.min(arrayList.size(), arrayList2.size()) && ((C0.b) arrayList.get((arrayList.size() - 1) - i4)).equals(arrayList2.get((arrayList2.size() - 1) - i4))) {
            View viewA = ((C0.b) arrayList.get((arrayList.size() - 1) - i4)).a();
            if (!z3 && O1.o.h(viewA, o.a.f2112i)) {
                z3 = true;
            }
            if (!z4 && O1.o.h(viewA, o.a.f2114k)) {
                z4 = true;
            }
            i4++;
        }
        if (i4 < Math.max(arrayList.size(), arrayList2.size())) {
            l();
            if (arrayList2.size() > 0) {
                int iB2 = ((C0.b) arrayList2.get(0)).b();
                if (m(arrayList2, o.a.f2119p, o.a.f2120q)) {
                    eventDispatcher.g(O1.n.C("topPointerOut", iB2, bVar, motionEvent));
                }
                List listF = f(arrayList2.subList(0, arrayList2.size() - i4), o.a.f2113j, o.a.f2114k, z4);
                if (listF.size() > 0) {
                    d("topPointerLeave", bVar, motionEvent, listF, eventDispatcher);
                }
            }
            if (m(arrayList, o.a.f2121r, o.a.f2122s)) {
                eventDispatcher.g(O1.n.C("topPointerOver", i3, bVar, motionEvent));
            }
            List listF2 = f(arrayList.subList(0, arrayList.size() - i4), o.a.f2111h, o.a.f2112i, z3);
            if (listF2.size() > 0) {
                Collections.reverse(listF2);
                d("topPointerEnter", bVar, motionEvent, listF2, eventDispatcher);
            }
        }
        HashMap map2 = new HashMap(bVar.d());
        if (i3 == -1) {
            map2.remove(Integer.valueOf(iB));
        }
        this.f7487a = map2;
    }

    private void l() {
        this.f7493g = (this.f7493g + 1) % Integer.MAX_VALUE;
    }

    private static boolean m(List list, o.a aVar, o.a aVar2) {
        Iterator it = list.iterator();
        while (it.hasNext()) {
            C0.b bVar = (C0.b) it.next();
            if (O1.o.h(bVar.a(), aVar) || O1.o.h(bVar.a(), aVar2)) {
                return true;
            }
        }
        return false;
    }

    private n.b n(n.b bVar, float f3, float f4) {
        HashMap map = new HashMap(bVar.h());
        HashMap map2 = new HashMap(bVar.c());
        HashMap map3 = new HashMap(bVar.j());
        float[] fArr = {f3, f4};
        Iterator it = map.entrySet().iterator();
        while (it.hasNext()) {
            ((Map.Entry) it.next()).setValue(fArr);
        }
        float[] fArr2 = {0.0f, 0.0f};
        Iterator it2 = map2.entrySet().iterator();
        while (it2.hasNext()) {
            ((Map.Entry) it2.next()).setValue(fArr2);
        }
        float[] fArrE = e(fArr);
        Iterator it3 = map3.entrySet().iterator();
        while (it3.hasNext()) {
            ((Map.Entry) it3.next()).setValue(fArrE);
        }
        return new n.b(bVar.i(), bVar.b(), bVar.g(), bVar.k(), map, new HashMap(bVar.d()), map2, map3, new HashSet(bVar.f()));
    }

    private void q(int i3, n.b bVar, MotionEvent motionEvent, EventDispatcher eventDispatcher) {
        List list = (List) bVar.d().get(Integer.valueOf(bVar.b()));
        l();
        if (!this.f7490d.contains(Integer.valueOf(bVar.b()))) {
            if (m(list, o.a.f2121r, o.a.f2122s)) {
                eventDispatcher.g(O1.n.C("topPointerOver", i3, bVar, motionEvent));
            }
            List listF = f(list, o.a.f2111h, o.a.f2112i, false);
            Collections.reverse(listF);
            d("topPointerEnter", bVar, motionEvent, listF, eventDispatcher);
        }
        if (m(list, o.a.f2107d, o.a.f2108e)) {
            this.f7489c.put(Integer.valueOf(bVar.b()), new ArrayList(list));
        }
        if (m(list, o.a.f2109f, o.a.f2110g)) {
            eventDispatcher.g(O1.n.C("topPointerDown", i3, bVar, motionEvent));
        }
    }

    private void r(int i3, n.b bVar, MotionEvent motionEvent, EventDispatcher eventDispatcher) {
        if (m((List) bVar.d().get(Integer.valueOf(bVar.b())), o.a.f2115l, o.a.f2116m)) {
            eventDispatcher.g(O1.n.D("topPointerMove", i3, bVar, motionEvent, i()));
        }
    }

    private void s(int i3, n.b bVar, MotionEvent motionEvent, EventDispatcher eventDispatcher) {
        int iB = bVar.b();
        List list = (List) bVar.d().get(Integer.valueOf(iB));
        if (m(list, o.a.f2117n, o.a.f2118o)) {
            eventDispatcher.g(O1.n.C("topPointerUp", i3, bVar, motionEvent));
        }
        if (!this.f7490d.contains(Integer.valueOf(iB))) {
            if (m(list, o.a.f2119p, o.a.f2120q)) {
                eventDispatcher.g(O1.n.C("topPointerOut", i3, bVar, motionEvent));
            }
            d("topPointerLeave", bVar, motionEvent, f(list, o.a.f2113j, o.a.f2114k, false), eventDispatcher);
        }
        List list2 = (List) this.f7489c.remove(Integer.valueOf(iB));
        if (list2 != null && m(list, o.a.f2107d, o.a.f2108e)) {
            List listG = g(list2, list);
            if (!listG.isEmpty()) {
                eventDispatcher.g(O1.n.C("topClick", ((C0.b) listG.get(0)).b(), bVar, motionEvent));
            }
        }
        if (motionEvent.getActionMasked() == 1) {
            this.f7492f = -1;
        }
        this.f7490d.remove(Integer.valueOf(iB));
    }

    private static boolean t(float[] fArr, float[] fArr2) {
        return Math.abs(fArr2[0] - fArr[0]) > 0.1f || Math.abs(fArr2[1] - fArr[1]) > 0.1f;
    }

    public void k(MotionEvent motionEvent, EventDispatcher eventDispatcher, boolean z3) {
        int iB;
        View viewA;
        if (this.f7491e != -1) {
            return;
        }
        int actionMasked = motionEvent.getActionMasked();
        int pointerId = motionEvent.getPointerId(motionEvent.getActionIndex());
        if (actionMasked == 0) {
            this.f7492f = motionEvent.getPointerId(0);
        } else if (actionMasked == 7) {
            this.f7490d.add(Integer.valueOf(pointerId));
        }
        n.b bVarB = b(pointerId, motionEvent);
        boolean z4 = z3 && motionEvent.getActionMasked() == 10;
        if (z4) {
            Map map = this.f7487a;
            List list = map != null ? (List) map.get(Integer.valueOf(bVarB.b())) : null;
            if (list == null || list.isEmpty()) {
                return;
            }
            C0.b bVar = (C0.b) list.get(list.size() - 1);
            iB = bVar.b();
            viewA = bVar.a();
            bVarB.d().put(Integer.valueOf(pointerId), new ArrayList());
        } else {
            List list2 = (List) bVarB.d().get(Integer.valueOf(pointerId));
            if (list2 == null || list2.isEmpty()) {
                return;
            }
            C0.b bVar2 = (C0.b) list2.get(0);
            iB = bVar2.b();
            viewA = bVar2.a();
        }
        j(iB, bVarB, motionEvent, eventDispatcher);
        switch (actionMasked) {
            case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
            case 5:
                q(iB, bVarB, motionEvent, eventDispatcher);
                break;
            case 1:
            case 6:
                l();
                s(iB, bVarB, motionEvent, eventDispatcher);
                break;
            case 2:
                r(iB, bVarB, motionEvent, eventDispatcher);
                break;
            case 3:
                c(viewA, bVarB, motionEvent, eventDispatcher);
                j(-1, bVarB, motionEvent, eventDispatcher);
                break;
            case 4:
            case 8:
            default:
                Y.a.I("ReactNative", "Motion Event was ignored. Action=" + actionMasked + " Target=" + iB);
                return;
            case 7:
                float[] fArr = (float[]) bVarB.c().get(Integer.valueOf(pointerId));
                Map map2 = this.f7488b;
                if (!t(fArr, (map2 == null || !map2.containsKey(Integer.valueOf(pointerId))) ? new float[]{0.0f, 0.0f} : (float[]) this.f7488b.get(Integer.valueOf(pointerId)))) {
                    return;
                } else {
                    r(iB, bVarB, motionEvent, eventDispatcher);
                }
                break;
            case 9:
                return;
            case 10:
                if (z4) {
                    r(iB, bVarB, motionEvent, eventDispatcher);
                }
                break;
        }
        this.f7488b = new HashMap(bVarB.c());
        this.f7494h = motionEvent.getButtonState();
        this.f7490d.retainAll(this.f7488b.keySet());
    }

    public void o() {
        this.f7491e = -1;
    }

    public void p(View view, MotionEvent motionEvent, EventDispatcher eventDispatcher) {
        if (this.f7491e != -1 || view == null) {
            return;
        }
        MotionEvent motionEventA = a(view, motionEvent);
        motionEventA.setAction(3);
        k(motionEventA, eventDispatcher, false);
        this.f7491e = view.getId();
    }
}
