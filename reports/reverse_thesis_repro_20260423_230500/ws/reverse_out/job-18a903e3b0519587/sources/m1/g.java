package m1;

import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import c2.C0353a;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactNoCrashSoftException;
import com.facebook.react.bridge.ReactSoftExceptionLogger;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.RetryableMountingLayerException;
import com.facebook.react.bridge.SoftAssertions;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.fabric.events.EventEmitterWrapper;
import com.facebook.react.fabric.mounting.mountitems.MountItem;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.B0;
import com.facebook.react.uimanager.C0469s0;
import com.facebook.react.uimanager.InterfaceC0458m0;
import com.facebook.react.uimanager.InterfaceC0462o0;
import com.facebook.react.uimanager.InterfaceC0477w0;
import com.facebook.react.uimanager.N;
import com.facebook.react.uimanager.P;
import com.facebook.react.uimanager.RootViewManager;
import com.facebook.react.uimanager.U0;
import com.facebook.react.uimanager.ViewManager;
import f1.C0527a;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import m1.d;
import q1.C0655b;

/* JADX INFO: loaded from: classes.dex */
public class g {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final String f9633o = "g";

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static final boolean f9634p;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private B0 f9637c;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private J1.a f9640f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private U0 f9641g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private RootViewManager f9642h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private d.a f9643i;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private l.h f9647m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final int f9648n;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private volatile boolean f9635a = false;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private volatile boolean f9636b = false;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private ConcurrentHashMap f9638d = new ConcurrentHashMap();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Queue f9639e = new ArrayDeque();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Set f9644j = new HashSet();

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final Set f9645k = new HashSet();

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final Set f9646l = new HashSet();

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f9649b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f9650c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f9651d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ ViewGroup f9652e;

        a(int i3, int i4, int i5, ViewGroup viewGroup) {
            this.f9649b = i3;
            this.f9650c = i4;
            this.f9651d = i5;
            this.f9652e = viewGroup;
        }

        @Override // java.lang.Runnable
        public void run() {
            Y.a.m(g.f9633o, "addViewAt: [" + this.f9649b + "] -> [" + this.f9650c + "] idx: " + this.f9651d + " AFTER");
            g.x(this.f9652e, false);
        }
    }

    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f9654b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f9655c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f9656d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ ViewGroup f9657e;

        b(int i3, int i4, int i5, ViewGroup viewGroup) {
            this.f9654b = i3;
            this.f9655c = i4;
            this.f9656d = i5;
            this.f9657e = viewGroup;
        }

        @Override // java.lang.Runnable
        public void run() {
            Y.a.m(g.f9633o, "removeViewAt: [" + this.f9654b + "] -> [" + this.f9655c + "] idx: " + this.f9656d + " AFTER");
            g.x(this.f9657e, false);
        }
    }

    class c implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ e f9659b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ d f9660c;

        c(e eVar, d dVar) {
            this.f9659b = eVar;
            this.f9660c = dVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            e eVar = this.f9659b;
            EventEmitterWrapper eventEmitterWrapper = eVar.f9673h;
            if (eventEmitterWrapper != null) {
                this.f9660c.a(eventEmitterWrapper);
                return;
            }
            if (eVar.f9674i == null) {
                eVar.f9674i = new LinkedList();
            }
            this.f9659b.f9674i.add(this.f9660c);
        }
    }

    private static class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f9662a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final boolean f9663b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f9664c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final WritableMap f9665d;

        public d(String str, WritableMap writableMap, int i3, boolean z3) {
            this.f9662a = str;
            this.f9665d = writableMap;
            this.f9664c = i3;
            this.f9663b = z3;
        }

        public void a(EventEmitterWrapper eventEmitterWrapper) {
            if (this.f9663b) {
                eventEmitterWrapper.dispatchUnique(this.f9662a, this.f9665d);
            } else {
                eventEmitterWrapper.dispatch(this.f9662a, this.f9665d, this.f9664c);
            }
        }
    }

    static {
        C0527a c0527a = C0527a.f9197a;
        f9634p = false;
    }

    public g(int i3, J1.a aVar, U0 u02, RootViewManager rootViewManager, d.a aVar2, B0 b02) {
        this.f9648n = i3;
        this.f9640f = aVar;
        this.f9641g = u02;
        this.f9642h = rootViewManager;
        this.f9643i = aVar2;
        this.f9637c = b02;
    }

    private void d(final View view) {
        if (u()) {
            return;
        }
        this.f9638d.put(Integer.valueOf(this.f9648n), new e(this.f9648n, view, this.f9642h, true));
        Runnable runnable = new Runnable() { // from class: m1.e
            @Override // java.lang.Runnable
            public final void run() {
                this.f9630b.v(view);
            }
        };
        if (UiThreadUtil.isOnUiThread()) {
            runnable.run();
        } else {
            UiThreadUtil.runOnUiThread(runnable);
        }
    }

    private void k() {
        this.f9643i.a(this.f9639e);
    }

    private e n(int i3) {
        ConcurrentHashMap concurrentHashMap = this.f9638d;
        if (concurrentHashMap == null) {
            return null;
        }
        return (e) concurrentHashMap.get(Integer.valueOf(i3));
    }

    private static N r(e eVar) {
        NativeModule nativeModule = eVar.f9669d;
        if (nativeModule != null) {
            return (N) nativeModule;
        }
        throw new IllegalStateException("Unable to find ViewManager for view: " + eVar);
    }

    private e s(int i3) {
        e eVar = (e) this.f9638d.get(Integer.valueOf(i3));
        if (eVar != null) {
            return eVar;
        }
        throw new RetryableMountingLayerException("Unable to find viewState for tag " + i3 + ". Surface stopped: " + u());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void v(View view) {
        if (u()) {
            return;
        }
        if (view.getId() == this.f9648n) {
            ReactSoftExceptionLogger.logSoftException(f9633o, new P("Race condition in addRootView detected. Trying to set an id of [" + this.f9648n + "] on the RootView, but that id has already been set. "));
        } else if (view.getId() != -1) {
            String str = f9633o;
            Y.a.o(str, "Trying to add RootTag to RootView that already has a tag: existing tag: [%d] new tag: [%d]", Integer.valueOf(view.getId()), Integer.valueOf(this.f9648n));
            ReactSoftExceptionLogger.logSoftException(str, new P("Trying to add a root view with an explicit id already set. React Native uses the id field to track react tags and will overwrite this field. If that is fine, explicitly overwrite the id field to View.NO_ID before calling addRootView."));
        }
        view.setId(this.f9648n);
        if (view instanceof InterfaceC0462o0) {
            ((InterfaceC0462o0) view).setRootViewTag(this.f9648n);
        }
        k();
        this.f9636b = true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void w() {
        if (C0655b.j()) {
            this.f9641g.i(this.f9648n);
        }
        this.f9647m = new l.h();
        for (Map.Entry entry : this.f9638d.entrySet()) {
            this.f9647m.m(((Integer) entry.getKey()).intValue(), this);
            z((e) entry.getValue());
        }
        this.f9638d = null;
        this.f9640f = null;
        this.f9642h = null;
        this.f9643i = null;
        this.f9637c = null;
        this.f9639e.clear();
        Y.a.m(f9633o, "Surface [" + this.f9648n + "] was stopped on SurfaceMountingManager.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void x(ViewGroup viewGroup, boolean z3) {
        int id = viewGroup.getId();
        Y.a.m(f9633o, "  <ViewGroup tag=" + id + " class=" + viewGroup.getClass().toString() + ">");
        for (int i3 = 0; i3 < viewGroup.getChildCount(); i3++) {
            Y.a.m(f9633o, "     <View idx=" + i3 + " tag=" + viewGroup.getChildAt(i3).getId() + " class=" + viewGroup.getChildAt(i3).getClass().toString() + ">");
        }
        String str = f9633o;
        Y.a.m(str, "  </ViewGroup tag=" + id + ">");
        if (z3) {
            Y.a.m(str, "Displaying Ancestors:");
            for (ViewParent parent = viewGroup.getParent(); parent != null; parent = parent.getParent()) {
                ViewGroup viewGroup2 = parent instanceof ViewGroup ? (ViewGroup) parent : null;
                int id2 = viewGroup2 == null ? -1 : viewGroup2.getId();
                Y.a.m(f9633o, "<ViewParent tag=" + id2 + " class=" + parent.getClass().toString() + ">");
            }
        }
    }

    private void z(e eVar) {
        A0 a02 = eVar.f9672g;
        if (a02 != null) {
            a02.f();
            eVar.f9672g = null;
        }
        EventEmitterWrapper eventEmitterWrapper = eVar.f9673h;
        if (eventEmitterWrapper != null) {
            eventEmitterWrapper.destroy();
            eVar.f9673h = null;
        }
        ViewManager viewManager = eVar.f9669d;
        if (eVar.f9668c || viewManager == null) {
            return;
        }
        viewManager.onDropViewInstance(eVar.f9666a);
    }

    public void A(String str, int i3, ReadableMap readableMap, A0 a02, boolean z3) {
        UiThreadUtil.assertOnUiThread();
        if (!u() && n(i3) == null) {
            h(str, i3, readableMap, a02, null, z3);
        }
    }

    public void B() {
        Y.a.o(f9633o, "Views created for surface {%d}:", Integer.valueOf(o()));
        for (e eVar : this.f9638d.values()) {
            ViewManager viewManager = eVar.f9669d;
            Integer numValueOf = null;
            String name = viewManager != null ? viewManager.getName() : null;
            View view = eVar.f9666a;
            View view2 = view != null ? (View) view.getParent() : null;
            if (view2 != null) {
                numValueOf = Integer.valueOf(view2.getId());
            }
            Y.a.o(f9633o, "<%s id=%d parentTag=%s isRoot=%b />", name, Integer.valueOf(eVar.f9667b), numValueOf, Boolean.valueOf(eVar.f9668c));
        }
    }

    public void C(int i3, int i4, ReadableArray readableArray) {
        if (u()) {
            return;
        }
        e eVarN = n(i3);
        if (eVarN == null) {
            throw new RetryableMountingLayerException("Unable to find viewState for tag: [" + i3 + "] for commandId: " + i4);
        }
        ViewManager viewManager = eVarN.f9669d;
        if (viewManager == null) {
            throw new RetryableMountingLayerException("Unable to find viewManager for tag " + i3);
        }
        View view = eVarN.f9666a;
        if (view != null) {
            viewManager.receiveCommand(view, i4, readableArray);
            return;
        }
        throw new RetryableMountingLayerException("Unable to find viewState view for tag " + i3);
    }

    public void D(int i3, String str, ReadableArray readableArray) {
        if (u()) {
            return;
        }
        e eVarN = n(i3);
        if (eVarN == null) {
            throw new RetryableMountingLayerException("Unable to find viewState for tag: " + i3 + " for commandId: " + str);
        }
        ViewManager viewManager = eVarN.f9669d;
        if (viewManager == null) {
            throw new RetryableMountingLayerException("Unable to find viewState manager for tag " + i3);
        }
        View view = eVarN.f9666a;
        if (view != null) {
            viewManager.receiveCommand(view, str, readableArray);
            return;
        }
        throw new RetryableMountingLayerException("Unable to find viewState view for tag " + i3);
    }

    public void E(int i3, int i4, int i5) {
        int i6;
        if (u()) {
            return;
        }
        if (this.f9644j.contains(Integer.valueOf(i3))) {
            ReactSoftExceptionLogger.logSoftException(f9633o, new P("removeViewAt tried to remove a React View that was actually reused. This indicates a bug in the Differ (specifically instruction ordering). [" + i3 + "]"));
            return;
        }
        UiThreadUtil.assertOnUiThread();
        e eVarN = n(i4);
        if (eVarN == null) {
            ReactSoftExceptionLogger.logSoftException(m1.d.f9621i, new IllegalStateException("Unable to find viewState for tag: [" + i4 + "] for removeViewAt"));
            return;
        }
        View view = eVarN.f9666a;
        if (!(view instanceof ViewGroup)) {
            String str = "Unable to remove a view from a view that is not a ViewGroup. ParentTag: " + i4 + " - Tag: " + i3 + " - Index: " + i5;
            Y.a.m(f9633o, str);
            throw new IllegalStateException(str);
        }
        ViewGroup viewGroup = (ViewGroup) view;
        if (viewGroup == null) {
            throw new IllegalStateException("Unable to find view for tag [" + i4 + "]");
        }
        int i7 = 0;
        if (f9634p) {
            Y.a.m(f9633o, "removeViewAt: [" + i3 + "] -> [" + i4 + "] idx: " + i5 + " BEFORE");
            x(viewGroup, false);
        }
        N nR = r(eVarN);
        View childAt = nR.getChildAt(viewGroup, i5);
        int id = childAt != null ? childAt.getId() : -1;
        if (id != i3) {
            int childCount = viewGroup.getChildCount();
            while (true) {
                if (i7 >= childCount) {
                    i7 = -1;
                    break;
                } else if (viewGroup.getChildAt(i7).getId() == i3) {
                    break;
                } else {
                    i7++;
                }
            }
            if (i7 == -1) {
                Y.a.m(f9633o, "removeViewAt: [" + i3 + "] -> [" + i4 + "] @" + i5 + ": view already removed from parent! Children in parent: " + childCount);
                return;
            }
            x(viewGroup, true);
            ReactSoftExceptionLogger.logSoftException(f9633o, new IllegalStateException("Tried to remove view [" + i3 + "] of parent [" + i4 + "] at index " + i5 + ", but got view tag " + id + " - actual index of view: " + i7));
            i6 = i7;
        } else {
            i6 = i5;
        }
        try {
            nR.removeViewAt(viewGroup, i6);
            if (f9634p) {
                UiThreadUtil.runOnUiThread(new b(i3, i4, i6, viewGroup));
            }
        } catch (RuntimeException e3) {
            int childCount2 = nR.getChildCount(viewGroup);
            x(viewGroup, true);
            throw new IllegalStateException("Cannot remove child at index " + i6 + " from parent ViewGroup [" + viewGroup.getId() + "], only " + childCount2 + " children in parent. Warning: childCount may be incorrect!", e3);
        }
    }

    public void F(MountItem mountItem) {
        this.f9639e.add(mountItem);
    }

    public void G(int i3, int i4) {
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        if (eVarS.f9669d == null) {
            throw new RetryableMountingLayerException("Unable to find viewState manager for tag " + i3);
        }
        View view = eVarS.f9666a;
        if (view != null) {
            view.sendAccessibilityEvent(i4);
            return;
        }
        throw new RetryableMountingLayerException("Unable to find viewState view for tag " + i3);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public synchronized void H(int i3, int i4, boolean z3) {
        UiThreadUtil.assertOnUiThread();
        if (u()) {
            return;
        }
        if (!z3) {
            this.f9640f.d(i4, null);
            return;
        }
        e eVarS = s(i3);
        View view = eVarS.f9666a;
        if (i4 != i3 && (view instanceof ViewParent)) {
            this.f9640f.d(i4, (ViewParent) view);
            return;
        }
        if (view == 0) {
            SoftAssertions.assertUnreachable("Cannot find view for tag [" + i3 + "].");
            return;
        }
        if (eVarS.f9668c) {
            SoftAssertions.assertUnreachable("Cannot block native responder on [" + i3 + "] that is a root view");
        }
        this.f9640f.d(i4, view.getParent());
    }

    public void I() {
        Y.a.m(f9633o, "Stopping surface [" + this.f9648n + "]");
        if (u()) {
            return;
        }
        this.f9635a = true;
        for (e eVar : this.f9638d.values()) {
            A0 a02 = eVar.f9672g;
            if (a02 != null) {
                a02.f();
                eVar.f9672g = null;
            }
            EventEmitterWrapper eventEmitterWrapper = eVar.f9673h;
            if (eventEmitterWrapper != null) {
                eventEmitterWrapper.destroy();
                eVar.f9673h = null;
            }
        }
        Runnable runnable = new Runnable() { // from class: m1.f
            @Override // java.lang.Runnable
            public final void run() {
                this.f9632b.w();
            }
        };
        if (UiThreadUtil.isOnUiThread()) {
            runnable.run();
        } else {
            UiThreadUtil.runOnUiThread(runnable);
        }
    }

    public void J(int i3) {
        this.f9645k.remove(Integer.valueOf(i3));
        if (this.f9646l.contains(Integer.valueOf(i3))) {
            this.f9646l.remove(Integer.valueOf(i3));
            i(i3);
        }
    }

    public void K(int i3, EventEmitterWrapper eventEmitterWrapper) {
        UiThreadUtil.assertOnUiThread();
        if (u()) {
            return;
        }
        e eVar = (e) this.f9638d.get(Integer.valueOf(i3));
        if (eVar == null) {
            eVar = new e(i3);
            this.f9638d.put(Integer.valueOf(i3), eVar);
        }
        EventEmitterWrapper eventEmitterWrapper2 = eVar.f9673h;
        eVar.f9673h = eventEmitterWrapper;
        if (eventEmitterWrapper2 != eventEmitterWrapper && eventEmitterWrapper2 != null) {
            eventEmitterWrapper2.destroy();
        }
        Queue queue = eVar.f9674i;
        if (queue != null) {
            Iterator it = queue.iterator();
            while (it.hasNext()) {
                ((d) it.next()).a(eventEmitterWrapper);
            }
            eVar.f9674i = null;
        }
    }

    public void L(int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        if (eVarS.f9668c) {
            return;
        }
        View view = eVarS.f9666a;
        if (view == null) {
            throw new IllegalStateException("Unable to find View for tag: " + i3);
        }
        int i11 = 1;
        if (i10 == 1) {
            i11 = 0;
        } else if (i10 != 2) {
            i11 = 2;
        }
        view.setLayoutDirection(i11);
        view.measure(View.MeasureSpec.makeMeasureSpec(i7, 1073741824), View.MeasureSpec.makeMeasureSpec(i8, 1073741824));
        ViewParent parent = view.getParent();
        if (parent instanceof InterfaceC0477w0) {
            parent.requestLayout();
        }
        NativeModule nativeModule = s(i4).f9669d;
        N n3 = nativeModule != null ? (N) nativeModule : null;
        if (n3 == null || !n3.needsCustomLayoutForChildren()) {
            view.layout(i5, i6, i7 + i5, i8 + i6);
        }
        int i12 = i9 == 0 ? 4 : 0;
        if (view.getVisibility() != i12) {
            view.setVisibility(i12);
        }
    }

    public void M(int i3, int i4, int i5, int i6, int i7) {
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        if (eVarS.f9668c) {
            return;
        }
        KeyEvent.Callback callback = eVarS.f9666a;
        if (callback != null) {
            if (callback instanceof InterfaceC0458m0) {
                ((InterfaceC0458m0) callback).d(i4, i5, i6, i7);
            }
        } else {
            throw new IllegalStateException("Unable to find View for tag: " + i3);
        }
    }

    public void N(int i3, int i4, int i5, int i6, int i7) {
        UiThreadUtil.assertOnUiThread();
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        if (eVarS.f9668c) {
            return;
        }
        View view = eVarS.f9666a;
        if (view == null) {
            throw new IllegalStateException("Unable to find View for tag: " + i3);
        }
        ViewManager viewManager = eVarS.f9669d;
        if (viewManager != null) {
            viewManager.setPadding(view, i4, i5, i6, i7);
            return;
        }
        throw new IllegalStateException("Unable to find ViewManager for view: " + eVarS);
    }

    public void O(int i3, ReadableMap readableMap) {
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        eVarS.f9670e = new C0469s0(readableMap);
        View view = eVarS.f9666a;
        if (view != null) {
            ((ViewManager) Z0.a.c(eVarS.f9669d)).updateProperties(view, eVarS.f9670e);
            return;
        }
        throw new IllegalStateException("Unable to find view for tag [" + i3 + "]");
    }

    public void P(int i3, A0 a02) {
        UiThreadUtil.assertOnUiThread();
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        A0 a03 = eVarS.f9672g;
        eVarS.f9672g = a02;
        ViewManager viewManager = eVarS.f9669d;
        if (viewManager == null) {
            throw new IllegalStateException("Unable to find ViewManager for tag: " + i3);
        }
        Object objUpdateState = viewManager.updateState(eVarS.f9666a, eVarS.f9670e, a02);
        if (objUpdateState != null) {
            viewManager.updateExtraData(eVarS.f9666a, objUpdateState);
        }
        if (a03 != null) {
            a03.f();
        }
    }

    public void e(int i3, int i4, int i5) {
        UiThreadUtil.assertOnUiThread();
        if (u()) {
            return;
        }
        e eVarS = s(i3);
        View view = eVarS.f9666a;
        if (!(view instanceof ViewGroup)) {
            String str = "Unable to add a view into a view that is not a ViewGroup. ParentTag: " + i3 + " - Tag: " + i4 + " - Index: " + i5;
            Y.a.m(f9633o, str);
            throw new IllegalStateException(str);
        }
        ViewGroup viewGroup = (ViewGroup) view;
        e eVarS2 = s(i4);
        View view2 = eVarS2.f9666a;
        if (view2 == null) {
            throw new IllegalStateException("Unable to find view for viewState " + eVarS2 + " and tag " + i4);
        }
        boolean z3 = f9634p;
        if (z3) {
            Y.a.m(f9633o, "addViewAt: [" + i4 + "] -> [" + i3 + "] idx: " + i5 + " BEFORE");
            x(viewGroup, false);
        }
        ViewParent parent = view2.getParent();
        if (parent != null) {
            boolean z4 = parent instanceof ViewGroup;
            int id = z4 ? ((ViewGroup) parent).getId() : -1;
            ReactSoftExceptionLogger.logSoftException(f9633o, new IllegalStateException("addViewAt: cannot insert view [" + i4 + "] into parent [" + i3 + "]: View already has a parent: [" + id + "]  Parent: " + parent.getClass().getSimpleName() + " View: " + view2.getClass().getSimpleName()));
            if (z4) {
                ((ViewGroup) parent).removeView(view2);
            }
            this.f9644j.add(Integer.valueOf(i4));
        }
        try {
            r(eVarS).addView(viewGroup, view2, i5);
            if (z3) {
                UiThreadUtil.runOnUiThread(new a(i4, i3, i5, viewGroup));
            }
        } catch (IllegalStateException | IndexOutOfBoundsException e3) {
            throw new IllegalStateException("addViewAt: failed to insert view [" + i4 + "] into parent [" + i3 + "] at index " + i5, e3);
        }
    }

    public void f(View view, B0 b02) {
        this.f9637c = b02;
        d(view);
    }

    public void g(String str, int i3, ReadableMap readableMap, A0 a02, EventEmitterWrapper eventEmitterWrapper, boolean z3) {
        if (u()) {
            return;
        }
        e eVarN = n(i3);
        if (eVarN == null || eVarN.f9666a == null) {
            h(str, i3, readableMap, a02, eventEmitterWrapper, z3);
        }
    }

    public void h(String str, int i3, ReadableMap readableMap, A0 a02, EventEmitterWrapper eventEmitterWrapper, boolean z3) {
        C0353a.c(0L, "SurfaceMountingManager::createViewUnsafe(" + str + ")");
        try {
            C0469s0 c0469s0 = new C0469s0(readableMap);
            e eVar = new e(i3);
            eVar.f9670e = c0469s0;
            eVar.f9672g = a02;
            eVar.f9673h = eventEmitterWrapper;
            this.f9638d.put(Integer.valueOf(i3), eVar);
            if (z3) {
                ViewManager viewManagerC = this.f9641g.c(str);
                eVar.f9666a = viewManagerC.createView(i3, this.f9637c, c0469s0, a02, this.f9640f);
                eVar.f9669d = viewManagerC;
            }
        } finally {
            C0353a.i(0L);
        }
    }

    public void i(int i3) {
        UiThreadUtil.assertOnUiThread();
        if (u()) {
            return;
        }
        e eVarN = n(i3);
        if (eVarN == null) {
            ReactSoftExceptionLogger.logSoftException(ReactSoftExceptionLogger.Categories.SURFACE_MOUNTING_MANAGER_MISSING_VIEWSTATE, new ReactNoCrashSoftException("Unable to find viewState for tag: " + i3 + " for deleteView"));
            return;
        }
        if (this.f9645k.contains(Integer.valueOf(i3))) {
            this.f9646l.add(Integer.valueOf(i3));
        } else {
            this.f9638d.remove(Integer.valueOf(i3));
            z(eVarN);
        }
    }

    public void j(int i3, String str, boolean z3, WritableMap writableMap, int i4) {
        e eVar;
        ConcurrentHashMap concurrentHashMap = this.f9638d;
        if (concurrentHashMap == null || (eVar = (e) concurrentHashMap.get(Integer.valueOf(i3))) == null) {
            return;
        }
        UiThreadUtil.runOnUiThread(new c(eVar, new d(str, writableMap, i4, z3)));
    }

    public B0 l() {
        return this.f9637c;
    }

    public EventEmitterWrapper m(int i3) {
        e eVarN = n(i3);
        if (eVarN == null) {
            return null;
        }
        return eVarN.f9673h;
    }

    public int o() {
        return this.f9648n;
    }

    public View p(int i3) {
        e eVarN = n(i3);
        View view = eVarN == null ? null : eVarN.f9666a;
        if (view != null) {
            return view;
        }
        throw new P("Trying to resolve view with tag " + i3 + " which doesn't exist");
    }

    public boolean q(int i3) {
        l.h hVar = this.f9647m;
        if (hVar != null && hVar.e(i3)) {
            return true;
        }
        ConcurrentHashMap concurrentHashMap = this.f9638d;
        if (concurrentHashMap == null) {
            return false;
        }
        return concurrentHashMap.containsKey(Integer.valueOf(i3));
    }

    public boolean t() {
        return this.f9636b;
    }

    public boolean u() {
        return this.f9635a;
    }

    public void y(int i3) {
        this.f9645k.add(Integer.valueOf(i3));
    }

    private static class e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        View f9666a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final int f9667b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final boolean f9668c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        ViewManager f9669d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        C0469s0 f9670e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        ReadableMap f9671f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        A0 f9672g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        EventEmitterWrapper f9673h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        Queue f9674i;

        public String toString() {
            return "ViewState [" + this.f9667b + "] - isRoot: " + this.f9668c + " - props: " + this.f9670e + " - localData: " + this.f9671f + " - viewManager: " + this.f9669d + " - isLayoutOnly: " + (this.f9669d == null);
        }

        private e(int i3) {
            this(i3, null, null, false);
        }

        private e(int i3, View view, ViewManager viewManager, boolean z3) {
            this.f9670e = null;
            this.f9671f = null;
            this.f9672g = null;
            this.f9673h = null;
            this.f9674i = null;
            this.f9667b = i3;
            this.f9666a = view;
            this.f9668c = z3;
            this.f9669d = viewManager;
        }
    }
}
