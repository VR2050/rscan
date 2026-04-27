package androidx.core.view;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.ContentInfo;
import android.view.KeyEvent;
import android.view.OnReceiveContentListener;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import android.view.WindowInsets;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.contentcapture.ContentCaptureSession;
import androidx.core.view.C0252a;
import androidx.core.view.C0271j0;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import l.C0612g;
import m.AbstractC0624b;
import s.AbstractC0679a;
import t.AbstractC0689a;

/* JADX INFO: loaded from: classes.dex */
public abstract class V {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static WeakHashMap f4418a = null;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static Field f4419b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static boolean f4420c = false;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static final int[] f4421d = {AbstractC0624b.f9546b, AbstractC0624b.f9547c, AbstractC0624b.f9558n, AbstractC0624b.f9569y, AbstractC0624b.f9527B, AbstractC0624b.f9528C, AbstractC0624b.f9529D, AbstractC0624b.f9530E, AbstractC0624b.f9531F, AbstractC0624b.f9532G, AbstractC0624b.f9548d, AbstractC0624b.f9549e, AbstractC0624b.f9550f, AbstractC0624b.f9551g, AbstractC0624b.f9552h, AbstractC0624b.f9553i, AbstractC0624b.f9554j, AbstractC0624b.f9555k, AbstractC0624b.f9556l, AbstractC0624b.f9557m, AbstractC0624b.f9559o, AbstractC0624b.f9560p, AbstractC0624b.f9561q, AbstractC0624b.f9562r, AbstractC0624b.f9563s, AbstractC0624b.f9564t, AbstractC0624b.f9565u, AbstractC0624b.f9566v, AbstractC0624b.f9567w, AbstractC0624b.f9568x, AbstractC0624b.f9570z, AbstractC0624b.f9526A};

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static final G f4422e = new G() { // from class: androidx.core.view.U
        @Override // androidx.core.view.G
        public final C0258d a(C0258d c0258d) {
            return V.I(c0258d);
        }
    };

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final e f4423f = new e();

    class a extends f {
        a(int i3, Class cls, int i4) {
            super(i3, cls, i4);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
        public Boolean c(View view) {
            return Boolean.valueOf(j.d(view));
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
        public void d(View view, Boolean bool) {
            j.j(view, bool.booleanValue());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public boolean g(Boolean bool, Boolean bool2) {
            return !a(bool, bool2);
        }
    }

    class b extends f {
        b(int i3, Class cls, int i4, int i5) {
            super(i3, cls, i4, i5);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
        public CharSequence c(View view) {
            return j.b(view);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
        public void d(View view, CharSequence charSequence) {
            j.h(view, charSequence);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public boolean g(CharSequence charSequence, CharSequence charSequence2) {
            return !TextUtils.equals(charSequence, charSequence2);
        }
    }

    class c extends f {
        c(int i3, Class cls, int i4, int i5) {
            super(i3, cls, i4, i5);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
        public CharSequence c(View view) {
            return l.b(view);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
        public void d(View view, CharSequence charSequence) {
            l.e(view, charSequence);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public boolean g(CharSequence charSequence, CharSequence charSequence2) {
            return !TextUtils.equals(charSequence, charSequence2);
        }
    }

    class d extends f {
        d(int i3, Class cls, int i4) {
            super(i3, cls, i4);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: h, reason: merged with bridge method [inline-methods] */
        public Boolean c(View view) {
            return Boolean.valueOf(j.c(view));
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: i, reason: merged with bridge method [inline-methods] */
        public void d(View view, Boolean bool) {
            j.g(view, bool.booleanValue());
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        @Override // androidx.core.view.V.f
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public boolean g(Boolean bool, Boolean bool2) {
            return !a(bool, bool2);
        }
    }

    static class e implements ViewTreeObserver.OnGlobalLayoutListener, View.OnAttachStateChangeListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final WeakHashMap f4424b = new WeakHashMap();

        e() {
        }

        private void b(Map.Entry entry) {
            View view = (View) entry.getKey();
            boolean zBooleanValue = ((Boolean) entry.getValue()).booleanValue();
            boolean z3 = view.isShown() && view.getWindowVisibility() == 0;
            if (zBooleanValue != z3) {
                V.J(view, z3 ? 16 : 32);
                entry.setValue(Boolean.valueOf(z3));
            }
        }

        private void c(View view) {
            view.getViewTreeObserver().addOnGlobalLayoutListener(this);
        }

        private void e(View view) {
            view.getViewTreeObserver().removeOnGlobalLayoutListener(this);
        }

        void a(View view) {
            this.f4424b.put(view, Boolean.valueOf(view.isShown() && view.getWindowVisibility() == 0));
            view.addOnAttachStateChangeListener(this);
            if (view.isAttachedToWindow()) {
                c(view);
            }
        }

        void d(View view) {
            this.f4424b.remove(view);
            view.removeOnAttachStateChangeListener(this);
            e(view);
        }

        @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
        public void onGlobalLayout() {
            if (Build.VERSION.SDK_INT < 28) {
                Iterator it = this.f4424b.entrySet().iterator();
                while (it.hasNext()) {
                    b((Map.Entry) it.next());
                }
            }
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewAttachedToWindow(View view) {
            c(view);
        }

        @Override // android.view.View.OnAttachStateChangeListener
        public void onViewDetachedFromWindow(View view) {
        }
    }

    static abstract class f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f4425a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Class f4426b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f4427c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f4428d;

        f(int i3, Class cls, int i4) {
            this(i3, cls, 0, i4);
        }

        private boolean b() {
            return Build.VERSION.SDK_INT >= this.f4427c;
        }

        boolean a(Boolean bool, Boolean bool2) {
            return (bool != null && bool.booleanValue()) == (bool2 != null && bool2.booleanValue());
        }

        abstract Object c(View view);

        abstract void d(View view, Object obj);

        Object e(View view) {
            if (b()) {
                return c(view);
            }
            Object tag = view.getTag(this.f4425a);
            if (this.f4426b.isInstance(tag)) {
                return tag;
            }
            return null;
        }

        void f(View view, Object obj) {
            if (b()) {
                d(view, obj);
            } else if (g(e(view), obj)) {
                V.h(view);
                view.setTag(this.f4425a, obj);
                V.J(view, this.f4428d);
            }
        }

        abstract boolean g(Object obj, Object obj2);

        f(int i3, Class cls, int i4, int i5) {
            this.f4425a = i3;
            this.f4426b = cls;
            this.f4428d = i4;
            this.f4427c = i5;
        }
    }

    static class g {
        static WindowInsets a(View view, WindowInsets windowInsets) {
            return view.dispatchApplyWindowInsets(windowInsets);
        }

        static WindowInsets b(View view, WindowInsets windowInsets) {
            return view.onApplyWindowInsets(windowInsets);
        }

        static void c(View view) {
            view.requestApplyInsets();
        }
    }

    private static class h {

        class a implements View.OnApplyWindowInsetsListener {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            C0271j0 f4429a = null;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ View f4430b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            final /* synthetic */ E f4431c;

            a(View view, E e3) {
                this.f4430b = view;
                this.f4431c = e3;
            }

            @Override // android.view.View.OnApplyWindowInsetsListener
            public WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
                C0271j0 c0271j0W = C0271j0.w(windowInsets, view);
                int i3 = Build.VERSION.SDK_INT;
                if (i3 < 30) {
                    h.a(windowInsets, this.f4430b);
                    if (c0271j0W.equals(this.f4429a)) {
                        return this.f4431c.a(view, c0271j0W).u();
                    }
                }
                this.f4429a = c0271j0W;
                C0271j0 c0271j0A = this.f4431c.a(view, c0271j0W);
                if (i3 >= 30) {
                    return c0271j0A.u();
                }
                V.U(view);
                return c0271j0A.u();
            }
        }

        static void a(WindowInsets windowInsets, View view) {
            View.OnApplyWindowInsetsListener onApplyWindowInsetsListener = (View.OnApplyWindowInsetsListener) view.getTag(AbstractC0624b.f9544S);
            if (onApplyWindowInsetsListener != null) {
                onApplyWindowInsetsListener.onApplyWindowInsets(view, windowInsets);
            }
        }

        static C0271j0 b(View view, C0271j0 c0271j0, Rect rect) {
            WindowInsets windowInsetsU = c0271j0.u();
            if (windowInsetsU != null) {
                return C0271j0.w(view.computeSystemWindowInsets(windowInsetsU, rect), view);
            }
            rect.setEmpty();
            return c0271j0;
        }

        static boolean c(View view, float f3, float f4, boolean z3) {
            return view.dispatchNestedFling(f3, f4, z3);
        }

        static boolean d(View view, float f3, float f4) {
            return view.dispatchNestedPreFling(f3, f4);
        }

        static boolean e(View view, int i3, int i4, int[] iArr, int[] iArr2) {
            return view.dispatchNestedPreScroll(i3, i4, iArr, iArr2);
        }

        static boolean f(View view, int i3, int i4, int i5, int i6, int[] iArr) {
            return view.dispatchNestedScroll(i3, i4, i5, i6, iArr);
        }

        static ColorStateList g(View view) {
            return view.getBackgroundTintList();
        }

        static PorterDuff.Mode h(View view) {
            return view.getBackgroundTintMode();
        }

        static float i(View view) {
            return view.getElevation();
        }

        public static C0271j0 j(View view) {
            return C0271j0.a.a(view);
        }

        static String k(View view) {
            return view.getTransitionName();
        }

        static float l(View view) {
            return view.getTranslationZ();
        }

        static float m(View view) {
            return view.getZ();
        }

        static boolean n(View view) {
            return view.hasNestedScrollingParent();
        }

        static boolean o(View view) {
            return view.isImportantForAccessibility();
        }

        static boolean p(View view) {
            return view.isNestedScrollingEnabled();
        }

        static void q(View view, ColorStateList colorStateList) {
            view.setBackgroundTintList(colorStateList);
        }

        static void r(View view, PorterDuff.Mode mode) {
            view.setBackgroundTintMode(mode);
        }

        static void s(View view, float f3) {
            view.setElevation(f3);
        }

        static void t(View view, boolean z3) {
            view.setNestedScrollingEnabled(z3);
        }

        static void u(View view, E e3) {
            if (Build.VERSION.SDK_INT < 30) {
                view.setTag(AbstractC0624b.f9537L, e3);
            }
            if (e3 == null) {
                view.setOnApplyWindowInsetsListener((View.OnApplyWindowInsetsListener) view.getTag(AbstractC0624b.f9544S));
            } else {
                view.setOnApplyWindowInsetsListener(new a(view, e3));
            }
        }

        static void v(View view, String str) {
            view.setTransitionName(str);
        }

        static void w(View view, float f3) {
            view.setTranslationZ(f3);
        }

        static void x(View view, float f3) {
            view.setZ(f3);
        }

        static boolean y(View view, int i3) {
            return view.startNestedScroll(i3);
        }

        static void z(View view) {
            view.stopNestedScroll();
        }
    }

    private static class i {
        public static C0271j0 a(View view) {
            WindowInsets rootWindowInsets = view.getRootWindowInsets();
            if (rootWindowInsets == null) {
                return null;
            }
            C0271j0 c0271j0V = C0271j0.v(rootWindowInsets);
            c0271j0V.s(c0271j0V);
            c0271j0V.d(view.getRootView());
            return c0271j0V;
        }

        static int b(View view) {
            return view.getScrollIndicators();
        }

        static void c(View view, int i3) {
            view.setScrollIndicators(i3);
        }

        static void d(View view, int i3, int i4) {
            view.setScrollIndicators(i3, i4);
        }
    }

    static class j {
        static void a(View view, final o oVar) {
            C0612g c0612g = (C0612g) view.getTag(AbstractC0624b.f9543R);
            if (c0612g == null) {
                c0612g = new C0612g();
                view.setTag(AbstractC0624b.f9543R, c0612g);
            }
            Objects.requireNonNull(oVar);
            View.OnUnhandledKeyEventListener onUnhandledKeyEventListener = new View.OnUnhandledKeyEventListener(oVar) { // from class: androidx.core.view.W
                @Override // android.view.View.OnUnhandledKeyEventListener
                public final boolean onUnhandledKeyEvent(View view2, KeyEvent keyEvent) {
                    throw null;
                }
            };
            c0612g.put(oVar, onUnhandledKeyEventListener);
            view.addOnUnhandledKeyEventListener(onUnhandledKeyEventListener);
        }

        static CharSequence b(View view) {
            return view.getAccessibilityPaneTitle();
        }

        static boolean c(View view) {
            return view.isAccessibilityHeading();
        }

        static boolean d(View view) {
            return view.isScreenReaderFocusable();
        }

        static void e(View view, o oVar) {
            View.OnUnhandledKeyEventListener onUnhandledKeyEventListener;
            C0612g c0612g = (C0612g) view.getTag(AbstractC0624b.f9543R);
            if (c0612g == null || (onUnhandledKeyEventListener = (View.OnUnhandledKeyEventListener) c0612g.get(oVar)) == null) {
                return;
            }
            view.removeOnUnhandledKeyEventListener(onUnhandledKeyEventListener);
        }

        static <T> T f(View view, int i3) {
            return (T) view.requireViewById(i3);
        }

        static void g(View view, boolean z3) {
            view.setAccessibilityHeading(z3);
        }

        static void h(View view, CharSequence charSequence) {
            view.setAccessibilityPaneTitle(charSequence);
        }

        public static void i(View view, AbstractC0679a abstractC0679a) {
            view.setAutofillId(null);
        }

        static void j(View view, boolean z3) {
            view.setScreenReaderFocusable(z3);
        }
    }

    private static class k {
        static View.AccessibilityDelegate a(View view) {
            return view.getAccessibilityDelegate();
        }

        static ContentCaptureSession b(View view) {
            return view.getContentCaptureSession();
        }

        static List<Rect> c(View view) {
            return view.getSystemGestureExclusionRects();
        }

        static void d(View view, Context context, int[] iArr, AttributeSet attributeSet, TypedArray typedArray, int i3, int i4) {
            view.saveAttributeDataForStyleable(context, iArr, attributeSet, typedArray, i3, i4);
        }

        static void e(View view, AbstractC0689a abstractC0689a) {
            view.setContentCaptureSession(null);
        }

        static void f(View view, List<Rect> list) {
            view.setSystemGestureExclusionRects(list);
        }
    }

    private static class l {
        static int a(View view) {
            return view.getImportantForContentCapture();
        }

        static CharSequence b(View view) {
            return view.getStateDescription();
        }

        static boolean c(View view) {
            return view.isImportantForContentCapture();
        }

        static void d(View view, int i3) {
            view.setImportantForContentCapture(i3);
        }

        static void e(View view, CharSequence charSequence) {
            view.setStateDescription(charSequence);
        }
    }

    private static final class m {
        public static String[] a(View view) {
            return view.getReceiveContentMimeTypes();
        }

        public static C0258d b(View view, C0258d c0258d) {
            ContentInfo contentInfoF = c0258d.f();
            ContentInfo contentInfoPerformReceiveContent = view.performReceiveContent(contentInfoF);
            if (contentInfoPerformReceiveContent == null) {
                return null;
            }
            return contentInfoPerformReceiveContent == contentInfoF ? c0258d : C0258d.g(contentInfoPerformReceiveContent);
        }

        public static void c(View view, String[] strArr, F f3) {
            if (f3 == null) {
                view.setOnReceiveContentListener(strArr, null);
            } else {
                view.setOnReceiveContentListener(strArr, new n(f3));
            }
        }
    }

    private static final class n implements OnReceiveContentListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final F f4432a;

        n(F f3) {
            this.f4432a = f3;
        }

        public ContentInfo onReceiveContent(View view, ContentInfo contentInfo) {
            C0258d c0258dG = C0258d.g(contentInfo);
            C0258d c0258dA = this.f4432a.a(view, c0258dG);
            if (c0258dA == null) {
                return null;
            }
            return c0258dA == c0258dG ? contentInfo : c0258dA.f();
        }
    }

    public interface o {
    }

    static class p {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private static final ArrayList f4433d = new ArrayList();

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private WeakHashMap f4434a = null;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private SparseArray f4435b = null;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private WeakReference f4436c = null;

        p() {
        }

        static p a(View view) {
            p pVar = (p) view.getTag(AbstractC0624b.f9542Q);
            if (pVar != null) {
                return pVar;
            }
            p pVar2 = new p();
            view.setTag(AbstractC0624b.f9542Q, pVar2);
            return pVar2;
        }

        private View c(View view, KeyEvent keyEvent) {
            WeakHashMap weakHashMap = this.f4434a;
            if (weakHashMap != null && weakHashMap.containsKey(view)) {
                if (view instanceof ViewGroup) {
                    ViewGroup viewGroup = (ViewGroup) view;
                    for (int childCount = viewGroup.getChildCount() - 1; childCount >= 0; childCount--) {
                        View viewC = c(viewGroup.getChildAt(childCount), keyEvent);
                        if (viewC != null) {
                            return viewC;
                        }
                    }
                }
                if (e(view, keyEvent)) {
                    return view;
                }
            }
            return null;
        }

        private SparseArray d() {
            if (this.f4435b == null) {
                this.f4435b = new SparseArray();
            }
            return this.f4435b;
        }

        private boolean e(View view, KeyEvent keyEvent) {
            int size;
            ArrayList arrayList = (ArrayList) view.getTag(AbstractC0624b.f9543R);
            if (arrayList == null || arrayList.size() - 1 < 0) {
                return false;
            }
            androidx.activity.result.d.a(arrayList.get(size));
            throw null;
        }

        private void g() {
            WeakHashMap weakHashMap = this.f4434a;
            if (weakHashMap != null) {
                weakHashMap.clear();
            }
            ArrayList arrayList = f4433d;
            if (arrayList.isEmpty()) {
                return;
            }
            synchronized (arrayList) {
                try {
                    if (this.f4434a == null) {
                        this.f4434a = new WeakHashMap();
                    }
                    for (int size = arrayList.size() - 1; size >= 0; size--) {
                        ArrayList arrayList2 = f4433d;
                        View view = (View) ((WeakReference) arrayList2.get(size)).get();
                        if (view == null) {
                            arrayList2.remove(size);
                        } else {
                            this.f4434a.put(view, Boolean.TRUE);
                            for (ViewParent parent = view.getParent(); parent instanceof View; parent = parent.getParent()) {
                                this.f4434a.put((View) parent, Boolean.TRUE);
                            }
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        boolean b(View view, KeyEvent keyEvent) {
            if (keyEvent.getAction() == 0) {
                g();
            }
            View viewC = c(view, keyEvent);
            if (keyEvent.getAction() == 0) {
                int keyCode = keyEvent.getKeyCode();
                if (viewC != null && !KeyEvent.isModifierKey(keyCode)) {
                    d().put(keyCode, new WeakReference(viewC));
                }
            }
            return viewC != null;
        }

        boolean f(KeyEvent keyEvent) {
            WeakReference weakReference;
            int iIndexOfKey;
            WeakReference weakReference2 = this.f4436c;
            if (weakReference2 != null && weakReference2.get() == keyEvent) {
                return false;
            }
            this.f4436c = new WeakReference(keyEvent);
            SparseArray sparseArrayD = d();
            if (keyEvent.getAction() != 1 || (iIndexOfKey = sparseArrayD.indexOfKey(keyEvent.getKeyCode())) < 0) {
                weakReference = null;
            } else {
                weakReference = (WeakReference) sparseArrayD.valueAt(iIndexOfKey);
                sparseArrayD.removeAt(iIndexOfKey);
            }
            if (weakReference == null) {
                weakReference = (WeakReference) sparseArrayD.get(keyEvent.getKeyCode());
            }
            if (weakReference == null) {
                return false;
            }
            View view = (View) weakReference.get();
            if (view != null && view.isAttachedToWindow()) {
                e(view, keyEvent);
            }
            return true;
        }
    }

    public static String A(View view) {
        return h.k(view);
    }

    public static int B(View view) {
        return view.getWindowSystemUiVisibility();
    }

    public static boolean C(View view) {
        return j(view) != null;
    }

    public static boolean D(View view) {
        Boolean bool = (Boolean) b().e(view);
        return bool != null && bool.booleanValue();
    }

    public static boolean E(View view) {
        return view.isAttachedToWindow();
    }

    public static boolean F(View view) {
        return view.isLaidOut();
    }

    public static boolean G(View view) {
        return h.p(view);
    }

    public static boolean H(View view) {
        Boolean bool = (Boolean) W().e(view);
        return bool != null && bool.booleanValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ C0258d I(C0258d c0258d) {
        return c0258d;
    }

    static void J(View view, int i3) {
        AccessibilityManager accessibilityManager = (AccessibilityManager) view.getContext().getSystemService("accessibility");
        if (accessibilityManager.isEnabled()) {
            boolean z3 = l(view) != null && view.isShown() && view.getWindowVisibility() == 0;
            if (view.getAccessibilityLiveRegion() != 0 || z3) {
                AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain();
                accessibilityEventObtain.setEventType(z3 ? 32 : 2048);
                accessibilityEventObtain.setContentChangeTypes(i3);
                if (z3) {
                    accessibilityEventObtain.getText().add(l(view));
                    g0(view);
                }
                view.sendAccessibilityEventUnchecked(accessibilityEventObtain);
                return;
            }
            if (i3 == 32) {
                AccessibilityEvent accessibilityEventObtain2 = AccessibilityEvent.obtain();
                view.onInitializeAccessibilityEvent(accessibilityEventObtain2);
                accessibilityEventObtain2.setEventType(32);
                accessibilityEventObtain2.setContentChangeTypes(i3);
                accessibilityEventObtain2.setSource(view);
                view.onPopulateAccessibilityEvent(accessibilityEventObtain2);
                accessibilityEventObtain2.getText().add(l(view));
                accessibilityManager.sendAccessibilityEvent(accessibilityEventObtain2);
                return;
            }
            if (view.getParent() != null) {
                try {
                    view.getParent().notifySubtreeAccessibilityStateChanged(view, view, i3);
                } catch (AbstractMethodError e3) {
                    Log.e("ViewCompat", view.getParent().getClass().getSimpleName() + " does not fully implement ViewParent", e3);
                }
            }
        }
    }

    public static void K(View view, int i3) {
        view.offsetLeftAndRight(i3);
    }

    public static void L(View view, int i3) {
        view.offsetTopAndBottom(i3);
    }

    public static C0271j0 M(View view, C0271j0 c0271j0) {
        WindowInsets windowInsetsU = c0271j0.u();
        if (windowInsetsU != null) {
            WindowInsets windowInsetsB = g.b(view, windowInsetsU);
            if (!windowInsetsB.equals(windowInsetsU)) {
                return C0271j0.w(windowInsetsB, view);
            }
        }
        return c0271j0;
    }

    public static void N(View view, r.v vVar) {
        view.onInitializeAccessibilityNodeInfo(vVar.P0());
    }

    private static f O() {
        return new b(AbstractC0624b.f9536K, CharSequence.class, 8, 28);
    }

    public static boolean P(View view, int i3, Bundle bundle) {
        return view.performAccessibilityAction(i3, bundle);
    }

    public static C0258d Q(View view, C0258d c0258d) {
        if (Log.isLoggable("ViewCompat", 3)) {
            Log.d("ViewCompat", "performReceiveContent: " + c0258d + ", view=" + view.getClass().getSimpleName() + "[" + view.getId() + "]");
        }
        if (Build.VERSION.SDK_INT >= 31) {
            return m.b(view, c0258d);
        }
        F f3 = (F) view.getTag(AbstractC0624b.f9538M);
        if (f3 == null) {
            return p(view).a(c0258d);
        }
        C0258d c0258dA = f3.a(view, c0258d);
        if (c0258dA == null) {
            return null;
        }
        return p(view).a(c0258dA);
    }

    public static void R(View view) {
        view.postInvalidateOnAnimation();
    }

    public static void S(View view, Runnable runnable) {
        view.postOnAnimation(runnable);
    }

    public static void T(View view, Runnable runnable, long j3) {
        view.postOnAnimationDelayed(runnable, j3);
    }

    public static void U(View view) {
        g.c(view);
    }

    public static void V(View view, Context context, int[] iArr, AttributeSet attributeSet, TypedArray typedArray, int i3, int i4) {
        if (Build.VERSION.SDK_INT >= 29) {
            k.d(view, context, iArr, attributeSet, typedArray, i3, i4);
        }
    }

    private static f W() {
        return new a(AbstractC0624b.f9540O, Boolean.class, 28);
    }

    public static void X(View view, C0252a c0252a) {
        if (c0252a == null && (j(view) instanceof C0252a.C0064a)) {
            c0252a = new C0252a();
        }
        g0(view);
        view.setAccessibilityDelegate(c0252a == null ? null : c0252a.d());
    }

    public static void Y(View view, boolean z3) {
        b().f(view, Boolean.valueOf(z3));
    }

    public static void Z(View view, int i3) {
        view.setAccessibilityLiveRegion(i3);
    }

    public static void a0(View view, CharSequence charSequence) {
        O().f(view, charSequence);
        if (charSequence != null) {
            f4423f.a(view);
        } else {
            f4423f.d(view);
        }
    }

    private static f b() {
        return new d(AbstractC0624b.f9535J, Boolean.class, 28);
    }

    public static void b0(View view, Drawable drawable) {
        view.setBackground(drawable);
    }

    public static C0261e0 c(View view) {
        if (f4418a == null) {
            f4418a = new WeakHashMap();
        }
        C0261e0 c0261e0 = (C0261e0) f4418a.get(view);
        if (c0261e0 != null) {
            return c0261e0;
        }
        C0261e0 c0261e02 = new C0261e0(view);
        f4418a.put(view, c0261e02);
        return c0261e02;
    }

    public static void c0(View view, ColorStateList colorStateList) {
        h.q(view, colorStateList);
    }

    public static C0271j0 d(View view, C0271j0 c0271j0, Rect rect) {
        return h.b(view, c0271j0, rect);
    }

    public static void d0(View view, PorterDuff.Mode mode) {
        h.r(view, mode);
    }

    public static C0271j0 e(View view, C0271j0 c0271j0) {
        WindowInsets windowInsetsU = c0271j0.u();
        if (windowInsetsU != null) {
            WindowInsets windowInsetsA = g.a(view, windowInsetsU);
            if (!windowInsetsA.equals(windowInsetsU)) {
                return C0271j0.w(windowInsetsA, view);
            }
        }
        return c0271j0;
    }

    public static void e0(View view, float f3) {
        h.s(view, f3);
    }

    static boolean f(View view, KeyEvent keyEvent) {
        if (Build.VERSION.SDK_INT >= 28) {
            return false;
        }
        return p.a(view).b(view, keyEvent);
    }

    public static void f0(View view, int i3) {
        view.setImportantForAccessibility(i3);
    }

    static boolean g(View view, KeyEvent keyEvent) {
        if (Build.VERSION.SDK_INT >= 28) {
            return false;
        }
        return p.a(view).f(keyEvent);
    }

    private static void g0(View view) {
        if (view.getImportantForAccessibility() == 0) {
            view.setImportantForAccessibility(1);
        }
    }

    static void h(View view) {
        C0252a c0252aI = i(view);
        if (c0252aI == null) {
            c0252aI = new C0252a();
        }
        X(view, c0252aI);
    }

    public static void h0(View view, boolean z3) {
        h.t(view, z3);
    }

    public static C0252a i(View view) {
        View.AccessibilityDelegate accessibilityDelegateJ = j(view);
        if (accessibilityDelegateJ == null) {
            return null;
        }
        return accessibilityDelegateJ instanceof C0252a.C0064a ? ((C0252a.C0064a) accessibilityDelegateJ).f4443a : new C0252a(accessibilityDelegateJ);
    }

    public static void i0(View view, E e3) {
        h.u(view, e3);
    }

    private static View.AccessibilityDelegate j(View view) {
        return Build.VERSION.SDK_INT >= 29 ? k.a(view) : k(view);
    }

    public static void j0(View view, boolean z3) {
        W().f(view, Boolean.valueOf(z3));
    }

    private static View.AccessibilityDelegate k(View view) {
        if (f4420c) {
            return null;
        }
        if (f4419b == null) {
            try {
                Field declaredField = View.class.getDeclaredField("mAccessibilityDelegate");
                f4419b = declaredField;
                declaredField.setAccessible(true);
            } catch (Throwable unused) {
                f4420c = true;
                return null;
            }
        }
        try {
            Object obj = f4419b.get(view);
            if (obj instanceof View.AccessibilityDelegate) {
                return (View.AccessibilityDelegate) obj;
            }
            return null;
        } catch (Throwable unused2) {
            f4420c = true;
            return null;
        }
    }

    public static void k0(View view, int i3, int i4) {
        i.d(view, i3, i4);
    }

    public static CharSequence l(View view) {
        return (CharSequence) O().e(view);
    }

    public static void l0(View view, CharSequence charSequence) {
        n0().f(view, charSequence);
    }

    public static ColorStateList m(View view) {
        return h.g(view);
    }

    public static void m0(View view, String str) {
        h.v(view, str);
    }

    public static PorterDuff.Mode n(View view) {
        return h.h(view);
    }

    private static f n0() {
        return new c(AbstractC0624b.f9541P, CharSequence.class, 64, 30);
    }

    public static float o(View view) {
        return h.i(view);
    }

    public static void o0(View view) {
        h.z(view);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private static G p(View view) {
        return view instanceof G ? (G) view : f4422e;
    }

    public static boolean q(View view) {
        return view.getFitsSystemWindows();
    }

    public static int r(View view) {
        return view.getImportantForAccessibility();
    }

    public static int s(View view) {
        return view.getLayoutDirection();
    }

    public static int t(View view) {
        return view.getMinimumHeight();
    }

    public static String[] u(View view) {
        return Build.VERSION.SDK_INT >= 31 ? m.a(view) : (String[]) view.getTag(AbstractC0624b.f9539N);
    }

    public static int v(View view) {
        return view.getPaddingEnd();
    }

    public static int w(View view) {
        return view.getPaddingStart();
    }

    public static ViewParent x(View view) {
        return view.getParentForAccessibility();
    }

    public static C0271j0 y(View view) {
        return i.a(view);
    }

    public static CharSequence z(View view) {
        return (CharSequence) n0().e(view);
    }
}
