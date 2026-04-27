package androidx.appcompat.app;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.app.UiModeManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.LocaleList;
import android.os.PowerManager;
import android.text.TextUtils;
import android.util.AndroidRuntimeException;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.ActionMode;
import android.view.ContextThemeWrapper;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import androidx.appcompat.view.b;
import androidx.appcompat.view.f;
import androidx.appcompat.view.menu.e;
import androidx.appcompat.view.menu.j;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.C0237k;
import androidx.appcompat.widget.ContentFrameLayout;
import androidx.appcompat.widget.I;
import androidx.appcompat.widget.ViewStubCompat;
import androidx.appcompat.widget.g0;
import androidx.appcompat.widget.q0;
import androidx.appcompat.widget.r0;
import androidx.core.content.res.f;
import androidx.core.view.AbstractC0265g0;
import androidx.core.view.AbstractC0282t;
import androidx.core.view.AbstractC0283u;
import androidx.core.view.C0261e0;
import androidx.core.view.C0271j0;
import androidx.core.view.E;
import androidx.core.view.V;
import androidx.lifecycle.f;
import d.AbstractC0502a;
import e.AbstractC0510a;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import l.C0612g;
import org.xmlpull.v1.XmlPullParser;

/* JADX INFO: loaded from: classes.dex */
class h extends androidx.appcompat.app.f implements e.a, LayoutInflater.Factory2 {

    /* JADX INFO: renamed from: k0, reason: collision with root package name */
    private static final C0612g f3148k0 = new C0612g();

    /* JADX INFO: renamed from: l0, reason: collision with root package name */
    private static final boolean f3149l0 = false;

    /* JADX INFO: renamed from: m0, reason: collision with root package name */
    private static final int[] f3150m0 = {R.attr.windowBackground};

    /* JADX INFO: renamed from: n0, reason: collision with root package name */
    private static final boolean f3151n0 = !"robolectric".equals(Build.FINGERPRINT);

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private boolean f3152A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private boolean f3153B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    ViewGroup f3154C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private TextView f3155D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private View f3156E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private boolean f3157F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private boolean f3158G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    boolean f3159H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    boolean f3160I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    boolean f3161J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    boolean f3162K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    boolean f3163L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private boolean f3164M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    private q[] f3165N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    private q f3166O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private boolean f3167P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private boolean f3168Q;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    private boolean f3169R;

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    boolean f3170S;

    /* JADX INFO: renamed from: T, reason: collision with root package name */
    private Configuration f3171T;

    /* JADX INFO: renamed from: U, reason: collision with root package name */
    private int f3172U;

    /* JADX INFO: renamed from: V, reason: collision with root package name */
    private int f3173V;

    /* JADX INFO: renamed from: W, reason: collision with root package name */
    private int f3174W;

    /* JADX INFO: renamed from: X, reason: collision with root package name */
    private boolean f3175X;

    /* JADX INFO: renamed from: Y, reason: collision with root package name */
    private n f3176Y;

    /* JADX INFO: renamed from: Z, reason: collision with root package name */
    private n f3177Z;

    /* JADX INFO: renamed from: a0, reason: collision with root package name */
    boolean f3178a0;

    /* JADX INFO: renamed from: b0, reason: collision with root package name */
    int f3179b0;

    /* JADX INFO: renamed from: c0, reason: collision with root package name */
    private final Runnable f3180c0;

    /* JADX INFO: renamed from: d0, reason: collision with root package name */
    private boolean f3181d0;

    /* JADX INFO: renamed from: e0, reason: collision with root package name */
    private Rect f3182e0;

    /* JADX INFO: renamed from: f0, reason: collision with root package name */
    private Rect f3183f0;

    /* JADX INFO: renamed from: g0, reason: collision with root package name */
    private s f3184g0;

    /* JADX INFO: renamed from: h0, reason: collision with root package name */
    private u f3185h0;

    /* JADX INFO: renamed from: i0, reason: collision with root package name */
    private OnBackInvokedDispatcher f3186i0;

    /* JADX INFO: renamed from: j0, reason: collision with root package name */
    private OnBackInvokedCallback f3187j0;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final Object f3188k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    final Context f3189l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    Window f3190m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private l f3191n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    final androidx.appcompat.app.d f3192o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    androidx.appcompat.app.a f3193p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    MenuInflater f3194q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private CharSequence f3195r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private I f3196s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private f f3197t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private r f3198u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    androidx.appcompat.view.b f3199v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    ActionBarContextView f3200w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    PopupWindow f3201x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    Runnable f3202y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    C0261e0 f3203z;

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            h hVar = h.this;
            if ((hVar.f3179b0 & 1) != 0) {
                hVar.i0(0);
            }
            h hVar2 = h.this;
            if ((hVar2.f3179b0 & 4096) != 0) {
                hVar2.i0(108);
            }
            h hVar3 = h.this;
            hVar3.f3178a0 = false;
            hVar3.f3179b0 = 0;
        }
    }

    class b implements E {
        b() {
        }

        @Override // androidx.core.view.E
        public C0271j0 a(View view, C0271j0 c0271j0) {
            int iK = c0271j0.k();
            int iF1 = h.this.f1(c0271j0, null);
            if (iK != iF1) {
                c0271j0 = c0271j0.p(c0271j0.i(), iF1, c0271j0.j(), c0271j0.h());
            }
            return V.M(view, c0271j0);
        }
    }

    class c implements ContentFrameLayout.a {
        c() {
        }

        @Override // androidx.appcompat.widget.ContentFrameLayout.a
        public void a() {
        }

        @Override // androidx.appcompat.widget.ContentFrameLayout.a
        public void onDetachedFromWindow() {
            h.this.g0();
        }
    }

    class d implements Runnable {

        class a extends AbstractC0265g0 {
            a() {
            }

            @Override // androidx.core.view.InterfaceC0263f0
            public void b(View view) {
                h.this.f3200w.setAlpha(1.0f);
                h.this.f3203z.h(null);
                h.this.f3203z = null;
            }

            @Override // androidx.core.view.AbstractC0265g0, androidx.core.view.InterfaceC0263f0
            public void c(View view) {
                h.this.f3200w.setVisibility(0);
            }
        }

        d() {
        }

        @Override // java.lang.Runnable
        public void run() {
            h hVar = h.this;
            hVar.f3201x.showAtLocation(hVar.f3200w, 55, 0, 0);
            h.this.j0();
            if (!h.this.U0()) {
                h.this.f3200w.setAlpha(1.0f);
                h.this.f3200w.setVisibility(0);
            } else {
                h.this.f3200w.setAlpha(0.0f);
                h hVar2 = h.this;
                hVar2.f3203z = V.c(hVar2.f3200w).b(1.0f);
                h.this.f3203z.h(new a());
            }
        }
    }

    class e extends AbstractC0265g0 {
        e() {
        }

        @Override // androidx.core.view.InterfaceC0263f0
        public void b(View view) {
            h.this.f3200w.setAlpha(1.0f);
            h.this.f3203z.h(null);
            h.this.f3203z = null;
        }

        @Override // androidx.core.view.AbstractC0265g0, androidx.core.view.InterfaceC0263f0
        public void c(View view) {
            h.this.f3200w.setVisibility(0);
            if (h.this.f3200w.getParent() instanceof View) {
                V.U((View) h.this.f3200w.getParent());
            }
        }
    }

    private final class f implements j.a {
        f() {
        }

        @Override // androidx.appcompat.view.menu.j.a
        public void c(androidx.appcompat.view.menu.e eVar, boolean z3) {
            h.this.Z(eVar);
        }

        @Override // androidx.appcompat.view.menu.j.a
        public boolean d(androidx.appcompat.view.menu.e eVar) {
            Window.Callback callbackV0 = h.this.v0();
            if (callbackV0 == null) {
                return true;
            }
            callbackV0.onMenuOpened(108, eVar);
            return true;
        }
    }

    class g implements b.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private b.a f3211a;

        class a extends AbstractC0265g0 {
            a() {
            }

            @Override // androidx.core.view.InterfaceC0263f0
            public void b(View view) {
                h.this.f3200w.setVisibility(8);
                h hVar = h.this;
                PopupWindow popupWindow = hVar.f3201x;
                if (popupWindow != null) {
                    popupWindow.dismiss();
                } else if (hVar.f3200w.getParent() instanceof View) {
                    V.U((View) h.this.f3200w.getParent());
                }
                h.this.f3200w.k();
                h.this.f3203z.h(null);
                h hVar2 = h.this;
                hVar2.f3203z = null;
                V.U(hVar2.f3154C);
            }
        }

        public g(b.a aVar) {
            this.f3211a = aVar;
        }

        @Override // androidx.appcompat.view.b.a
        public boolean a(androidx.appcompat.view.b bVar, Menu menu) {
            V.U(h.this.f3154C);
            return this.f3211a.a(bVar, menu);
        }

        @Override // androidx.appcompat.view.b.a
        public void b(androidx.appcompat.view.b bVar) {
            this.f3211a.b(bVar);
            h hVar = h.this;
            if (hVar.f3201x != null) {
                hVar.f3190m.getDecorView().removeCallbacks(h.this.f3202y);
            }
            h hVar2 = h.this;
            if (hVar2.f3200w != null) {
                hVar2.j0();
                h hVar3 = h.this;
                hVar3.f3203z = V.c(hVar3.f3200w).b(0.0f);
                h.this.f3203z.h(new a());
            }
            h hVar4 = h.this;
            androidx.appcompat.app.d dVar = hVar4.f3192o;
            if (dVar != null) {
                dVar.h(hVar4.f3199v);
            }
            h hVar5 = h.this;
            hVar5.f3199v = null;
            V.U(hVar5.f3154C);
            h.this.d1();
        }

        @Override // androidx.appcompat.view.b.a
        public boolean c(androidx.appcompat.view.b bVar, MenuItem menuItem) {
            return this.f3211a.c(bVar, menuItem);
        }

        @Override // androidx.appcompat.view.b.a
        public boolean d(androidx.appcompat.view.b bVar, Menu menu) {
            return this.f3211a.d(bVar, menu);
        }
    }

    /* JADX INFO: renamed from: androidx.appcompat.app.h$h, reason: collision with other inner class name */
    static class C0050h {
        static boolean a(PowerManager powerManager) {
            return powerManager.isPowerSaveMode();
        }

        static String b(Locale locale) {
            return locale.toLanguageTag();
        }
    }

    static class i {
        static void a(Configuration configuration, Configuration configuration2, Configuration configuration3) {
            LocaleList locales = configuration.getLocales();
            LocaleList locales2 = configuration2.getLocales();
            if (locales.equals(locales2)) {
                return;
            }
            configuration3.setLocales(locales2);
            configuration3.locale = configuration2.locale;
        }

        static androidx.core.os.c b(Configuration configuration) {
            return androidx.core.os.c.b(configuration.getLocales().toLanguageTags());
        }

        public static void c(androidx.core.os.c cVar) {
            LocaleList.setDefault(LocaleList.forLanguageTags(cVar.g()));
        }

        static void d(Configuration configuration, androidx.core.os.c cVar) {
            configuration.setLocales(LocaleList.forLanguageTags(cVar.g()));
        }
    }

    static class j {
        static void a(Configuration configuration, Configuration configuration2, Configuration configuration3) {
            if ((configuration.colorMode & 3) != (configuration2.colorMode & 3)) {
                configuration3.colorMode |= configuration2.colorMode & 3;
            }
            if ((configuration.colorMode & 12) != (configuration2.colorMode & 12)) {
                configuration3.colorMode |= configuration2.colorMode & 12;
            }
        }
    }

    static class k {
        static OnBackInvokedDispatcher a(Activity activity) {
            return activity.getOnBackInvokedDispatcher();
        }

        static OnBackInvokedCallback b(Object obj, final h hVar) {
            Objects.requireNonNull(hVar);
            OnBackInvokedCallback onBackInvokedCallback = new OnBackInvokedCallback() { // from class: androidx.appcompat.app.p
                @Override // android.window.OnBackInvokedCallback
                public final void onBackInvoked() {
                    hVar.D0();
                }
            };
            androidx.appcompat.app.l.a(obj).registerOnBackInvokedCallback(1000000, onBackInvokedCallback);
            return onBackInvokedCallback;
        }

        static void c(Object obj, Object obj2) {
            androidx.appcompat.app.l.a(obj).unregisterOnBackInvokedCallback(androidx.appcompat.app.k.a(obj2));
        }
    }

    class l extends androidx.appcompat.view.i {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f3214c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f3215d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f3216e;

        l(Window.Callback callback) {
            super(callback);
        }

        public boolean b(Window.Callback callback, KeyEvent keyEvent) {
            try {
                this.f3215d = true;
                return callback.dispatchKeyEvent(keyEvent);
            } finally {
                this.f3215d = false;
            }
        }

        public void c(Window.Callback callback) {
            try {
                this.f3214c = true;
                callback.onContentChanged();
            } finally {
                this.f3214c = false;
            }
        }

        public void d(Window.Callback callback, int i3, Menu menu) {
            try {
                this.f3216e = true;
                callback.onPanelClosed(i3, menu);
            } finally {
                this.f3216e = false;
            }
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public boolean dispatchKeyEvent(KeyEvent keyEvent) {
            return this.f3215d ? a().dispatchKeyEvent(keyEvent) : h.this.h0(keyEvent) || super.dispatchKeyEvent(keyEvent);
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public boolean dispatchKeyShortcutEvent(KeyEvent keyEvent) {
            return super.dispatchKeyShortcutEvent(keyEvent) || h.this.G0(keyEvent.getKeyCode(), keyEvent);
        }

        final ActionMode e(ActionMode.Callback callback) {
            f.a aVar = new f.a(h.this.f3189l, callback);
            androidx.appcompat.view.b bVarX0 = h.this.X0(aVar);
            if (bVarX0 != null) {
                return aVar.e(bVarX0);
            }
            return null;
        }

        @Override // android.view.Window.Callback
        public void onContentChanged() {
            if (this.f3214c) {
                a().onContentChanged();
            }
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public boolean onCreatePanelMenu(int i3, Menu menu) {
            if (i3 != 0 || (menu instanceof androidx.appcompat.view.menu.e)) {
                return super.onCreatePanelMenu(i3, menu);
            }
            return false;
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public View onCreatePanelView(int i3) {
            return super.onCreatePanelView(i3);
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public boolean onMenuOpened(int i3, Menu menu) {
            super.onMenuOpened(i3, menu);
            h.this.J0(i3);
            return true;
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public void onPanelClosed(int i3, Menu menu) {
            if (this.f3216e) {
                a().onPanelClosed(i3, menu);
            } else {
                super.onPanelClosed(i3, menu);
                h.this.K0(i3);
            }
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public boolean onPreparePanel(int i3, View view, Menu menu) {
            androidx.appcompat.view.menu.e eVar = menu instanceof androidx.appcompat.view.menu.e ? (androidx.appcompat.view.menu.e) menu : null;
            if (i3 == 0 && eVar == null) {
                return false;
            }
            if (eVar != null) {
                eVar.b0(true);
            }
            boolean zOnPreparePanel = super.onPreparePanel(i3, view, menu);
            if (eVar != null) {
                eVar.b0(false);
            }
            return zOnPreparePanel;
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public void onProvideKeyboardShortcuts(List list, Menu menu, int i3) {
            androidx.appcompat.view.menu.e eVar;
            q qVarT0 = h.this.t0(0, true);
            if (qVarT0 == null || (eVar = qVarT0.f3235j) == null) {
                super.onProvideKeyboardShortcuts(list, menu, i3);
            } else {
                super.onProvideKeyboardShortcuts(list, eVar, i3);
            }
        }

        @Override // android.view.Window.Callback
        public ActionMode onWindowStartingActionMode(ActionMode.Callback callback) {
            return null;
        }

        @Override // androidx.appcompat.view.i, android.view.Window.Callback
        public ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int i3) {
            return (h.this.B0() && i3 == 0) ? e(callback) : super.onWindowStartingActionMode(callback, i3);
        }
    }

    private class m extends n {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final PowerManager f3218c;

        m(Context context) {
            super();
            this.f3218c = (PowerManager) context.getApplicationContext().getSystemService("power");
        }

        @Override // androidx.appcompat.app.h.n
        IntentFilter b() {
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("android.os.action.POWER_SAVE_MODE_CHANGED");
            return intentFilter;
        }

        @Override // androidx.appcompat.app.h.n
        public int c() {
            return C0050h.a(this.f3218c) ? 2 : 1;
        }

        @Override // androidx.appcompat.app.h.n
        public void d() {
            h.this.f();
        }
    }

    abstract class n {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private BroadcastReceiver f3220a;

        class a extends BroadcastReceiver {
            a() {
            }

            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context, Intent intent) {
                n.this.d();
            }
        }

        n() {
        }

        void a() {
            BroadcastReceiver broadcastReceiver = this.f3220a;
            if (broadcastReceiver != null) {
                try {
                    h.this.f3189l.unregisterReceiver(broadcastReceiver);
                } catch (IllegalArgumentException unused) {
                }
                this.f3220a = null;
            }
        }

        abstract IntentFilter b();

        abstract int c();

        abstract void d();

        void e() {
            a();
            IntentFilter intentFilterB = b();
            if (intentFilterB == null || intentFilterB.countActions() == 0) {
                return;
            }
            if (this.f3220a == null) {
                this.f3220a = new a();
            }
            h.this.f3189l.registerReceiver(this.f3220a, intentFilterB);
        }
    }

    private class o extends n {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final y f3223c;

        o(y yVar) {
            super();
            this.f3223c = yVar;
        }

        @Override // androidx.appcompat.app.h.n
        IntentFilter b() {
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction("android.intent.action.TIME_SET");
            intentFilter.addAction("android.intent.action.TIMEZONE_CHANGED");
            intentFilter.addAction("android.intent.action.TIME_TICK");
            return intentFilter;
        }

        @Override // androidx.appcompat.app.h.n
        public int c() {
            return this.f3223c.d() ? 2 : 1;
        }

        @Override // androidx.appcompat.app.h.n
        public void d() {
            h.this.f();
        }
    }

    private class p extends ContentFrameLayout {
        public p(Context context) {
            super(context);
        }

        private boolean b(int i3, int i4) {
            return i3 < -5 || i4 < -5 || i3 > getWidth() + 5 || i4 > getHeight() + 5;
        }

        @Override // android.view.ViewGroup, android.view.View
        public boolean dispatchKeyEvent(KeyEvent keyEvent) {
            return h.this.h0(keyEvent) || super.dispatchKeyEvent(keyEvent);
        }

        @Override // android.view.ViewGroup
        public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
            if (motionEvent.getAction() != 0 || !b((int) motionEvent.getX(), (int) motionEvent.getY())) {
                return super.onInterceptTouchEvent(motionEvent);
            }
            h.this.b0(0);
            return true;
        }

        @Override // android.view.View
        public void setBackgroundResource(int i3) {
            setBackgroundDrawable(AbstractC0510a.b(getContext(), i3));
        }
    }

    protected static final class q {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        int f3226a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f3227b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        int f3228c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        int f3229d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        int f3230e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        int f3231f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        ViewGroup f3232g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        View f3233h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        View f3234i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        androidx.appcompat.view.menu.e f3235j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        androidx.appcompat.view.menu.c f3236k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        Context f3237l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        boolean f3238m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        boolean f3239n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        boolean f3240o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        public boolean f3241p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        boolean f3242q = false;

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        boolean f3243r;

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        Bundle f3244s;

        q(int i3) {
            this.f3226a = i3;
        }

        androidx.appcompat.view.menu.k a(j.a aVar) {
            if (this.f3235j == null) {
                return null;
            }
            if (this.f3236k == null) {
                androidx.appcompat.view.menu.c cVar = new androidx.appcompat.view.menu.c(this.f3237l, d.g.f8919j);
                this.f3236k = cVar;
                cVar.k(aVar);
                this.f3235j.b(this.f3236k);
            }
            return this.f3236k.b(this.f3232g);
        }

        public boolean b() {
            if (this.f3233h == null) {
                return false;
            }
            return this.f3234i != null || this.f3236k.a().getCount() > 0;
        }

        void c(androidx.appcompat.view.menu.e eVar) {
            androidx.appcompat.view.menu.c cVar;
            androidx.appcompat.view.menu.e eVar2 = this.f3235j;
            if (eVar == eVar2) {
                return;
            }
            if (eVar2 != null) {
                eVar2.P(this.f3236k);
            }
            this.f3235j = eVar;
            if (eVar == null || (cVar = this.f3236k) == null) {
                return;
            }
            eVar.b(cVar);
        }

        void d(Context context) {
            TypedValue typedValue = new TypedValue();
            Resources.Theme themeNewTheme = context.getResources().newTheme();
            themeNewTheme.setTo(context.getTheme());
            themeNewTheme.resolveAttribute(AbstractC0502a.f8789a, typedValue, true);
            int i3 = typedValue.resourceId;
            if (i3 != 0) {
                themeNewTheme.applyStyle(i3, true);
            }
            themeNewTheme.resolveAttribute(AbstractC0502a.f8781B, typedValue, true);
            int i4 = typedValue.resourceId;
            if (i4 != 0) {
                themeNewTheme.applyStyle(i4, true);
            } else {
                themeNewTheme.applyStyle(d.i.f8942b, true);
            }
            androidx.appcompat.view.d dVar = new androidx.appcompat.view.d(context, 0);
            dVar.getTheme().setTo(themeNewTheme);
            this.f3237l = dVar;
            TypedArray typedArrayObtainStyledAttributes = dVar.obtainStyledAttributes(d.j.f9139y0);
            this.f3227b = typedArrayObtainStyledAttributes.getResourceId(d.j.f8950B0, 0);
            this.f3231f = typedArrayObtainStyledAttributes.getResourceId(d.j.f8946A0, 0);
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    private final class r implements j.a {
        r() {
        }

        @Override // androidx.appcompat.view.menu.j.a
        public void c(androidx.appcompat.view.menu.e eVar, boolean z3) {
            androidx.appcompat.view.menu.e eVarD = eVar.D();
            boolean z4 = eVarD != eVar;
            h hVar = h.this;
            if (z4) {
                eVar = eVarD;
            }
            q qVarM0 = hVar.m0(eVar);
            if (qVarM0 != null) {
                if (!z4) {
                    h.this.c0(qVarM0, z3);
                } else {
                    h.this.Y(qVarM0.f3226a, qVarM0, eVarD);
                    h.this.c0(qVarM0, true);
                }
            }
        }

        @Override // androidx.appcompat.view.menu.j.a
        public boolean d(androidx.appcompat.view.menu.e eVar) {
            Window.Callback callbackV0;
            if (eVar != eVar.D()) {
                return true;
            }
            h hVar = h.this;
            if (!hVar.f3159H || (callbackV0 = hVar.v0()) == null || h.this.f3170S) {
                return true;
            }
            callbackV0.onMenuOpened(108, eVar);
            return true;
        }
    }

    h(Activity activity, androidx.appcompat.app.d dVar) {
        this(activity, null, dVar, activity);
    }

    private void A0(int i3) {
        this.f3179b0 = (1 << i3) | this.f3179b0;
        if (this.f3178a0) {
            return;
        }
        V.S(this.f3190m.getDecorView(), this.f3180c0);
        this.f3178a0 = true;
    }

    private boolean F0(int i3, KeyEvent keyEvent) {
        if (keyEvent.getRepeatCount() != 0) {
            return false;
        }
        q qVarT0 = t0(i3, true);
        if (qVarT0.f3240o) {
            return false;
        }
        return P0(qVarT0, keyEvent);
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0062  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean I0(int r5, android.view.KeyEvent r6) {
        /*
            r4 = this;
            androidx.appcompat.view.b r0 = r4.f3199v
            r1 = 0
            if (r0 == 0) goto L6
            return r1
        L6:
            r0 = 1
            androidx.appcompat.app.h$q r2 = r4.t0(r5, r0)
            if (r5 != 0) goto L43
            androidx.appcompat.widget.I r5 = r4.f3196s
            if (r5 == 0) goto L43
            boolean r5 = r5.h()
            if (r5 == 0) goto L43
            android.content.Context r5 = r4.f3189l
            android.view.ViewConfiguration r5 = android.view.ViewConfiguration.get(r5)
            boolean r5 = r5.hasPermanentMenuKey()
            if (r5 != 0) goto L43
            androidx.appcompat.widget.I r5 = r4.f3196s
            boolean r5 = r5.b()
            if (r5 != 0) goto L3c
            boolean r5 = r4.f3170S
            if (r5 != 0) goto L62
            boolean r5 = r4.P0(r2, r6)
            if (r5 == 0) goto L62
            androidx.appcompat.widget.I r5 = r4.f3196s
            boolean r0 = r5.g()
            goto L68
        L3c:
            androidx.appcompat.widget.I r5 = r4.f3196s
            boolean r0 = r5.f()
            goto L68
        L43:
            boolean r5 = r2.f3240o
            if (r5 != 0) goto L64
            boolean r3 = r2.f3239n
            if (r3 == 0) goto L4c
            goto L64
        L4c:
            boolean r5 = r2.f3238m
            if (r5 == 0) goto L62
            boolean r5 = r2.f3243r
            if (r5 == 0) goto L5b
            r2.f3238m = r1
            boolean r5 = r4.P0(r2, r6)
            goto L5c
        L5b:
            r5 = r0
        L5c:
            if (r5 == 0) goto L62
            r4.M0(r2, r6)
            goto L68
        L62:
            r0 = r1
            goto L68
        L64:
            r4.c0(r2, r0)
            r0 = r5
        L68:
            if (r0 == 0) goto L85
            android.content.Context r5 = r4.f3189l
            android.content.Context r5 = r5.getApplicationContext()
            java.lang.String r6 = "audio"
            java.lang.Object r5 = r5.getSystemService(r6)
            android.media.AudioManager r5 = (android.media.AudioManager) r5
            if (r5 == 0) goto L7e
            r5.playSoundEffect(r1)
            goto L85
        L7e:
            java.lang.String r5 = "AppCompatDelegate"
            java.lang.String r6 = "Couldn't get audio manager"
            android.util.Log.w(r5, r6)
        L85:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.h.I0(int, android.view.KeyEvent):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:64:0x00ed  */
    /* JADX WARN: Removed duplicated region for block: B:69:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void M0(androidx.appcompat.app.h.q r12, android.view.KeyEvent r13) {
        /*
            Method dump skipped, instruction units count: 244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.h.M0(androidx.appcompat.app.h$q, android.view.KeyEvent):void");
    }

    private boolean O0(q qVar, int i3, KeyEvent keyEvent, int i4) {
        androidx.appcompat.view.menu.e eVar;
        boolean zPerformShortcut = false;
        if (keyEvent.isSystem()) {
            return false;
        }
        if ((qVar.f3238m || P0(qVar, keyEvent)) && (eVar = qVar.f3235j) != null) {
            zPerformShortcut = eVar.performShortcut(i3, keyEvent, i4);
        }
        if (zPerformShortcut && (i4 & 1) == 0 && this.f3196s == null) {
            c0(qVar, true);
        }
        return zPerformShortcut;
    }

    private boolean P0(q qVar, KeyEvent keyEvent) {
        I i3;
        I i4;
        I i5;
        if (this.f3170S) {
            return false;
        }
        if (qVar.f3238m) {
            return true;
        }
        q qVar2 = this.f3166O;
        if (qVar2 != null && qVar2 != qVar) {
            c0(qVar2, false);
        }
        Window.Callback callbackV0 = v0();
        if (callbackV0 != null) {
            qVar.f3234i = callbackV0.onCreatePanelView(qVar.f3226a);
        }
        int i6 = qVar.f3226a;
        boolean z3 = i6 == 0 || i6 == 108;
        if (z3 && (i5 = this.f3196s) != null) {
            i5.d();
        }
        if (qVar.f3234i == null) {
            if (z3) {
                N0();
            }
            androidx.appcompat.view.menu.e eVar = qVar.f3235j;
            if (eVar == null || qVar.f3243r) {
                if (eVar == null && (!z0(qVar) || qVar.f3235j == null)) {
                    return false;
                }
                if (z3 && this.f3196s != null) {
                    if (this.f3197t == null) {
                        this.f3197t = new f();
                    }
                    this.f3196s.a(qVar.f3235j, this.f3197t);
                }
                qVar.f3235j.e0();
                if (!callbackV0.onCreatePanelMenu(qVar.f3226a, qVar.f3235j)) {
                    qVar.c(null);
                    if (z3 && (i3 = this.f3196s) != null) {
                        i3.a(null, this.f3197t);
                    }
                    return false;
                }
                qVar.f3243r = false;
            }
            qVar.f3235j.e0();
            Bundle bundle = qVar.f3244s;
            if (bundle != null) {
                qVar.f3235j.Q(bundle);
                qVar.f3244s = null;
            }
            if (!callbackV0.onPreparePanel(0, qVar.f3234i, qVar.f3235j)) {
                if (z3 && (i4 = this.f3196s) != null) {
                    i4.a(null, this.f3197t);
                }
                qVar.f3235j.d0();
                return false;
            }
            boolean z4 = KeyCharacterMap.load(keyEvent != null ? keyEvent.getDeviceId() : -1).getKeyboardType() != 1;
            qVar.f3241p = z4;
            qVar.f3235j.setQwertyMode(z4);
            qVar.f3235j.d0();
        }
        qVar.f3238m = true;
        qVar.f3239n = false;
        this.f3166O = qVar;
        return true;
    }

    private void Q0(boolean z3) {
        I i3 = this.f3196s;
        if (i3 == null || !i3.h() || (ViewConfiguration.get(this.f3189l).hasPermanentMenuKey() && !this.f3196s.e())) {
            q qVarT0 = t0(0, true);
            qVarT0.f3242q = true;
            c0(qVarT0, false);
            M0(qVarT0, null);
            return;
        }
        Window.Callback callbackV0 = v0();
        if (this.f3196s.b() && z3) {
            this.f3196s.f();
            if (this.f3170S) {
                return;
            }
            callbackV0.onPanelClosed(108, t0(0, true).f3235j);
            return;
        }
        if (callbackV0 == null || this.f3170S) {
            return;
        }
        if (this.f3178a0 && (this.f3179b0 & 1) != 0) {
            this.f3190m.getDecorView().removeCallbacks(this.f3180c0);
            this.f3180c0.run();
        }
        q qVarT02 = t0(0, true);
        androidx.appcompat.view.menu.e eVar = qVarT02.f3235j;
        if (eVar == null || qVarT02.f3243r || !callbackV0.onPreparePanel(0, qVarT02.f3234i, eVar)) {
            return;
        }
        callbackV0.onMenuOpened(108, qVarT02.f3235j);
        this.f3196s.g();
    }

    private int R0(int i3) {
        if (i3 == 8) {
            Log.i("AppCompatDelegate", "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR id when requesting this feature.");
            return 108;
        }
        if (i3 != 9) {
            return i3;
        }
        Log.i("AppCompatDelegate", "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR_OVERLAY id when requesting this feature.");
        return 109;
    }

    private boolean S(boolean z3) {
        return T(z3, true);
    }

    private boolean T(boolean z3, boolean z4) {
        if (this.f3170S) {
            return false;
        }
        int iX = X();
        int iC0 = C0(this.f3189l, iX);
        androidx.core.os.c cVarW = Build.VERSION.SDK_INT < 33 ? W(this.f3189l) : null;
        if (!z4 && cVarW != null) {
            cVarW = s0(this.f3189l.getResources().getConfiguration());
        }
        boolean zC1 = c1(iC0, cVarW, z3);
        if (iX == 0) {
            r0(this.f3189l).e();
        } else {
            n nVar = this.f3176Y;
            if (nVar != null) {
                nVar.a();
            }
        }
        if (iX == 3) {
            q0(this.f3189l).e();
        } else {
            n nVar2 = this.f3177Z;
            if (nVar2 != null) {
                nVar2.a();
            }
        }
        return zC1;
    }

    private void U() {
        ContentFrameLayout contentFrameLayout = (ContentFrameLayout) this.f3154C.findViewById(R.id.content);
        View decorView = this.f3190m.getDecorView();
        contentFrameLayout.a(decorView.getPaddingLeft(), decorView.getPaddingTop(), decorView.getPaddingRight(), decorView.getPaddingBottom());
        TypedArray typedArrayObtainStyledAttributes = this.f3189l.obtainStyledAttributes(d.j.f9139y0);
        typedArrayObtainStyledAttributes.getValue(d.j.f8986K0, contentFrameLayout.getMinWidthMajor());
        typedArrayObtainStyledAttributes.getValue(d.j.f8990L0, contentFrameLayout.getMinWidthMinor());
        if (typedArrayObtainStyledAttributes.hasValue(d.j.f8978I0)) {
            typedArrayObtainStyledAttributes.getValue(d.j.f8978I0, contentFrameLayout.getFixedWidthMajor());
        }
        if (typedArrayObtainStyledAttributes.hasValue(d.j.f8982J0)) {
            typedArrayObtainStyledAttributes.getValue(d.j.f8982J0, contentFrameLayout.getFixedWidthMinor());
        }
        if (typedArrayObtainStyledAttributes.hasValue(d.j.f8970G0)) {
            typedArrayObtainStyledAttributes.getValue(d.j.f8970G0, contentFrameLayout.getFixedHeightMajor());
        }
        if (typedArrayObtainStyledAttributes.hasValue(d.j.f8974H0)) {
            typedArrayObtainStyledAttributes.getValue(d.j.f8974H0, contentFrameLayout.getFixedHeightMinor());
        }
        typedArrayObtainStyledAttributes.recycle();
        contentFrameLayout.requestLayout();
    }

    private void V(Window window) {
        if (this.f3190m != null) {
            throw new IllegalStateException("AppCompat has already installed itself into the Window");
        }
        Window.Callback callback = window.getCallback();
        if (callback instanceof l) {
            throw new IllegalStateException("AppCompat has already installed itself into the Window");
        }
        l lVar = new l(callback);
        this.f3191n = lVar;
        window.setCallback(lVar);
        g0 g0VarT = g0.t(this.f3189l, null, f3150m0);
        Drawable drawableG = g0VarT.g(0);
        if (drawableG != null) {
            window.setBackgroundDrawable(drawableG);
        }
        g0VarT.w();
        this.f3190m = window;
        if (Build.VERSION.SDK_INT < 33 || this.f3186i0 != null) {
            return;
        }
        N(null);
    }

    private boolean V0(ViewParent viewParent) {
        if (viewParent == null) {
            return false;
        }
        View decorView = this.f3190m.getDecorView();
        while (viewParent != null) {
            if (viewParent == decorView || !(viewParent instanceof View) || ((View) viewParent).isAttachedToWindow()) {
                return false;
            }
            viewParent = viewParent.getParent();
        }
        return true;
    }

    private int X() {
        int i3 = this.f3172U;
        return i3 != -100 ? i3 : androidx.appcompat.app.f.o();
    }

    private void Z0() {
        if (this.f3153B) {
            throw new AndroidRuntimeException("Window feature must be requested before adding content");
        }
    }

    private void a0() {
        n nVar = this.f3176Y;
        if (nVar != null) {
            nVar.a();
        }
        n nVar2 = this.f3177Z;
        if (nVar2 != null) {
            nVar2.a();
        }
    }

    private androidx.appcompat.app.c a1() {
        for (Context baseContext = this.f3189l; baseContext != null; baseContext = ((ContextWrapper) baseContext).getBaseContext()) {
            if (baseContext instanceof androidx.appcompat.app.c) {
                return (androidx.appcompat.app.c) baseContext;
            }
            if (!(baseContext instanceof ContextWrapper)) {
                break;
            }
        }
        return null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private void b1(Configuration configuration) {
        Activity activity = (Activity) this.f3188k;
        if (activity instanceof androidx.lifecycle.k) {
            if (((androidx.lifecycle.k) activity).s().b().b(f.b.CREATED)) {
                activity.onConfigurationChanged(configuration);
            }
        } else {
            if (!this.f3169R || this.f3170S) {
                return;
            }
            activity.onConfigurationChanged(configuration);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x008c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean c1(int r10, androidx.core.os.c r11, boolean r12) {
        /*
            Method dump skipped, instruction units count: 203
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.h.c1(int, androidx.core.os.c, boolean):boolean");
    }

    private Configuration d0(Context context, int i3, androidx.core.os.c cVar, Configuration configuration, boolean z3) {
        int i4 = i3 != 1 ? i3 != 2 ? z3 ? 0 : context.getApplicationContext().getResources().getConfiguration().uiMode & 48 : 32 : 16;
        Configuration configuration2 = new Configuration();
        configuration2.fontScale = 0.0f;
        if (configuration != null) {
            configuration2.setTo(configuration);
        }
        configuration2.uiMode = i4 | (configuration2.uiMode & (-49));
        if (cVar != null) {
            S0(configuration2, cVar);
        }
        return configuration2;
    }

    private ViewGroup e0() {
        ViewGroup viewGroup;
        TypedArray typedArrayObtainStyledAttributes = this.f3189l.obtainStyledAttributes(d.j.f9139y0);
        if (!typedArrayObtainStyledAttributes.hasValue(d.j.f8958D0)) {
            typedArrayObtainStyledAttributes.recycle();
            throw new IllegalStateException("You need to use a Theme.AppCompat theme (or descendant) with this activity.");
        }
        if (typedArrayObtainStyledAttributes.getBoolean(d.j.f8994M0, false)) {
            I(1);
        } else if (typedArrayObtainStyledAttributes.getBoolean(d.j.f8958D0, false)) {
            I(108);
        }
        if (typedArrayObtainStyledAttributes.getBoolean(d.j.f8962E0, false)) {
            I(109);
        }
        if (typedArrayObtainStyledAttributes.getBoolean(d.j.f8966F0, false)) {
            I(10);
        }
        this.f3162K = typedArrayObtainStyledAttributes.getBoolean(d.j.f9143z0, false);
        typedArrayObtainStyledAttributes.recycle();
        l0();
        this.f3190m.getDecorView();
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(this.f3189l);
        if (this.f3163L) {
            viewGroup = this.f3161J ? (ViewGroup) layoutInflaterFrom.inflate(d.g.f8924o, (ViewGroup) null) : (ViewGroup) layoutInflaterFrom.inflate(d.g.f8923n, (ViewGroup) null);
        } else if (this.f3162K) {
            viewGroup = (ViewGroup) layoutInflaterFrom.inflate(d.g.f8915f, (ViewGroup) null);
            this.f3160I = false;
            this.f3159H = false;
        } else if (this.f3159H) {
            TypedValue typedValue = new TypedValue();
            this.f3189l.getTheme().resolveAttribute(AbstractC0502a.f8792d, typedValue, true);
            viewGroup = (ViewGroup) LayoutInflater.from(typedValue.resourceId != 0 ? new androidx.appcompat.view.d(this.f3189l, typedValue.resourceId) : this.f3189l).inflate(d.g.f8925p, (ViewGroup) null);
            I i3 = (I) viewGroup.findViewById(d.f.f8899p);
            this.f3196s = i3;
            i3.setWindowCallback(v0());
            if (this.f3160I) {
                this.f3196s.k(109);
            }
            if (this.f3157F) {
                this.f3196s.k(2);
            }
            if (this.f3158G) {
                this.f3196s.k(5);
            }
        } else {
            viewGroup = null;
        }
        if (viewGroup == null) {
            throw new IllegalArgumentException("AppCompat does not support the current theme features: { windowActionBar: " + this.f3159H + ", windowActionBarOverlay: " + this.f3160I + ", android:windowIsFloating: " + this.f3162K + ", windowActionModeOverlay: " + this.f3161J + ", windowNoTitle: " + this.f3163L + " }");
        }
        V.i0(viewGroup, new b());
        if (this.f3196s == null) {
            this.f3155D = (TextView) viewGroup.findViewById(d.f.f8880C);
        }
        r0.c(viewGroup);
        ContentFrameLayout contentFrameLayout = (ContentFrameLayout) viewGroup.findViewById(d.f.f8885b);
        ViewGroup viewGroup2 = (ViewGroup) this.f3190m.findViewById(R.id.content);
        if (viewGroup2 != null) {
            while (viewGroup2.getChildCount() > 0) {
                View childAt = viewGroup2.getChildAt(0);
                viewGroup2.removeViewAt(0);
                contentFrameLayout.addView(childAt);
            }
            viewGroup2.setId(-1);
            contentFrameLayout.setId(R.id.content);
            if (viewGroup2 instanceof FrameLayout) {
                ((FrameLayout) viewGroup2).setForeground(null);
            }
        }
        this.f3190m.setContentView(viewGroup);
        contentFrameLayout.setAttachListener(new c());
        return viewGroup;
    }

    private void e1(int i3, androidx.core.os.c cVar, boolean z3, Configuration configuration) {
        Resources resources = this.f3189l.getResources();
        Configuration configuration2 = new Configuration(resources.getConfiguration());
        if (configuration != null) {
            configuration2.updateFrom(configuration);
        }
        configuration2.uiMode = i3 | (resources.getConfiguration().uiMode & (-49));
        if (cVar != null) {
            S0(configuration2, cVar);
        }
        resources.updateConfiguration(configuration2, null);
        if (Build.VERSION.SDK_INT < 26) {
            w.a(resources);
        }
        int i4 = this.f3173V;
        if (i4 != 0) {
            this.f3189l.setTheme(i4);
            this.f3189l.getTheme().applyStyle(this.f3173V, true);
        }
        if (z3 && (this.f3188k instanceof Activity)) {
            b1(configuration2);
        }
    }

    private void g1(View view) {
        view.setBackgroundColor((V.B(view) & 8192) != 0 ? androidx.core.content.a.b(this.f3189l, d.c.f8817b) : androidx.core.content.a.b(this.f3189l, d.c.f8816a));
    }

    private void k0() {
        if (this.f3153B) {
            return;
        }
        this.f3154C = e0();
        CharSequence charSequenceU0 = u0();
        if (!TextUtils.isEmpty(charSequenceU0)) {
            I i3 = this.f3196s;
            if (i3 != null) {
                i3.setWindowTitle(charSequenceU0);
            } else if (N0() != null) {
                N0().t(charSequenceU0);
            } else {
                TextView textView = this.f3155D;
                if (textView != null) {
                    textView.setText(charSequenceU0);
                }
            }
        }
        U();
        L0(this.f3154C);
        this.f3153B = true;
        q qVarT0 = t0(0, false);
        if (this.f3170S) {
            return;
        }
        if (qVarT0 == null || qVarT0.f3235j == null) {
            A0(108);
        }
    }

    private void l0() {
        if (this.f3190m == null) {
            Object obj = this.f3188k;
            if (obj instanceof Activity) {
                V(((Activity) obj).getWindow());
            }
        }
        if (this.f3190m == null) {
            throw new IllegalStateException("We have not been given a Window");
        }
    }

    private static Configuration n0(Configuration configuration, Configuration configuration2) {
        Configuration configuration3 = new Configuration();
        configuration3.fontScale = 0.0f;
        if (configuration2 != null && configuration.diff(configuration2) != 0) {
            float f3 = configuration.fontScale;
            float f4 = configuration2.fontScale;
            if (f3 != f4) {
                configuration3.fontScale = f4;
            }
            int i3 = configuration.mcc;
            int i4 = configuration2.mcc;
            if (i3 != i4) {
                configuration3.mcc = i4;
            }
            int i5 = configuration.mnc;
            int i6 = configuration2.mnc;
            if (i5 != i6) {
                configuration3.mnc = i6;
            }
            int i7 = Build.VERSION.SDK_INT;
            i.a(configuration, configuration2, configuration3);
            int i8 = configuration.touchscreen;
            int i9 = configuration2.touchscreen;
            if (i8 != i9) {
                configuration3.touchscreen = i9;
            }
            int i10 = configuration.keyboard;
            int i11 = configuration2.keyboard;
            if (i10 != i11) {
                configuration3.keyboard = i11;
            }
            int i12 = configuration.keyboardHidden;
            int i13 = configuration2.keyboardHidden;
            if (i12 != i13) {
                configuration3.keyboardHidden = i13;
            }
            int i14 = configuration.navigation;
            int i15 = configuration2.navigation;
            if (i14 != i15) {
                configuration3.navigation = i15;
            }
            int i16 = configuration.navigationHidden;
            int i17 = configuration2.navigationHidden;
            if (i16 != i17) {
                configuration3.navigationHidden = i17;
            }
            int i18 = configuration.orientation;
            int i19 = configuration2.orientation;
            if (i18 != i19) {
                configuration3.orientation = i19;
            }
            int i20 = configuration.screenLayout & 15;
            int i21 = configuration2.screenLayout;
            if (i20 != (i21 & 15)) {
                configuration3.screenLayout |= i21 & 15;
            }
            int i22 = configuration.screenLayout & 192;
            int i23 = configuration2.screenLayout;
            if (i22 != (i23 & 192)) {
                configuration3.screenLayout |= i23 & 192;
            }
            int i24 = configuration.screenLayout & 48;
            int i25 = configuration2.screenLayout;
            if (i24 != (i25 & 48)) {
                configuration3.screenLayout |= i25 & 48;
            }
            int i26 = configuration.screenLayout & 768;
            int i27 = configuration2.screenLayout;
            if (i26 != (i27 & 768)) {
                configuration3.screenLayout |= i27 & 768;
            }
            if (i7 >= 26) {
                j.a(configuration, configuration2, configuration3);
            }
            int i28 = configuration.uiMode & 15;
            int i29 = configuration2.uiMode;
            if (i28 != (i29 & 15)) {
                configuration3.uiMode |= i29 & 15;
            }
            int i30 = configuration.uiMode & 48;
            int i31 = configuration2.uiMode;
            if (i30 != (i31 & 48)) {
                configuration3.uiMode |= i31 & 48;
            }
            int i32 = configuration.screenWidthDp;
            int i33 = configuration2.screenWidthDp;
            if (i32 != i33) {
                configuration3.screenWidthDp = i33;
            }
            int i34 = configuration.screenHeightDp;
            int i35 = configuration2.screenHeightDp;
            if (i34 != i35) {
                configuration3.screenHeightDp = i35;
            }
            int i36 = configuration.smallestScreenWidthDp;
            int i37 = configuration2.smallestScreenWidthDp;
            if (i36 != i37) {
                configuration3.smallestScreenWidthDp = i37;
            }
            int i38 = configuration.densityDpi;
            int i39 = configuration2.densityDpi;
            if (i38 != i39) {
                configuration3.densityDpi = i39;
            }
        }
        return configuration3;
    }

    private int p0(Context context) {
        if (!this.f3175X && (this.f3188k instanceof Activity)) {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager == null) {
                return 0;
            }
            try {
                ActivityInfo activityInfo = packageManager.getActivityInfo(new ComponentName(context, this.f3188k.getClass()), Build.VERSION.SDK_INT >= 29 ? 269221888 : 786432);
                if (activityInfo != null) {
                    this.f3174W = activityInfo.configChanges;
                }
            } catch (PackageManager.NameNotFoundException e3) {
                Log.d("AppCompatDelegate", "Exception while getting ActivityInfo", e3);
                this.f3174W = 0;
            }
        }
        this.f3175X = true;
        return this.f3174W;
    }

    private n q0(Context context) {
        if (this.f3177Z == null) {
            this.f3177Z = new m(context);
        }
        return this.f3177Z;
    }

    private n r0(Context context) {
        if (this.f3176Y == null) {
            this.f3176Y = new o(y.a(context));
        }
        return this.f3176Y;
    }

    private void w0() {
        k0();
        if (this.f3159H && this.f3193p == null) {
            Object obj = this.f3188k;
            if (obj instanceof Activity) {
                this.f3193p = new z((Activity) this.f3188k, this.f3160I);
            } else if (obj instanceof Dialog) {
                this.f3193p = new z((Dialog) this.f3188k);
            }
            androidx.appcompat.app.a aVar = this.f3193p;
            if (aVar != null) {
                aVar.r(this.f3181d0);
            }
        }
    }

    private boolean x0(q qVar) {
        View view = qVar.f3234i;
        if (view != null) {
            qVar.f3233h = view;
            return true;
        }
        if (qVar.f3235j == null) {
            return false;
        }
        if (this.f3198u == null) {
            this.f3198u = new r();
        }
        View view2 = (View) qVar.a(this.f3198u);
        qVar.f3233h = view2;
        return view2 != null;
    }

    private boolean y0(q qVar) {
        qVar.d(o0());
        qVar.f3232g = new p(qVar.f3237l);
        qVar.f3228c = 81;
        return true;
    }

    private boolean z0(q qVar) {
        Resources.Theme themeNewTheme;
        Context context = this.f3189l;
        int i3 = qVar.f3226a;
        if ((i3 == 0 || i3 == 108) && this.f3196s != null) {
            TypedValue typedValue = new TypedValue();
            Resources.Theme theme = context.getTheme();
            theme.resolveAttribute(AbstractC0502a.f8792d, typedValue, true);
            if (typedValue.resourceId != 0) {
                themeNewTheme = context.getResources().newTheme();
                themeNewTheme.setTo(theme);
                themeNewTheme.applyStyle(typedValue.resourceId, true);
                themeNewTheme.resolveAttribute(AbstractC0502a.f8793e, typedValue, true);
            } else {
                theme.resolveAttribute(AbstractC0502a.f8793e, typedValue, true);
                themeNewTheme = null;
            }
            if (typedValue.resourceId != 0) {
                if (themeNewTheme == null) {
                    themeNewTheme = context.getResources().newTheme();
                    themeNewTheme.setTo(theme);
                }
                themeNewTheme.applyStyle(typedValue.resourceId, true);
            }
            if (themeNewTheme != null) {
                androidx.appcompat.view.d dVar = new androidx.appcompat.view.d(context, 0);
                dVar.getTheme().setTo(themeNewTheme);
                context = dVar;
            }
        }
        androidx.appcompat.view.menu.e eVar = new androidx.appcompat.view.menu.e(context);
        eVar.S(this);
        qVar.c(eVar);
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0045  */
    @Override // androidx.appcompat.app.f
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void A() {
        /*
            r3 = this;
            java.lang.Object r0 = r3.f3188k
            boolean r0 = r0 instanceof android.app.Activity
            if (r0 == 0) goto L9
            androidx.appcompat.app.f.G(r3)
        L9:
            boolean r0 = r3.f3178a0
            if (r0 == 0) goto L18
            android.view.Window r0 = r3.f3190m
            android.view.View r0 = r0.getDecorView()
            java.lang.Runnable r1 = r3.f3180c0
            r0.removeCallbacks(r1)
        L18:
            r0 = 1
            r3.f3170S = r0
            int r0 = r3.f3172U
            r1 = -100
            if (r0 == r1) goto L45
            java.lang.Object r0 = r3.f3188k
            boolean r1 = r0 instanceof android.app.Activity
            if (r1 == 0) goto L45
            android.app.Activity r0 = (android.app.Activity) r0
            boolean r0 = r0.isChangingConfigurations()
            if (r0 == 0) goto L45
            l.g r0 = androidx.appcompat.app.h.f3148k0
            java.lang.Object r1 = r3.f3188k
            java.lang.Class r1 = r1.getClass()
            java.lang.String r1 = r1.getName()
            int r2 = r3.f3172U
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            r0.put(r1, r2)
            goto L54
        L45:
            l.g r0 = androidx.appcompat.app.h.f3148k0
            java.lang.Object r1 = r3.f3188k
            java.lang.Class r1 = r1.getClass()
            java.lang.String r1 = r1.getName()
            r0.remove(r1)
        L54:
            androidx.appcompat.app.a r0 = r3.f3193p
            if (r0 == 0) goto L5b
            r0.n()
        L5b:
            r3.a0()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.h.A():void");
    }

    @Override // androidx.appcompat.app.f
    public void B(Bundle bundle) {
        k0();
    }

    public boolean B0() {
        return this.f3152A;
    }

    @Override // androidx.appcompat.app.f
    public void C() {
        androidx.appcompat.app.a aVarT = t();
        if (aVarT != null) {
            aVarT.s(true);
        }
    }

    int C0(Context context, int i3) {
        if (i3 == -100) {
            return -1;
        }
        if (i3 != -1) {
            if (i3 == 0) {
                if (((UiModeManager) context.getApplicationContext().getSystemService("uimode")).getNightMode() == 0) {
                    return -1;
                }
                return r0(context).c();
            }
            if (i3 != 1 && i3 != 2) {
                if (i3 == 3) {
                    return q0(context).c();
                }
                throw new IllegalStateException("Unknown value set for night mode. Please use one of the MODE_NIGHT values from AppCompatDelegate.");
            }
        }
        return i3;
    }

    @Override // androidx.appcompat.app.f
    public void D(Bundle bundle) {
    }

    boolean D0() {
        boolean z3 = this.f3167P;
        this.f3167P = false;
        q qVarT0 = t0(0, false);
        if (qVarT0 != null && qVarT0.f3240o) {
            if (!z3) {
                c0(qVarT0, true);
            }
            return true;
        }
        androidx.appcompat.view.b bVar = this.f3199v;
        if (bVar != null) {
            bVar.c();
            return true;
        }
        androidx.appcompat.app.a aVarT = t();
        return aVarT != null && aVarT.h();
    }

    @Override // androidx.appcompat.app.f
    public void E() {
        T(true, false);
    }

    boolean E0(int i3, KeyEvent keyEvent) {
        if (i3 == 4) {
            this.f3167P = (keyEvent.getFlags() & 128) != 0;
        } else if (i3 == 82) {
            F0(0, keyEvent);
            return true;
        }
        return false;
    }

    @Override // androidx.appcompat.app.f
    public void F() {
        androidx.appcompat.app.a aVarT = t();
        if (aVarT != null) {
            aVarT.s(false);
        }
    }

    boolean G0(int i3, KeyEvent keyEvent) {
        androidx.appcompat.app.a aVarT = t();
        if (aVarT != null && aVarT.o(i3, keyEvent)) {
            return true;
        }
        q qVar = this.f3166O;
        if (qVar != null && O0(qVar, keyEvent.getKeyCode(), keyEvent, 1)) {
            q qVar2 = this.f3166O;
            if (qVar2 != null) {
                qVar2.f3239n = true;
            }
            return true;
        }
        if (this.f3166O == null) {
            q qVarT0 = t0(0, true);
            P0(qVarT0, keyEvent);
            boolean zO0 = O0(qVarT0, keyEvent.getKeyCode(), keyEvent, 1);
            qVarT0.f3238m = false;
            if (zO0) {
                return true;
            }
        }
        return false;
    }

    boolean H0(int i3, KeyEvent keyEvent) {
        if (i3 != 4) {
            if (i3 == 82) {
                I0(0, keyEvent);
                return true;
            }
        } else if (D0()) {
            return true;
        }
        return false;
    }

    @Override // androidx.appcompat.app.f
    public boolean I(int i3) {
        int iR0 = R0(i3);
        if (this.f3163L && iR0 == 108) {
            return false;
        }
        if (this.f3159H && iR0 == 1) {
            this.f3159H = false;
        }
        if (iR0 == 1) {
            Z0();
            this.f3163L = true;
            return true;
        }
        if (iR0 == 2) {
            Z0();
            this.f3157F = true;
            return true;
        }
        if (iR0 == 5) {
            Z0();
            this.f3158G = true;
            return true;
        }
        if (iR0 == 10) {
            Z0();
            this.f3161J = true;
            return true;
        }
        if (iR0 == 108) {
            Z0();
            this.f3159H = true;
            return true;
        }
        if (iR0 != 109) {
            return this.f3190m.requestFeature(iR0);
        }
        Z0();
        this.f3160I = true;
        return true;
    }

    @Override // androidx.appcompat.app.f
    public void J(int i3) {
        k0();
        ViewGroup viewGroup = (ViewGroup) this.f3154C.findViewById(R.id.content);
        viewGroup.removeAllViews();
        LayoutInflater.from(this.f3189l).inflate(i3, viewGroup);
        this.f3191n.c(this.f3190m.getCallback());
    }

    void J0(int i3) {
        androidx.appcompat.app.a aVarT;
        if (i3 != 108 || (aVarT = t()) == null) {
            return;
        }
        aVarT.i(true);
    }

    @Override // androidx.appcompat.app.f
    public void K(View view) {
        k0();
        ViewGroup viewGroup = (ViewGroup) this.f3154C.findViewById(R.id.content);
        viewGroup.removeAllViews();
        viewGroup.addView(view);
        this.f3191n.c(this.f3190m.getCallback());
    }

    void K0(int i3) {
        if (i3 == 108) {
            androidx.appcompat.app.a aVarT = t();
            if (aVarT != null) {
                aVarT.i(false);
                return;
            }
            return;
        }
        if (i3 == 0) {
            q qVarT0 = t0(i3, true);
            if (qVarT0.f3240o) {
                c0(qVarT0, false);
            }
        }
    }

    @Override // androidx.appcompat.app.f
    public void L(View view, ViewGroup.LayoutParams layoutParams) {
        k0();
        ViewGroup viewGroup = (ViewGroup) this.f3154C.findViewById(R.id.content);
        viewGroup.removeAllViews();
        viewGroup.addView(view, layoutParams);
        this.f3191n.c(this.f3190m.getCallback());
    }

    void L0(ViewGroup viewGroup) {
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002c  */
    @Override // androidx.appcompat.app.f
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void N(android.window.OnBackInvokedDispatcher r3) {
        /*
            r2 = this;
            super.N(r3)
            android.window.OnBackInvokedDispatcher r0 = r2.f3186i0
            if (r0 == 0) goto L11
            android.window.OnBackInvokedCallback r1 = r2.f3187j0
            if (r1 == 0) goto L11
            androidx.appcompat.app.h.k.c(r0, r1)
            r0 = 0
            r2.f3187j0 = r0
        L11:
            if (r3 != 0) goto L2c
            java.lang.Object r0 = r2.f3188k
            boolean r1 = r0 instanceof android.app.Activity
            if (r1 == 0) goto L2c
            android.app.Activity r0 = (android.app.Activity) r0
            android.view.Window r0 = r0.getWindow()
            if (r0 == 0) goto L2c
            java.lang.Object r3 = r2.f3188k
            android.app.Activity r3 = (android.app.Activity) r3
            android.window.OnBackInvokedDispatcher r3 = androidx.appcompat.app.h.k.a(r3)
            r2.f3186i0 = r3
            goto L2e
        L2c:
            r2.f3186i0 = r3
        L2e:
            r2.d1()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.h.N(android.window.OnBackInvokedDispatcher):void");
    }

    final androidx.appcompat.app.a N0() {
        return this.f3193p;
    }

    @Override // androidx.appcompat.app.f
    public void O(int i3) {
        this.f3173V = i3;
    }

    @Override // androidx.appcompat.app.f
    public final void P(CharSequence charSequence) {
        this.f3195r = charSequence;
        I i3 = this.f3196s;
        if (i3 != null) {
            i3.setWindowTitle(charSequence);
            return;
        }
        if (N0() != null) {
            N0().t(charSequence);
            return;
        }
        TextView textView = this.f3155D;
        if (textView != null) {
            textView.setText(charSequence);
        }
    }

    void S0(Configuration configuration, androidx.core.os.c cVar) {
        i.d(configuration, cVar);
    }

    void T0(androidx.core.os.c cVar) {
        i.c(cVar);
    }

    final boolean U0() {
        ViewGroup viewGroup;
        return this.f3153B && (viewGroup = this.f3154C) != null && viewGroup.isLaidOut();
    }

    androidx.core.os.c W(Context context) {
        androidx.core.os.c cVarS;
        if (Build.VERSION.SDK_INT >= 33 || (cVarS = androidx.appcompat.app.f.s()) == null) {
            return null;
        }
        androidx.core.os.c cVarS0 = s0(context.getApplicationContext().getResources().getConfiguration());
        androidx.core.os.c cVarB = v.b(cVarS, cVarS0);
        return cVarB.e() ? cVarS0 : cVarB;
    }

    boolean W0() {
        if (this.f3186i0 == null) {
            return false;
        }
        q qVarT0 = t0(0, false);
        return (qVarT0 != null && qVarT0.f3240o) || this.f3199v != null;
    }

    public androidx.appcompat.view.b X0(b.a aVar) {
        androidx.appcompat.app.d dVar;
        if (aVar == null) {
            throw new IllegalArgumentException("ActionMode callback can not be null.");
        }
        androidx.appcompat.view.b bVar = this.f3199v;
        if (bVar != null) {
            bVar.c();
        }
        g gVar = new g(aVar);
        androidx.appcompat.app.a aVarT = t();
        if (aVarT != null) {
            androidx.appcompat.view.b bVarU = aVarT.u(gVar);
            this.f3199v = bVarU;
            if (bVarU != null && (dVar = this.f3192o) != null) {
                dVar.f(bVarU);
            }
        }
        if (this.f3199v == null) {
            this.f3199v = Y0(gVar);
        }
        d1();
        return this.f3199v;
    }

    void Y(int i3, q qVar, Menu menu) {
        if (menu == null) {
            if (qVar == null && i3 >= 0) {
                q[] qVarArr = this.f3165N;
                if (i3 < qVarArr.length) {
                    qVar = qVarArr[i3];
                }
            }
            if (qVar != null) {
                menu = qVar.f3235j;
            }
        }
        if ((qVar == null || qVar.f3240o) && !this.f3170S) {
            this.f3191n.d(this.f3190m.getCallback(), i3, menu);
        }
    }

    androidx.appcompat.view.b Y0(b.a aVar) {
        androidx.appcompat.view.b bVarV;
        Context dVar;
        androidx.appcompat.app.d dVar2;
        j0();
        androidx.appcompat.view.b bVar = this.f3199v;
        if (bVar != null) {
            bVar.c();
        }
        if (!(aVar instanceof g)) {
            aVar = new g(aVar);
        }
        androidx.appcompat.app.d dVar3 = this.f3192o;
        if (dVar3 == null || this.f3170S) {
            bVarV = null;
        } else {
            try {
                bVarV = dVar3.v(aVar);
            } catch (AbstractMethodError unused) {
                bVarV = null;
            }
        }
        if (bVarV != null) {
            this.f3199v = bVarV;
        } else {
            if (this.f3200w == null) {
                if (this.f3162K) {
                    TypedValue typedValue = new TypedValue();
                    Resources.Theme theme = this.f3189l.getTheme();
                    theme.resolveAttribute(AbstractC0502a.f8792d, typedValue, true);
                    if (typedValue.resourceId != 0) {
                        Resources.Theme themeNewTheme = this.f3189l.getResources().newTheme();
                        themeNewTheme.setTo(theme);
                        themeNewTheme.applyStyle(typedValue.resourceId, true);
                        dVar = new androidx.appcompat.view.d(this.f3189l, 0);
                        dVar.getTheme().setTo(themeNewTheme);
                    } else {
                        dVar = this.f3189l;
                    }
                    this.f3200w = new ActionBarContextView(dVar);
                    PopupWindow popupWindow = new PopupWindow(dVar, (AttributeSet) null, AbstractC0502a.f8794f);
                    this.f3201x = popupWindow;
                    androidx.core.widget.h.b(popupWindow, 2);
                    this.f3201x.setContentView(this.f3200w);
                    this.f3201x.setWidth(-1);
                    dVar.getTheme().resolveAttribute(AbstractC0502a.f8790b, typedValue, true);
                    this.f3200w.setContentHeight(TypedValue.complexToDimensionPixelSize(typedValue.data, dVar.getResources().getDisplayMetrics()));
                    this.f3201x.setHeight(-2);
                    this.f3202y = new d();
                } else {
                    ViewStubCompat viewStubCompat = (ViewStubCompat) this.f3154C.findViewById(d.f.f8891h);
                    if (viewStubCompat != null) {
                        viewStubCompat.setLayoutInflater(LayoutInflater.from(o0()));
                        this.f3200w = (ActionBarContextView) viewStubCompat.a();
                    }
                }
            }
            if (this.f3200w != null) {
                j0();
                this.f3200w.k();
                androidx.appcompat.view.e eVar = new androidx.appcompat.view.e(this.f3200w.getContext(), this.f3200w, aVar, this.f3201x == null);
                if (aVar.d(eVar, eVar.e())) {
                    eVar.k();
                    this.f3200w.h(eVar);
                    this.f3199v = eVar;
                    if (U0()) {
                        this.f3200w.setAlpha(0.0f);
                        C0261e0 c0261e0B = V.c(this.f3200w).b(1.0f);
                        this.f3203z = c0261e0B;
                        c0261e0B.h(new e());
                    } else {
                        this.f3200w.setAlpha(1.0f);
                        this.f3200w.setVisibility(0);
                        if (this.f3200w.getParent() instanceof View) {
                            V.U((View) this.f3200w.getParent());
                        }
                    }
                    if (this.f3201x != null) {
                        this.f3190m.getDecorView().post(this.f3202y);
                    }
                } else {
                    this.f3199v = null;
                }
            }
        }
        androidx.appcompat.view.b bVar2 = this.f3199v;
        if (bVar2 != null && (dVar2 = this.f3192o) != null) {
            dVar2.f(bVar2);
        }
        d1();
        return this.f3199v;
    }

    void Z(androidx.appcompat.view.menu.e eVar) {
        if (this.f3164M) {
            return;
        }
        this.f3164M = true;
        this.f3196s.l();
        Window.Callback callbackV0 = v0();
        if (callbackV0 != null && !this.f3170S) {
            callbackV0.onPanelClosed(108, eVar);
        }
        this.f3164M = false;
    }

    @Override // androidx.appcompat.view.menu.e.a
    public boolean a(androidx.appcompat.view.menu.e eVar, MenuItem menuItem) {
        q qVarM0;
        Window.Callback callbackV0 = v0();
        if (callbackV0 == null || this.f3170S || (qVarM0 = m0(eVar.D())) == null) {
            return false;
        }
        return callbackV0.onMenuItemSelected(qVarM0.f3226a, menuItem);
    }

    @Override // androidx.appcompat.view.menu.e.a
    public void b(androidx.appcompat.view.menu.e eVar) {
        Q0(true);
    }

    void b0(int i3) {
        c0(t0(i3, true), true);
    }

    void c0(q qVar, boolean z3) {
        ViewGroup viewGroup;
        I i3;
        if (z3 && qVar.f3226a == 0 && (i3 = this.f3196s) != null && i3.b()) {
            Z(qVar.f3235j);
            return;
        }
        WindowManager windowManager = (WindowManager) this.f3189l.getSystemService("window");
        if (windowManager != null && qVar.f3240o && (viewGroup = qVar.f3232g) != null) {
            windowManager.removeView(viewGroup);
            if (z3) {
                Y(qVar.f3226a, qVar, null);
            }
        }
        qVar.f3238m = false;
        qVar.f3239n = false;
        qVar.f3240o = false;
        qVar.f3233h = null;
        qVar.f3242q = true;
        if (this.f3166O == qVar) {
            this.f3166O = null;
        }
        if (qVar.f3226a == 0) {
            d1();
        }
    }

    void d1() {
        OnBackInvokedCallback onBackInvokedCallback;
        if (Build.VERSION.SDK_INT >= 33) {
            boolean zW0 = W0();
            if (zW0 && this.f3187j0 == null) {
                this.f3187j0 = k.b(this.f3186i0, this);
            } else {
                if (zW0 || (onBackInvokedCallback = this.f3187j0) == null) {
                    return;
                }
                k.c(this.f3186i0, onBackInvokedCallback);
                this.f3187j0 = null;
            }
        }
    }

    @Override // androidx.appcompat.app.f
    public void e(View view, ViewGroup.LayoutParams layoutParams) {
        k0();
        ((ViewGroup) this.f3154C.findViewById(R.id.content)).addView(view, layoutParams);
        this.f3191n.c(this.f3190m.getCallback());
    }

    @Override // androidx.appcompat.app.f
    public boolean f() {
        return S(true);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public View f0(View view, String str, Context context, AttributeSet attributeSet) {
        boolean z3;
        boolean zV0 = false;
        if (this.f3184g0 == null) {
            TypedArray typedArrayObtainStyledAttributes = this.f3189l.obtainStyledAttributes(d.j.f9139y0);
            String string = typedArrayObtainStyledAttributes.getString(d.j.f8954C0);
            typedArrayObtainStyledAttributes.recycle();
            if (string == null) {
                this.f3184g0 = new s();
            } else {
                try {
                    this.f3184g0 = (s) this.f3189l.getClassLoader().loadClass(string).getDeclaredConstructor(new Class[0]).newInstance(new Object[0]);
                } catch (Throwable th) {
                    Log.i("AppCompatDelegate", "Failed to instantiate custom view inflater " + string + ". Falling back to default.", th);
                    this.f3184g0 = new s();
                }
            }
        }
        boolean z4 = f3149l0;
        if (z4) {
            if (this.f3185h0 == null) {
                this.f3185h0 = new u();
            }
            if (this.f3185h0.a(attributeSet)) {
                z3 = true;
            } else {
                if (!(attributeSet instanceof XmlPullParser)) {
                    zV0 = V0((ViewParent) view);
                } else if (((XmlPullParser) attributeSet).getDepth() > 1) {
                    zV0 = true;
                }
                z3 = zV0;
            }
        } else {
            z3 = zV0;
        }
        return this.f3184g0.r(view, str, context, attributeSet, z3, z4, true, q0.c());
    }

    final int f1(C0271j0 c0271j0, Rect rect) {
        boolean z3;
        boolean z4;
        int iK = c0271j0 != null ? c0271j0.k() : rect != null ? rect.top : 0;
        ActionBarContextView actionBarContextView = this.f3200w;
        if (actionBarContextView == null || !(actionBarContextView.getLayoutParams() instanceof ViewGroup.MarginLayoutParams)) {
            z3 = false;
        } else {
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) this.f3200w.getLayoutParams();
            if (this.f3200w.isShown()) {
                if (this.f3182e0 == null) {
                    this.f3182e0 = new Rect();
                    this.f3183f0 = new Rect();
                }
                Rect rect2 = this.f3182e0;
                Rect rect3 = this.f3183f0;
                if (c0271j0 == null) {
                    rect2.set(rect);
                } else {
                    rect2.set(c0271j0.i(), c0271j0.k(), c0271j0.j(), c0271j0.h());
                }
                r0.a(this.f3154C, rect2, rect3);
                int i3 = rect2.top;
                int i4 = rect2.left;
                int i5 = rect2.right;
                C0271j0 c0271j0Y = V.y(this.f3154C);
                int i6 = c0271j0Y == null ? 0 : c0271j0Y.i();
                int iJ = c0271j0Y == null ? 0 : c0271j0Y.j();
                if (marginLayoutParams.topMargin == i3 && marginLayoutParams.leftMargin == i4 && marginLayoutParams.rightMargin == i5) {
                    z4 = false;
                } else {
                    marginLayoutParams.topMargin = i3;
                    marginLayoutParams.leftMargin = i4;
                    marginLayoutParams.rightMargin = i5;
                    z4 = true;
                }
                if (i3 <= 0 || this.f3156E != null) {
                    View view = this.f3156E;
                    if (view != null) {
                        ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) view.getLayoutParams();
                        int i7 = marginLayoutParams2.height;
                        int i8 = marginLayoutParams.topMargin;
                        if (i7 != i8 || marginLayoutParams2.leftMargin != i6 || marginLayoutParams2.rightMargin != iJ) {
                            marginLayoutParams2.height = i8;
                            marginLayoutParams2.leftMargin = i6;
                            marginLayoutParams2.rightMargin = iJ;
                            this.f3156E.setLayoutParams(marginLayoutParams2);
                        }
                    }
                } else {
                    View view2 = new View(this.f3189l);
                    this.f3156E = view2;
                    view2.setVisibility(8);
                    FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, marginLayoutParams.topMargin, 51);
                    layoutParams.leftMargin = i6;
                    layoutParams.rightMargin = iJ;
                    this.f3154C.addView(this.f3156E, -1, layoutParams);
                }
                View view3 = this.f3156E;
                z = view3 != null;
                if (z && view3.getVisibility() != 0) {
                    g1(this.f3156E);
                }
                if (!this.f3161J && z) {
                    iK = 0;
                }
                z3 = z;
                z = z4;
            } else if (marginLayoutParams.topMargin != 0) {
                marginLayoutParams.topMargin = 0;
                z3 = false;
            } else {
                z3 = false;
                z = false;
            }
            if (z) {
                this.f3200w.setLayoutParams(marginLayoutParams);
            }
        }
        View view4 = this.f3156E;
        if (view4 != null) {
            view4.setVisibility(z3 ? 0 : 8);
        }
        return iK;
    }

    void g0() {
        androidx.appcompat.view.menu.e eVar;
        I i3 = this.f3196s;
        if (i3 != null) {
            i3.l();
        }
        if (this.f3201x != null) {
            this.f3190m.getDecorView().removeCallbacks(this.f3202y);
            if (this.f3201x.isShowing()) {
                try {
                    this.f3201x.dismiss();
                } catch (IllegalArgumentException unused) {
                }
            }
            this.f3201x = null;
        }
        j0();
        q qVarT0 = t0(0, false);
        if (qVarT0 == null || (eVar = qVarT0.f3235j) == null) {
            return;
        }
        eVar.close();
    }

    boolean h0(KeyEvent keyEvent) {
        View decorView;
        Object obj = this.f3188k;
        if (((obj instanceof AbstractC0282t.a) || (obj instanceof androidx.appcompat.app.r)) && (decorView = this.f3190m.getDecorView()) != null && AbstractC0282t.d(decorView, keyEvent)) {
            return true;
        }
        if (keyEvent.getKeyCode() == 82 && this.f3191n.b(this.f3190m.getCallback(), keyEvent)) {
            return true;
        }
        int keyCode = keyEvent.getKeyCode();
        return keyEvent.getAction() == 0 ? E0(keyCode, keyEvent) : H0(keyCode, keyEvent);
    }

    @Override // androidx.appcompat.app.f
    public Context i(Context context) {
        this.f3168Q = true;
        int iC0 = C0(context, X());
        if (androidx.appcompat.app.f.w(context)) {
            androidx.appcompat.app.f.R(context);
        }
        androidx.core.os.c cVarW = W(context);
        if (context instanceof ContextThemeWrapper) {
            try {
                ((ContextThemeWrapper) context).applyOverrideConfiguration(d0(context, iC0, cVarW, null, false));
                return context;
            } catch (IllegalStateException unused) {
            }
        }
        if (context instanceof androidx.appcompat.view.d) {
            try {
                ((androidx.appcompat.view.d) context).a(d0(context, iC0, cVarW, null, false));
                return context;
            } catch (IllegalStateException unused2) {
            }
        }
        if (!f3151n0) {
            return super.i(context);
        }
        Configuration configuration = new Configuration();
        configuration.uiMode = -1;
        configuration.fontScale = 0.0f;
        Configuration configuration2 = context.createConfigurationContext(configuration).getResources().getConfiguration();
        Configuration configuration3 = context.getResources().getConfiguration();
        configuration2.uiMode = configuration3.uiMode;
        Configuration configurationD0 = d0(context, iC0, cVarW, !configuration2.equals(configuration3) ? n0(configuration2, configuration3) : null, true);
        androidx.appcompat.view.d dVar = new androidx.appcompat.view.d(context, d.i.f8943c);
        dVar.a(configurationD0);
        try {
            if (context.getTheme() != null) {
                f.C0059f.a(dVar.getTheme());
            }
        } catch (NullPointerException unused3) {
        }
        return super.i(dVar);
    }

    void i0(int i3) {
        q qVarT0;
        q qVarT02 = t0(i3, true);
        if (qVarT02.f3235j != null) {
            Bundle bundle = new Bundle();
            qVarT02.f3235j.R(bundle);
            if (bundle.size() > 0) {
                qVarT02.f3244s = bundle;
            }
            qVarT02.f3235j.e0();
            qVarT02.f3235j.clear();
        }
        qVarT02.f3243r = true;
        qVarT02.f3242q = true;
        if ((i3 != 108 && i3 != 0) || this.f3196s == null || (qVarT0 = t0(0, false)) == null) {
            return;
        }
        qVarT0.f3238m = false;
        P0(qVarT0, null);
    }

    void j0() {
        C0261e0 c0261e0 = this.f3203z;
        if (c0261e0 != null) {
            c0261e0.c();
        }
    }

    @Override // androidx.appcompat.app.f
    public View l(int i3) {
        k0();
        return this.f3190m.findViewById(i3);
    }

    q m0(Menu menu) {
        q[] qVarArr = this.f3165N;
        int length = qVarArr != null ? qVarArr.length : 0;
        for (int i3 = 0; i3 < length; i3++) {
            q qVar = qVarArr[i3];
            if (qVar != null && qVar.f3235j == menu) {
                return qVar;
            }
        }
        return null;
    }

    @Override // androidx.appcompat.app.f
    public Context n() {
        return this.f3189l;
    }

    final Context o0() {
        androidx.appcompat.app.a aVarT = t();
        Context contextK = aVarT != null ? aVarT.k() : null;
        return contextK == null ? this.f3189l : contextK;
    }

    @Override // android.view.LayoutInflater.Factory2
    public final View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        return f0(view, str, context, attributeSet);
    }

    @Override // androidx.appcompat.app.f
    public int p() {
        return this.f3172U;
    }

    @Override // androidx.appcompat.app.f
    public MenuInflater r() {
        if (this.f3194q == null) {
            w0();
            androidx.appcompat.app.a aVar = this.f3193p;
            this.f3194q = new androidx.appcompat.view.g(aVar != null ? aVar.k() : this.f3189l);
        }
        return this.f3194q;
    }

    androidx.core.os.c s0(Configuration configuration) {
        return i.b(configuration);
    }

    @Override // androidx.appcompat.app.f
    public androidx.appcompat.app.a t() {
        w0();
        return this.f3193p;
    }

    protected q t0(int i3, boolean z3) {
        q[] qVarArr = this.f3165N;
        if (qVarArr == null || qVarArr.length <= i3) {
            q[] qVarArr2 = new q[i3 + 1];
            if (qVarArr != null) {
                System.arraycopy(qVarArr, 0, qVarArr2, 0, qVarArr.length);
            }
            this.f3165N = qVarArr2;
            qVarArr = qVarArr2;
        }
        q qVar = qVarArr[i3];
        if (qVar != null) {
            return qVar;
        }
        q qVar2 = new q(i3);
        qVarArr[i3] = qVar2;
        return qVar2;
    }

    @Override // androidx.appcompat.app.f
    public void u() {
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(this.f3189l);
        if (layoutInflaterFrom.getFactory() == null) {
            AbstractC0283u.a(layoutInflaterFrom, this);
        } else {
            if (layoutInflaterFrom.getFactory2() instanceof h) {
                return;
            }
            Log.i("AppCompatDelegate", "The Activity's LayoutInflater already has a Factory installed so we can not install AppCompat's");
        }
    }

    final CharSequence u0() {
        Object obj = this.f3188k;
        return obj instanceof Activity ? ((Activity) obj).getTitle() : this.f3195r;
    }

    @Override // androidx.appcompat.app.f
    public void v() {
        if (N0() == null || t().l()) {
            return;
        }
        A0(0);
    }

    final Window.Callback v0() {
        return this.f3190m.getCallback();
    }

    @Override // androidx.appcompat.app.f
    public void y(Configuration configuration) {
        androidx.appcompat.app.a aVarT;
        if (this.f3159H && this.f3153B && (aVarT = t()) != null) {
            aVarT.m(configuration);
        }
        C0237k.b().g(this.f3189l);
        this.f3171T = new Configuration(this.f3189l.getResources().getConfiguration());
        T(false, false);
    }

    @Override // androidx.appcompat.app.f
    public void z(Bundle bundle) {
        String strC;
        this.f3168Q = true;
        S(false);
        l0();
        Object obj = this.f3188k;
        if (obj instanceof Activity) {
            try {
                strC = androidx.core.app.h.c((Activity) obj);
            } catch (IllegalArgumentException unused) {
                strC = null;
            }
            if (strC != null) {
                androidx.appcompat.app.a aVarN0 = N0();
                if (aVarN0 == null) {
                    this.f3181d0 = true;
                } else {
                    aVarN0.r(true);
                }
            }
            androidx.appcompat.app.f.d(this);
        }
        this.f3171T = new Configuration(this.f3189l.getResources().getConfiguration());
        this.f3169R = true;
    }

    h(Dialog dialog, androidx.appcompat.app.d dVar) {
        this(dialog.getContext(), dialog.getWindow(), dVar, dialog);
    }

    @Override // android.view.LayoutInflater.Factory
    public View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return onCreateView(null, str, context, attributeSet);
    }

    private h(Context context, Window window, androidx.appcompat.app.d dVar, Object obj) {
        androidx.appcompat.app.c cVarA1;
        this.f3203z = null;
        this.f3152A = true;
        this.f3172U = -100;
        this.f3180c0 = new a();
        this.f3189l = context;
        this.f3192o = dVar;
        this.f3188k = obj;
        if (this.f3172U == -100 && (obj instanceof Dialog) && (cVarA1 = a1()) != null) {
            this.f3172U = cVarA1.c0().p();
        }
        if (this.f3172U == -100) {
            C0612g c0612g = f3148k0;
            Integer num = (Integer) c0612g.get(obj.getClass().getName());
            if (num != null) {
                this.f3172U = num.intValue();
                c0612g.remove(obj.getClass().getName());
            }
        }
        if (window != null) {
            V(window);
        }
        C0237k.h();
    }
}
