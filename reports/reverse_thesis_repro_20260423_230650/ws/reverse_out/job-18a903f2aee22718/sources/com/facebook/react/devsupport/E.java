package com.facebook.react.devsupport;

import android.R;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.SensorManager;
import android.os.Build;
import android.util.Pair;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import c1.AbstractC0342n;
import com.facebook.fbreact.specs.NativeRedBoxSpec;
import com.facebook.react.bridge.DefaultJSExceptionHandler;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.common.JavascriptException;
import com.facebook.react.devsupport.C0384b;
import com.facebook.react.devsupport.C0393k;
import com.facebook.react.devsupport.SharedPreferencesOnSharedPreferenceChangeListenerC0392j;
import com.facebook.react.modules.core.RCTNativeAppEventEmitter;
import d1.C0507c;
import d1.g;
import j1.InterfaceC0592a;
import j1.InterfaceC0593b;
import j1.InterfaceC0594c;
import j1.InterfaceC0595d;
import j1.e;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public abstract class E implements j1.e {

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final InterfaceC0593b f6720B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private List f6721C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final Map f6722D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private final d1.k f6723E;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f6724a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final d1.g f6725b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final BroadcastReceiver f6726c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C0393k f6727d;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected final c0 f6729f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final String f6730g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final File f6731h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final File f6732i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final DefaultJSExceptionHandler f6733j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final InterfaceC0594c f6734k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final j1.h f6735l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private d1.j f6736m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private AlertDialog f6737n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private C0386d f6738o;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private ReactContext f6741r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final B1.a f6742s;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private boolean f6746w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private String f6747x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private j1.j[] f6748y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private j1.f f6749z;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final LinkedHashMap f6728e = new LinkedHashMap();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private boolean f6739p = false;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private int f6740q = 0;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f6743t = false;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private boolean f6744u = false;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private boolean f6745v = false;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private int f6719A = 0;

    class a extends BroadcastReceiver {
        a() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if (E.j0(context).equals(intent.getAction())) {
                E.this.r();
            }
        }
    }

    class b implements InterfaceC0595d {
        b() {
        }

        @Override // j1.InterfaceC0595d
        public void a() {
            if (!E.this.f6742s.m() && E.this.f6742s.n()) {
                Toast.makeText(E.this.f6724a, E.this.f6724a.getString(AbstractC0342n.f5629h), 1).show();
                E.this.f6742s.e(false);
            }
            E.this.r();
        }
    }

    class c implements DialogInterface.OnClickListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ EditText f6752b;

        c(EditText editText) {
            this.f6752b = editText;
        }

        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i3) {
            E.this.f6742s.g().d(this.f6752b.getText().toString());
            E.this.r();
        }
    }

    class d implements InterfaceC0595d {
        d() {
        }

        @Override // j1.InterfaceC0595d
        public void a() {
            E.this.f6742s.h(!E.this.f6742s.f());
            E.this.f6729f.g();
        }
    }

    class e extends ArrayAdapter {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Set f6755a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        e(Context context, int i3, String[] strArr, Set set) {
            super(context, i3, strArr);
            this.f6755a = set;
        }

        @Override // android.widget.BaseAdapter, android.widget.ListAdapter
        public boolean areAllItemsEnabled() {
            return false;
        }

        @Override // android.widget.ArrayAdapter, android.widget.Adapter
        public View getView(int i3, View view, ViewGroup viewGroup) {
            View view2 = super.getView(i3, view, viewGroup);
            view2.setEnabled(isEnabled(i3));
            return view2;
        }

        @Override // android.widget.BaseAdapter, android.widget.ListAdapter
        public boolean isEnabled(int i3) {
            return !this.f6755a.contains(getItem(i3));
        }
    }

    class f implements InterfaceC0593b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ C0384b.c f6757a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ InterfaceC0592a f6758b;

        f(C0384b.c cVar, InterfaceC0592a interfaceC0592a) {
            this.f6757a = cVar;
            this.f6758b = interfaceC0592a;
        }

        @Override // j1.InterfaceC0593b
        public void a() {
            E.this.l0();
            if (E.this.f6720B != null) {
                E.this.f6720B.a();
            }
            ReactMarker.logMarker(ReactMarkerConstants.DOWNLOAD_END, this.f6757a.c());
            this.f6758b.a();
        }

        @Override // j1.InterfaceC0593b
        public void b(String str, Integer num, Integer num2) {
            E.this.f6734k.b(str, num, num2);
            if (E.this.f6720B != null) {
                E.this.f6720B.b(str, num, num2);
            }
        }

        @Override // j1.InterfaceC0593b
        public void c(Exception exc) {
            E.this.l0();
            if (E.this.f6720B != null) {
                E.this.f6720B.c(exc);
            }
            Y.a.n("ReactNative", "Unable to download JS bundle", exc);
            E.this.F0(exc);
            this.f6758b.b(exc);
        }
    }

    class g implements C0393k.g {
        g() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void h() {
            E.this.w();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void i() {
            E.this.r();
        }

        @Override // com.facebook.react.devsupport.C0393k.g
        public void a() {
            E.this.f6746w = false;
        }

        @Override // com.facebook.react.devsupport.C0393k.g
        public void b() {
            E.this.f6746w = true;
        }

        @Override // com.facebook.react.devsupport.C0393k.g
        public void c() {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.F
                @Override // java.lang.Runnable
                public final void run() {
                    this.f6761b.h();
                }
            });
        }

        @Override // com.facebook.react.devsupport.C0393k.g
        public Map d() {
            return E.this.f6722D;
        }

        @Override // com.facebook.react.devsupport.C0393k.g
        public void e() {
            if (!InspectorFlags.getFuseboxEnabled()) {
                E.this.f6727d.n();
            }
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.G
                @Override // java.lang.Runnable
                public final void run() {
                    this.f6762b.i();
                }
            });
        }
    }

    public E(Context context, c0 c0Var, String str, boolean z3, j1.i iVar, InterfaceC0593b interfaceC0593b, int i3, Map map, d1.k kVar, InterfaceC0594c interfaceC0594c, j1.h hVar) {
        this.f6729f = c0Var;
        this.f6724a = context;
        this.f6730g = str;
        SharedPreferencesOnSharedPreferenceChangeListenerC0392j sharedPreferencesOnSharedPreferenceChangeListenerC0392j = new SharedPreferencesOnSharedPreferenceChangeListenerC0392j(context, new SharedPreferencesOnSharedPreferenceChangeListenerC0392j.b() { // from class: com.facebook.react.devsupport.p
            @Override // com.facebook.react.devsupport.SharedPreferencesOnSharedPreferenceChangeListenerC0392j.b
            public final void a() {
                this.f6903a.E0();
            }
        });
        this.f6742s = sharedPreferencesOnSharedPreferenceChangeListenerC0392j;
        this.f6727d = new C0393k(sharedPreferencesOnSharedPreferenceChangeListenerC0392j, context, sharedPreferencesOnSharedPreferenceChangeListenerC0392j.g());
        this.f6720B = interfaceC0593b;
        this.f6725b = new d1.g(new g.a() { // from class: com.facebook.react.devsupport.q
            @Override // d1.g.a
            public final void a() {
                this.f6904a.w();
            }
        }, i3);
        this.f6722D = map;
        this.f6726c = new a();
        String strK0 = k0();
        this.f6731h = new File(context.getFilesDir(), strK0 + "ReactNativeDevBundle.js");
        this.f6732i = context.getDir(strK0.toLowerCase(Locale.ROOT) + "_dev_js_split_bundles", 0);
        this.f6733j = new DefaultJSExceptionHandler();
        A(z3);
        this.f6734k = interfaceC0594c == null ? new C0390h(c0Var) : interfaceC0594c;
        this.f6723E = kVar;
        this.f6735l = hVar == null ? new a0(new q.i() { // from class: com.facebook.react.devsupport.r
            @Override // q.i
            public final Object get() {
                return this.f6905a.o0();
            }
        }) : hVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void A0() {
        this.f6742s.h(!r0.f());
        this.f6729f.g();
    }

    private void B0(Exception exc) {
        StringBuilder sb = new StringBuilder(exc.getMessage() == null ? "Exception in native call from JS" : exc.getMessage());
        for (Throwable cause = exc.getCause(); cause != null; cause = cause.getCause()) {
            sb.append("\n\n");
            sb.append(cause.getMessage());
        }
        if (!(exc instanceof JavascriptException)) {
            J0(sb.toString(), exc);
        } else {
            Y.a.n("ReactNative", "Exception in native call from JS", exc);
            I0(exc.getMessage().toString(), new j1.j[0], -1, j1.f.f9367c);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void C0() {
        UiThreadUtil.assertOnUiThread();
        if (!this.f6745v) {
            C0386d c0386d = this.f6738o;
            if (c0386d != null) {
                c0386d.i(false);
            }
            if (this.f6744u) {
                this.f6725b.f();
                this.f6744u = false;
            }
            if (this.f6743t) {
                this.f6724a.unregisterReceiver(this.f6726c);
                this.f6743t = false;
            }
            o();
            m0();
            this.f6734k.c();
            this.f6727d.j();
            return;
        }
        C0386d c0386d2 = this.f6738o;
        if (c0386d2 != null) {
            c0386d2.i(this.f6742s.l());
        }
        if (!this.f6744u) {
            this.f6725b.e((SensorManager) this.f6724a.getSystemService("sensor"));
            this.f6744u = true;
        }
        if (!this.f6743t) {
            IntentFilter intentFilter = new IntentFilter();
            intentFilter.addAction(j0(this.f6724a));
            d0(this.f6724a, this.f6726c, intentFilter, true);
            this.f6743t = true;
        }
        if (this.f6739p) {
            this.f6734k.a("Reloading...");
        }
        this.f6727d.z(getClass().getSimpleName(), new g());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void F0(final Exception exc) {
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.v
            @Override // java.lang.Runnable
            public final void run() {
                this.f6911b.p0(exc);
            }
        });
    }

    private void G0(ReactContext reactContext) {
        if (this.f6741r == reactContext) {
            return;
        }
        this.f6741r = reactContext;
        C0386d c0386d = this.f6738o;
        if (c0386d != null) {
            c0386d.i(false);
        }
        if (reactContext != null) {
            this.f6738o = new C0386d(reactContext);
        }
        if (this.f6741r != null) {
            try {
                URL url = new URL(E());
                ((HMRClient) this.f6741r.getJSModule(HMRClient.class)).setup("android", url.getPath().substring(1), url.getHost(), url.getPort() != -1 ? url.getPort() : url.getDefaultPort(), this.f6742s.n(), url.getProtocol());
            } catch (MalformedURLException e3) {
                J0(e3.getMessage(), e3);
            }
        }
        E0();
    }

    private void H0(String str) {
        if (this.f6724a == null) {
            return;
        }
        try {
            URL url = new URL(str);
            int port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
            this.f6734k.a(this.f6724a.getString(AbstractC0342n.f5633l, url.getHost() + ":" + port));
            this.f6739p = true;
        } catch (MalformedURLException e3) {
            Y.a.m("ReactNative", "Bundle url format is invalid. \n\n" + e3.toString());
        }
    }

    private void I0(final String str, final j1.j[] jVarArr, final int i3, final j1.f fVar) {
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.x
            @Override // java.lang.Runnable
            public final void run() {
                this.f6914b.z0(str, jVarArr, i3, fVar);
            }
        });
    }

    private void K0(String str, j1.j[] jVarArr, int i3, j1.f fVar) {
        this.f6747x = str;
        this.f6748y = jVarArr;
        this.f6719A = i3;
        this.f6749z = fVar;
    }

    private void d0(Context context, BroadcastReceiver broadcastReceiver, IntentFilter intentFilter, boolean z3) {
        if (Build.VERSION.SDK_INT < 34 || context.getApplicationInfo().targetSdkVersion < 34) {
            context.registerReceiver(broadcastReceiver, intentFilter);
        } else {
            context.registerReceiver(broadcastReceiver, intentFilter, z3 ? 2 : 4);
        }
    }

    private String h0() {
        try {
            return i0().k().toString();
        } catch (IllegalStateException unused) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String j0(Context context) {
        return context.getPackageName() + ".RELOAD_APP_ACTION";
    }

    private void m0() {
        AlertDialog alertDialog = this.f6737n;
        if (alertDialog != null) {
            alertDialog.dismiss();
            this.f6737n = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void n0(j1.g gVar) {
        this.f6727d.w(gVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ Context o0() {
        Activity activityI = this.f6729f.i();
        if (activityI == null || activityI.isFinishing()) {
            return null;
        }
        return activityI;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void p0(Exception exc) {
        if (exc instanceof C0507c) {
            J0(((C0507c) exc).getMessage(), exc);
        } else {
            J0(this.f6724a.getString(AbstractC0342n.f5638q), exc);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void q0(boolean z3) {
        this.f6742s.c(z3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void r0(boolean z3) {
        this.f6742s.e(z3);
        r();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void t0() {
        Activity activityI = this.f6729f.i();
        if (activityI == null || activityI.isFinishing()) {
            Y.a.m("ReactNative", "Unable to launch change bundle location because react activity is not available");
            return;
        }
        EditText editText = new EditText(activityI);
        editText.setHint("localhost:8081");
        new AlertDialog.Builder(activityI).setTitle(this.f6724a.getString(AbstractC0342n.f5623b)).setView(editText).setPositiveButton(R.string.ok, new c(editText)).create().show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void u0() {
        boolean zN = this.f6742s.n();
        this.f6742s.e(!zN);
        ReactContext reactContext = this.f6741r;
        if (reactContext != null) {
            if (zN) {
                ((HMRClient) reactContext.getJSModule(HMRClient.class)).disable();
            } else {
                ((HMRClient) reactContext.getJSModule(HMRClient.class)).enable();
            }
        }
        if (zN || this.f6742s.m()) {
            return;
        }
        Context context = this.f6724a;
        Toast.makeText(context, context.getString(AbstractC0342n.f5630i), 1).show();
        this.f6742s.j(true);
        r();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void v0() {
        if (!this.f6742s.l()) {
            Activity activityI = this.f6729f.i();
            if (activityI == null) {
                Y.a.m("ReactNative", "Unable to get reference to react activity");
            } else {
                C0386d.h(activityI);
            }
        }
        this.f6742s.c(!r0.l());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void w0() {
        Intent intent = new Intent(this.f6724a, (Class<?>) AbstractC0394l.class);
        intent.setFlags(268435456);
        this.f6724a.startActivity(intent);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void x0(InterfaceC0595d[] interfaceC0595dArr, DialogInterface dialogInterface, int i3) {
        interfaceC0595dArr[i3].a();
        this.f6737n = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void y0(DialogInterface dialogInterface) {
        this.f6737n = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void z0(String str, j1.j[] jVarArr, int i3, j1.f fVar) {
        K0(str, jVarArr, i3, fVar);
        if (this.f6736m == null) {
            d1.j jVarF = f(NativeRedBoxSpec.NAME);
            if (jVarF != null) {
                this.f6736m = jVarF;
            } else {
                this.f6736m = new i0(this);
            }
            this.f6736m.f(NativeRedBoxSpec.NAME);
        }
        if (this.f6736m.a()) {
            return;
        }
        this.f6736m.b();
    }

    @Override // j1.e
    public void A(boolean z3) {
        this.f6745v = z3;
        E0();
    }

    @Override // j1.e
    public j1.f B() {
        return this.f6749z;
    }

    @Override // j1.e
    public ReactContext C() {
        return this.f6741r;
    }

    @Override // j1.e
    /* JADX INFO: renamed from: D, reason: merged with bridge method [inline-methods] */
    public void s0() {
        this.f6727d.x(this.f6741r, this.f6724a.getString(AbstractC0342n.f5634m));
    }

    public void D0(String str, InterfaceC0592a interfaceC0592a) {
        ReactMarker.logMarker(ReactMarkerConstants.DOWNLOAD_START);
        H0(str);
        C0384b.c cVar = new C0384b.c();
        this.f6727d.o(new f(cVar, interfaceC0592a), this.f6731h, str, cVar);
    }

    @Override // j1.e
    public String E() {
        String str = this.f6730g;
        return str == null ? "" : this.f6727d.v((String) Z0.a.c(str));
    }

    public void E0() {
        if (UiThreadUtil.isOnUiThread()) {
            C0();
        } else {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f6913b.C0();
                }
            });
        }
    }

    public void J0(String str, Throwable th) {
        Y.a.n("ReactNative", "Exception in native call", th);
        I0(str, l0.a(th), -1, j1.f.f9368d);
    }

    @Override // j1.e
    public View a(String str) {
        return this.f6729f.a(str);
    }

    @Override // j1.e
    public void b(View view) {
        this.f6729f.b(view);
    }

    @Override // j1.e
    public void c(final boolean z3) {
        if (this.f6745v) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.o
                @Override // java.lang.Runnable
                public final void run() {
                    this.f6901b.q0(z3);
                }
            });
        }
    }

    @Override // j1.e
    public void d() {
        this.f6735l.d();
    }

    @Override // j1.e
    public void e(final boolean z3) {
        if (this.f6745v) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.t
                @Override // java.lang.Runnable
                public final void run() {
                    this.f6908b.r0(z3);
                }
            });
        }
    }

    public InterfaceC0594c e0() {
        return this.f6734k;
    }

    @Override // j1.e
    public d1.j f(String str) {
        d1.k kVar = this.f6723E;
        if (kVar == null) {
            return null;
        }
        return kVar.f(str);
    }

    public C0393k f0() {
        return this.f6727d;
    }

    @Override // j1.e
    public void g() {
        if (this.f6745v) {
            UiThreadUtil.runOnUiThread(new Runnable() { // from class: com.facebook.react.devsupport.u
                @Override // java.lang.Runnable
                public final void run() {
                    this.f6910b.A0();
                }
            });
        }
    }

    public String g0() {
        return this.f6730g;
    }

    @Override // j1.e
    public void h(String str, e.a aVar) {
        this.f6735l.h(str, aVar);
    }

    @Override // com.facebook.react.bridge.JSExceptionHandler
    public void handleException(Exception exc) {
        if (this.f6745v) {
            B0(exc);
        } else {
            this.f6733j.handleException(exc);
        }
    }

    @Override // j1.e
    public Activity i() {
        return this.f6729f.i();
    }

    public c0 i0() {
        return this.f6729f;
    }

    @Override // j1.e
    public String j() {
        return this.f6731h.getAbsolutePath();
    }

    @Override // j1.e
    public String k() {
        return this.f6747x;
    }

    protected abstract String k0();

    @Override // j1.e
    public void l() {
        this.f6727d.i();
    }

    protected void l0() {
        this.f6734k.c();
        this.f6739p = false;
    }

    @Override // j1.e
    public boolean m() {
        return this.f6745v;
    }

    @Override // j1.e
    public B1.a n() {
        return this.f6742s;
    }

    @Override // j1.e
    public void o() {
        d1.j jVar = this.f6736m;
        if (jVar == null) {
            return;
        }
        jVar.c();
    }

    @Override // j1.e
    public void p(ReactContext reactContext) {
        G0(reactContext);
    }

    @Override // j1.e
    public void q(final j1.g gVar) {
        new Runnable() { // from class: com.facebook.react.devsupport.s
            @Override // java.lang.Runnable
            public final void run() {
                this.f6906b.n0(gVar);
            }
        }.run();
    }

    @Override // j1.e
    public j1.i s() {
        return null;
    }

    @Override // j1.e
    public void t() {
        if (this.f6745v) {
            this.f6727d.y();
        }
    }

    @Override // j1.e
    public boolean u() {
        if (this.f6745v && this.f6731h.exists()) {
            try {
                String packageName = this.f6724a.getPackageName();
                if (this.f6731h.lastModified() > this.f6724a.getPackageManager().getPackageInfo(packageName, 0).lastUpdateTime) {
                    File file = new File(String.format(Locale.US, "/data/local/tmp/exopackage/%s//secondary-dex", packageName));
                    if (file.exists()) {
                        return this.f6731h.lastModified() > file.lastModified();
                    }
                    return true;
                }
            } catch (PackageManager.NameNotFoundException unused) {
                Y.a.m("ReactNative", "DevSupport is unable to get current app info");
            }
        }
        return false;
    }

    @Override // j1.e
    public j1.j[] v() {
        return this.f6748y;
    }

    @Override // j1.e
    public void w() {
        if (this.f6737n == null && this.f6745v && !ActivityManager.isUserAMonkey()) {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            HashSet hashSet = new HashSet();
            linkedHashMap.put(this.f6724a.getString(AbstractC0342n.f5637p), new b());
            if (this.f6742s.i()) {
                boolean z3 = this.f6746w;
                String string = this.f6724a.getString(z3 ? AbstractC0342n.f5624c : AbstractC0342n.f5625d);
                if (!z3) {
                    hashSet.add(string);
                }
                linkedHashMap.put(string, new InterfaceC0595d() { // from class: com.facebook.react.devsupport.y
                    @Override // j1.InterfaceC0595d
                    public final void a() {
                        this.f6919a.s0();
                    }
                });
            }
            linkedHashMap.put(this.f6724a.getString(AbstractC0342n.f5623b), new InterfaceC0595d() { // from class: com.facebook.react.devsupport.z
                @Override // j1.InterfaceC0595d
                public final void a() {
                    this.f6920a.t0();
                }
            });
            linkedHashMap.put(this.f6724a.getString(AbstractC0342n.f5632k), new d());
            linkedHashMap.put(this.f6742s.n() ? this.f6724a.getString(AbstractC0342n.f5631j) : this.f6724a.getString(AbstractC0342n.f5628g), new InterfaceC0595d() { // from class: com.facebook.react.devsupport.A
                @Override // j1.InterfaceC0595d
                public final void a() {
                    this.f6701a.u0();
                }
            });
            linkedHashMap.put(this.f6742s.l() ? this.f6724a.getString(AbstractC0342n.f5636o) : this.f6724a.getString(AbstractC0342n.f5635n), new InterfaceC0595d() { // from class: com.facebook.react.devsupport.B
                @Override // j1.InterfaceC0595d
                public final void a() {
                    this.f6702a.v0();
                }
            });
            linkedHashMap.put(this.f6724a.getString(AbstractC0342n.f5639r), new InterfaceC0595d() { // from class: com.facebook.react.devsupport.C
                @Override // j1.InterfaceC0595d
                public final void a() {
                    this.f6703a.w0();
                }
            });
            if (this.f6728e.size() > 0) {
                linkedHashMap.putAll(this.f6728e);
            }
            final InterfaceC0595d[] interfaceC0595dArr = (InterfaceC0595d[]) linkedHashMap.values().toArray(new InterfaceC0595d[0]);
            Activity activityI = this.f6729f.i();
            if (activityI == null || activityI.isFinishing()) {
                Y.a.m("ReactNative", "Unable to launch dev options menu because react activity isn't available");
                return;
            }
            LinearLayout linearLayout = new LinearLayout(activityI);
            linearLayout.setOrientation(1);
            TextView textView = new TextView(activityI);
            textView.setText(activityI.getString(AbstractC0342n.f5626e, k0()));
            textView.setPadding(0, 50, 0, 0);
            textView.setGravity(17);
            textView.setTextSize(16.0f);
            textView.setTypeface(textView.getTypeface(), 1);
            linearLayout.addView(textView);
            String strH0 = h0();
            if (strH0 != null) {
                TextView textView2 = new TextView(activityI);
                textView2.setText(activityI.getString(AbstractC0342n.f5627f, strH0));
                textView2.setPadding(0, 20, 0, 0);
                textView2.setGravity(17);
                textView2.setTextSize(14.0f);
                linearLayout.addView(textView2);
            }
            AlertDialog alertDialogCreate = new AlertDialog.Builder(activityI).setCustomTitle(linearLayout).setAdapter(new e(activityI, R.layout.simple_list_item_1, (String[]) linkedHashMap.keySet().toArray(new String[0]), hashSet), new DialogInterface.OnClickListener() { // from class: com.facebook.react.devsupport.D
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i3) {
                    this.f6717b.x0(interfaceC0595dArr, dialogInterface, i3);
                }
            }).setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: com.facebook.react.devsupport.n
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    this.f6898b.y0(dialogInterface);
                }
            }).create();
            this.f6737n = alertDialogCreate;
            alertDialogCreate.show();
            ReactContext reactContext = this.f6741r;
            if (reactContext != null) {
                ((RCTNativeAppEventEmitter) reactContext.getJSModule(RCTNativeAppEventEmitter.class)).emit("RCTDevMenuShown", null);
            }
        }
    }

    @Override // j1.e
    public Pair x(Pair pair) {
        List list = this.f6721C;
        if (list != null) {
            Iterator it = list.iterator();
            if (it.hasNext()) {
                androidx.activity.result.d.a(it.next());
                throw null;
            }
        }
        return pair;
    }

    @Override // j1.e
    public void y(String str, InterfaceC0595d interfaceC0595d) {
        this.f6728e.put(str, interfaceC0595d);
    }

    @Override // j1.e
    public void z(ReactContext reactContext) {
        if (reactContext == this.f6741r) {
            G0(null);
        }
        System.gc();
    }
}
