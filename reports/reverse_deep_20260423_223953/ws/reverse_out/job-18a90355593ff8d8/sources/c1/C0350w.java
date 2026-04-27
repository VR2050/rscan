package c1;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.KeyEvent;
import com.facebook.react.devsupport.k0;
import o1.InterfaceC0638a;
import q1.C0655b;

/* JADX INFO: renamed from: c1.w, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0350w {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Activity f5670a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private W f5671b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f5672c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Bundle f5673d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private com.facebook.react.devsupport.K f5674e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private K f5675f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private InterfaceC0351x f5676g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private InterfaceC0638a f5677h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f5678i;

    public C0350w(Activity activity, InterfaceC0351x interfaceC0351x, String str, Bundle bundle) {
        this.f5678i = C0655b.f();
        this.f5670a = activity;
        this.f5672c = str;
        this.f5673d = bundle;
        this.f5674e = new com.facebook.react.devsupport.K();
        this.f5676g = interfaceC0351x;
    }

    private j1.e b() {
        InterfaceC0351x interfaceC0351x;
        if (C0655b.c() && (interfaceC0351x = this.f5676g) != null && interfaceC0351x.c() != null) {
            return this.f5676g.c();
        }
        if (!d().v() || d().o() == null) {
            return null;
        }
        return d().o().D();
    }

    private K d() {
        return this.f5675f;
    }

    protected W a() {
        W w3 = new W(this.f5670a);
        w3.setIsFabric(f());
        return w3;
    }

    public G c() {
        return d().o();
    }

    public W e() {
        if (!C0655b.c()) {
            return this.f5671b;
        }
        InterfaceC0638a interfaceC0638a = this.f5677h;
        if (interfaceC0638a != null) {
            return (W) interfaceC0638a.a();
        }
        return null;
    }

    protected boolean f() {
        return this.f5678i;
    }

    public void g(String str) {
        if (C0655b.c()) {
            if (this.f5677h == null) {
                this.f5677h = this.f5676g.a(this.f5670a, str, this.f5673d);
            }
            this.f5677h.start();
        } else {
            if (this.f5671b != null) {
                throw new IllegalStateException("Cannot loadApp while app is already running.");
            }
            W wA = a();
            this.f5671b = wA;
            wA.u(d().o(), str, this.f5673d);
        }
    }

    public void h(int i3, int i4, Intent intent, boolean z3) {
        if (C0655b.c()) {
            this.f5676g.onActivityResult(this.f5670a, i3, i4, intent);
        } else if (d().v() && z3) {
            d().o().W(this.f5670a, i3, i4, intent);
        }
    }

    public boolean i() {
        if (C0655b.c()) {
            this.f5676g.g();
            return true;
        }
        if (!d().v()) {
            return false;
        }
        d().o().X();
        return true;
    }

    public void j(Configuration configuration) {
        if (C0655b.c()) {
            this.f5676g.d((Context) Z0.a.c(this.f5670a));
        } else if (d().v()) {
            c().Y((Context) Z0.a.c(this.f5670a), configuration);
        }
    }

    public void k() {
        t();
        if (C0655b.c()) {
            this.f5676g.h(this.f5670a);
        } else if (d().v()) {
            d().o().a0(this.f5670a);
        }
    }

    public void l() {
        if (C0655b.c()) {
            this.f5676g.f(this.f5670a);
        } else if (d().v()) {
            d().o().c0(this.f5670a);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference fix 'apply assigned field type' failed
    java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$UnknownArg
    	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
    	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
    	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
    	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
     */
    public void m() {
        if (!(this.f5670a instanceof A1.a)) {
            throw new ClassCastException("Host Activity does not implement DefaultHardwareBackBtnHandler");
        }
        if (C0655b.c()) {
            InterfaceC0351x interfaceC0351x = this.f5676g;
            Activity activity = this.f5670a;
            interfaceC0351x.b(activity, (A1.a) activity);
        } else if (d().v()) {
            G gO = d().o();
            Activity activity2 = this.f5670a;
            gO.e0(activity2, (A1.a) activity2);
        }
    }

    public boolean n(int i3, KeyEvent keyEvent) {
        InterfaceC0351x interfaceC0351x;
        if (i3 != 90) {
            return false;
        }
        if ((!C0655b.c() || (interfaceC0351x = this.f5676g) == null || interfaceC0351x.c() == null) && !(d().v() && d().u())) {
            return false;
        }
        keyEvent.startTracking();
        return true;
    }

    public boolean o(int i3) {
        InterfaceC0351x interfaceC0351x;
        if (i3 != 90) {
            return false;
        }
        if (!C0655b.c() || (interfaceC0351x = this.f5676g) == null) {
            if (!d().v() || !d().u()) {
                return false;
            }
            d().o().r0();
            return true;
        }
        j1.e eVarC = interfaceC0351x.c();
        if (eVarC == null || (eVarC instanceof k0)) {
            return false;
        }
        eVarC.w();
        return true;
    }

    public boolean p(Intent intent) {
        if (C0655b.c()) {
            this.f5676g.onNewIntent(intent);
            return true;
        }
        if (!d().v()) {
            return false;
        }
        d().o().g0(intent);
        return true;
    }

    public void q() {
        if (C0655b.c()) {
            this.f5676g.e(this.f5670a);
        } else if (d().v()) {
            d().o().h0(this.f5670a);
        }
    }

    public void r(boolean z3) {
        if (C0655b.c()) {
            this.f5676g.onWindowFocusChange(z3);
        } else if (d().v()) {
            d().o().i0(z3);
        }
    }

    public boolean s(int i3, KeyEvent keyEvent) {
        j1.e eVarB = b();
        if (eVarB != null && !(eVarB instanceof k0)) {
            if (i3 == 82) {
                eVarB.w();
                return true;
            }
            if (((com.facebook.react.devsupport.K) Z0.a.c(this.f5674e)).b(i3, this.f5670a.getCurrentFocus())) {
                eVarB.r();
                return true;
            }
        }
        return false;
    }

    public void t() {
        if (C0655b.c()) {
            InterfaceC0638a interfaceC0638a = this.f5677h;
            if (interfaceC0638a != null) {
                interfaceC0638a.stop();
                this.f5677h = null;
                return;
            }
            return;
        }
        W w3 = this.f5671b;
        if (w3 != null) {
            w3.v();
            this.f5671b = null;
        }
    }

    public C0350w(Activity activity, K k3, String str, Bundle bundle, boolean z3) {
        C0655b.f();
        this.f5678i = z3;
        this.f5670a = activity;
        this.f5672c = str;
        this.f5673d = bundle;
        this.f5674e = new com.facebook.react.devsupport.K();
        this.f5675f = k3;
    }
}
