package androidx.lifecycle;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import androidx.lifecycle.f;
import androidx.lifecycle.t;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class s implements k {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final b f5159j = new b(null);

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static final s f5160k = new s();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f5161b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f5162c;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Handler f5165f;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f5163d = true;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f5164e = true;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final l f5166g = new l(this);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Runnable f5167h = new Runnable() { // from class: androidx.lifecycle.r
        @Override // java.lang.Runnable
        public final void run() {
            s.k(this.f5158b);
        }
    };

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final t.a f5168i = new d();

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final a f5169a = new a();

        private a() {
        }

        public static final void a(Activity activity, Application.ActivityLifecycleCallbacks activityLifecycleCallbacks) {
            t2.j.f(activity, "activity");
            t2.j.f(activityLifecycleCallbacks, "callback");
            activity.registerActivityLifecycleCallbacks(activityLifecycleCallbacks);
        }
    }

    public static final class b {
        public /* synthetic */ b(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final k a() {
            return s.f5160k;
        }

        public final void b(Context context) {
            t2.j.f(context, "context");
            s.f5160k.j(context);
        }

        private b() {
        }
    }

    public static final class c extends AbstractC0305c {

        public static final class a extends AbstractC0305c {
            final /* synthetic */ s this$0;

            a(s sVar) {
                this.this$0 = sVar;
            }

            @Override // android.app.Application.ActivityLifecycleCallbacks
            public void onActivityPostResumed(Activity activity) {
                t2.j.f(activity, "activity");
                this.this$0.g();
            }

            @Override // android.app.Application.ActivityLifecycleCallbacks
            public void onActivityPostStarted(Activity activity) {
                t2.j.f(activity, "activity");
                this.this$0.h();
            }
        }

        c() {
        }

        @Override // androidx.lifecycle.AbstractC0305c, android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle bundle) {
            t2.j.f(activity, "activity");
            if (Build.VERSION.SDK_INT < 29) {
                t.f5171c.b(activity).f(s.this.f5168i);
            }
        }

        @Override // androidx.lifecycle.AbstractC0305c, android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
            t2.j.f(activity, "activity");
            s.this.f();
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPreCreated(Activity activity, Bundle bundle) {
            t2.j.f(activity, "activity");
            a.a(activity, new a(s.this));
        }

        @Override // androidx.lifecycle.AbstractC0305c, android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
            t2.j.f(activity, "activity");
            s.this.i();
        }
    }

    public static final class d implements t.a {
        d() {
        }

        @Override // androidx.lifecycle.t.a
        public void a() {
            s.this.g();
        }

        @Override // androidx.lifecycle.t.a
        public void b() {
        }

        @Override // androidx.lifecycle.t.a
        public void c() {
            s.this.h();
        }
    }

    private s() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void k(s sVar) {
        t2.j.f(sVar, "this$0");
        sVar.l();
        sVar.m();
    }

    public final void f() {
        int i3 = this.f5162c - 1;
        this.f5162c = i3;
        if (i3 == 0) {
            Handler handler = this.f5165f;
            t2.j.c(handler);
            handler.postDelayed(this.f5167h, 700L);
        }
    }

    public final void g() {
        int i3 = this.f5162c + 1;
        this.f5162c = i3;
        if (i3 == 1) {
            if (this.f5163d) {
                this.f5166g.h(f.a.ON_RESUME);
                this.f5163d = false;
            } else {
                Handler handler = this.f5165f;
                t2.j.c(handler);
                handler.removeCallbacks(this.f5167h);
            }
        }
    }

    public final void h() {
        int i3 = this.f5161b + 1;
        this.f5161b = i3;
        if (i3 == 1 && this.f5164e) {
            this.f5166g.h(f.a.ON_START);
            this.f5164e = false;
        }
    }

    public final void i() {
        this.f5161b--;
        m();
    }

    public final void j(Context context) {
        t2.j.f(context, "context");
        this.f5165f = new Handler();
        this.f5166g.h(f.a.ON_CREATE);
        Context applicationContext = context.getApplicationContext();
        t2.j.d(applicationContext, "null cannot be cast to non-null type android.app.Application");
        ((Application) applicationContext).registerActivityLifecycleCallbacks(new c());
    }

    public final void l() {
        if (this.f5162c == 0) {
            this.f5163d = true;
            this.f5166g.h(f.a.ON_PAUSE);
        }
    }

    public final void m() {
        if (this.f5161b == 0 && this.f5163d) {
            this.f5166g.h(f.a.ON_STOP);
            this.f5164e = true;
        }
    }

    @Override // androidx.lifecycle.k
    public f s() {
        return this.f5166g;
    }
}
