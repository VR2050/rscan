package androidx.lifecycle;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import java.util.concurrent.atomic.AtomicBoolean;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final h f5141a = new h();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final AtomicBoolean f5142b = new AtomicBoolean(false);

    public static final class a extends AbstractC0305c {
        @Override // androidx.lifecycle.AbstractC0305c, android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle bundle) {
            t2.j.f(activity, "activity");
            t.f5171c.c(activity);
        }
    }

    private h() {
    }

    public static final void a(Context context) {
        t2.j.f(context, "context");
        if (f5142b.getAndSet(true)) {
            return;
        }
        Context applicationContext = context.getApplicationContext();
        t2.j.d(applicationContext, "null cannot be cast to non-null type android.app.Application");
        ((Application) applicationContext).registerActivityLifecycleCallbacks(new a());
    }
}
