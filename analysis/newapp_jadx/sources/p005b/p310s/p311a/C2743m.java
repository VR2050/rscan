package p005b.p310s.p311a;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import androidx.work.PeriodicWorkRequest;
import java.lang.ref.WeakReference;
import java.util.concurrent.RejectedExecutionException;

/* renamed from: b.s.a.m */
/* loaded from: classes2.dex */
public final class C2743m {

    /* renamed from: a */
    public static final String f7506a = "m";

    /* renamed from: b */
    public final Activity f7507b;

    /* renamed from: c */
    public final BroadcastReceiver f7508c = new b(this);

    /* renamed from: d */
    public boolean f7509d = false;

    /* renamed from: e */
    public AsyncTask<Object, Object, Object> f7510e;

    /* renamed from: b.s.a.m$a */
    public static class a extends AsyncTask<Object, Object, Object> {

        /* renamed from: a */
        public WeakReference<Activity> f7511a;

        public a(Activity activity) {
            this.f7511a = new WeakReference<>(activity);
        }

        @Override // android.os.AsyncTask
        public Object doInBackground(Object... objArr) {
            try {
                Thread.sleep(PeriodicWorkRequest.MIN_PERIODIC_FLEX_MILLIS);
                String str = C2743m.f7506a;
                Activity activity = this.f7511a.get();
                if (activity == null) {
                    return null;
                }
                activity.finish();
                return null;
            } catch (InterruptedException unused) {
                return null;
            }
        }
    }

    /* renamed from: b.s.a.m$b */
    public static class b extends BroadcastReceiver {

        /* renamed from: a */
        public WeakReference<C2743m> f7512a;

        public b(C2743m c2743m) {
            this.f7512a = new WeakReference<>(c2743m);
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            C2743m c2743m;
            if (!"android.intent.action.BATTERY_CHANGED".equals(intent.getAction()) || (c2743m = this.f7512a.get()) == null) {
                return;
            }
            if (intent.getIntExtra("plugged", -1) <= 0) {
                c2743m.m3255b();
            } else {
                c2743m.m3254a();
            }
        }
    }

    public C2743m(Activity activity) {
        this.f7507b = activity;
        m3255b();
    }

    /* renamed from: a */
    public final void m3254a() {
        AsyncTask<Object, Object, Object> asyncTask = this.f7510e;
        if (asyncTask != null) {
            asyncTask.cancel(true);
            this.f7510e = null;
        }
    }

    /* renamed from: b */
    public void m3255b() {
        m3254a();
        a aVar = new a(this.f7507b);
        this.f7510e = aVar;
        try {
            aVar.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Object[0]);
        } catch (RejectedExecutionException unused) {
        }
    }
}
