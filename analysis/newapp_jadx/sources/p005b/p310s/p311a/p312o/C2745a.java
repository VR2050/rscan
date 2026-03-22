package p005b.p310s.p311a.p312o;

import android.content.Context;
import android.hardware.Camera;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.RejectedExecutionException;

/* renamed from: b.s.a.o.a */
/* loaded from: classes2.dex */
public final class C2745a implements Camera.AutoFocusCallback {

    /* renamed from: a */
    public static final String f7513a = C2745a.class.getSimpleName();

    /* renamed from: b */
    public static final Collection<String> f7514b;

    /* renamed from: c */
    public boolean f7515c;

    /* renamed from: d */
    public boolean f7516d;

    /* renamed from: e */
    public final boolean f7517e;

    /* renamed from: f */
    public final Camera f7518f;

    /* renamed from: g */
    public AsyncTask<?, ?, ?> f7519g;

    /* renamed from: b.s.a.o.a$a */
    public static class a extends AsyncTask<Object, Object, Object> {

        /* renamed from: a */
        public WeakReference<C2745a> f7520a;

        public a(C2745a c2745a) {
            this.f7520a = new WeakReference<>(c2745a);
        }

        @Override // android.os.AsyncTask
        public Object doInBackground(Object... objArr) {
            try {
                Thread.sleep(1200L);
            } catch (InterruptedException unused) {
            }
            C2745a c2745a = this.f7520a.get();
            if (c2745a == null) {
                return null;
            }
            c2745a.m3257b();
            return null;
        }
    }

    static {
        ArrayList arrayList = new ArrayList(2);
        f7514b = arrayList;
        arrayList.add("auto");
        arrayList.add("macro");
    }

    public C2745a(Context context, Camera camera) {
        this.f7518f = camera;
        this.f7517e = PreferenceManager.getDefaultSharedPreferences(context).getBoolean("preferences_auto_focus", true) && f7514b.contains(camera.getParameters().getFocusMode());
        m3257b();
    }

    /* renamed from: a */
    public final synchronized void m3256a() {
        if (!this.f7515c && this.f7519g == null) {
            a aVar = new a(this);
            try {
                aVar.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Object[0]);
                this.f7519g = aVar;
            } catch (RejectedExecutionException unused) {
            }
        }
    }

    /* renamed from: b */
    public synchronized void m3257b() {
        if (this.f7517e) {
            this.f7519g = null;
            if (!this.f7515c && !this.f7516d) {
                try {
                    this.f7518f.autoFocus(this);
                    this.f7516d = true;
                } catch (RuntimeException unused) {
                    m3256a();
                }
            }
        }
    }

    /* renamed from: c */
    public synchronized void m3258c() {
        this.f7515c = true;
        if (this.f7517e) {
            synchronized (this) {
                AsyncTask<?, ?, ?> asyncTask = this.f7519g;
                if (asyncTask != null) {
                    if (asyncTask.getStatus() != AsyncTask.Status.FINISHED) {
                        this.f7519g.cancel(true);
                    }
                    this.f7519g = null;
                }
                try {
                    this.f7518f.cancelAutoFocus();
                } catch (RuntimeException unused) {
                }
            }
        }
    }

    @Override // android.hardware.Camera.AutoFocusCallback
    public synchronized void onAutoFocus(boolean z, Camera camera) {
        this.f7516d = false;
        m3256a();
    }
}
