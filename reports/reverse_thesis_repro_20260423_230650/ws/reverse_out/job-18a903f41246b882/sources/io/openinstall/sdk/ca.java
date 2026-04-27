package io.openinstall.sdk;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import io.reactivex.annotations.SchedulerSupport;
import java.lang.ref.WeakReference;
import java.util.concurrent.DelayQueue;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class ca {
    private ClipboardManager b;
    private final DelayQueue<bz> c = new DelayQueue<>();
    private WeakReference<Activity> d = null;
    private int e = 0;
    private final boolean a = as.a().j().booleanValue();

    public ca(Context context) {
        try {
            this.b = (ClipboardManager) context.getSystemService("clipboard");
        } catch (Throwable th) {
        }
    }

    private ClipData f() {
        ClipDescription primaryClipDescription;
        ClipData primaryClip = null;
        try {
            primaryClipDescription = this.b.getPrimaryClipDescription();
        } catch (Throwable th) {
            primaryClipDescription = null;
        }
        if (primaryClipDescription == null) {
            return g();
        }
        boolean zHasMimeType = primaryClipDescription.hasMimeType("text/plain");
        if (Build.VERSION.SDK_INT >= 16) {
            zHasMimeType |= primaryClipDescription.hasMimeType("text/html");
        }
        if (!zHasMimeType) {
            return ClipData.newPlainText(SchedulerSupport.CUSTOM, "don't match");
        }
        try {
            primaryClip = this.b.getPrimaryClip();
        } catch (Throwable th2) {
        }
        return primaryClip == null ? g() : primaryClip;
    }

    private ClipData g() {
        if (!c()) {
            return null;
        }
        int i = this.e + 1;
        this.e = i;
        if (i < 3) {
            return null;
        }
        this.e = 0;
        return ClipData.newPlainText(SchedulerSupport.CUSTOM, "app focus");
    }

    public void a() {
        if (this.a) {
            this.c.offer(bz.a());
        }
    }

    public void a(WeakReference<Activity> weakReference) {
        this.d = weakReference;
    }

    public void b() {
        if (this.a) {
            this.c.offer(bz.a());
            this.c.offer(bz.b());
        }
    }

    public boolean c() {
        Activity activity;
        WeakReference<Activity> weakReference = this.d;
        if (weakReference == null || (activity = weakReference.get()) == null) {
            return false;
        }
        return activity.hasWindowFocus();
    }

    public ClipData d() {
        if (this.b == null) {
            return null;
        }
        return f();
    }

    public ClipData e() {
        ClipData clipDataF;
        int i;
        bz bzVar;
        if (this.b == null) {
            return null;
        }
        if (this.a) {
            clipDataF = f();
            i = 2;
        } else {
            clipDataF = null;
            i = 1;
        }
        while (clipDataF == null) {
            try {
                bzVar = (bz) this.c.poll(1000L, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                bzVar = null;
            }
            ClipData clipDataF2 = f();
            i++;
            if (bzVar == null || !bzVar.c()) {
                if (this.a || i < 3) {
                    clipDataF = clipDataF2;
                }
            } else if (clipDataF2 == null && ec.a) {
                ec.b(dz.init_background.a(), new Object[0]);
            }
            clipDataF = clipDataF2;
            break;
        }
        this.c.clear();
        return clipDataF;
    }
}
