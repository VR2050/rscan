package androidx.core.view;

import android.view.View;
import android.view.ViewTreeObserver;

/* JADX INFO: loaded from: classes.dex */
public final class H implements ViewTreeObserver.OnPreDrawListener, View.OnAttachStateChangeListener {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View f4395b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ViewTreeObserver f4396c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Runnable f4397d;

    private H(View view, Runnable runnable) {
        this.f4395b = view;
        this.f4396c = view.getViewTreeObserver();
        this.f4397d = runnable;
    }

    public static H a(View view, Runnable runnable) {
        if (view == null) {
            throw new NullPointerException("view == null");
        }
        if (runnable == null) {
            throw new NullPointerException("runnable == null");
        }
        H h3 = new H(view, runnable);
        view.getViewTreeObserver().addOnPreDrawListener(h3);
        view.addOnAttachStateChangeListener(h3);
        return h3;
    }

    public void b() {
        if (this.f4396c.isAlive()) {
            this.f4396c.removeOnPreDrawListener(this);
        } else {
            this.f4395b.getViewTreeObserver().removeOnPreDrawListener(this);
        }
        this.f4395b.removeOnAttachStateChangeListener(this);
    }

    @Override // android.view.ViewTreeObserver.OnPreDrawListener
    public boolean onPreDraw() {
        b();
        this.f4397d.run();
        return true;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewAttachedToWindow(View view) {
        this.f4396c = view.getViewTreeObserver();
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewDetachedFromWindow(View view) {
        b();
    }
}
