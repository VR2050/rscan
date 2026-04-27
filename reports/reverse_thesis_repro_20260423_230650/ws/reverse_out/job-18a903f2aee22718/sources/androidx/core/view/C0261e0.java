package androidx.core.view;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.view.View;
import android.view.animation.Interpolator;
import java.lang.ref.WeakReference;

/* JADX INFO: renamed from: androidx.core.view.e0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0261e0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final WeakReference f4466a;

    /* JADX INFO: renamed from: androidx.core.view.e0$a */
    class a extends AnimatorListenerAdapter {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ InterfaceC0263f0 f4467a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ View f4468b;

        a(InterfaceC0263f0 interfaceC0263f0, View view) {
            this.f4467a = interfaceC0263f0;
            this.f4468b = view;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animator) {
            this.f4467a.a(this.f4468b);
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            this.f4467a.b(this.f4468b);
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationStart(Animator animator) {
            this.f4467a.c(this.f4468b);
        }
    }

    C0261e0(View view) {
        this.f4466a = new WeakReference(view);
    }

    private void i(View view, InterfaceC0263f0 interfaceC0263f0) {
        if (interfaceC0263f0 != null) {
            view.animate().setListener(new a(interfaceC0263f0, view));
        } else {
            view.animate().setListener(null);
        }
    }

    public C0261e0 b(float f3) {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().alpha(f3);
        }
        return this;
    }

    public void c() {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().cancel();
        }
    }

    public long d() {
        View view = (View) this.f4466a.get();
        if (view != null) {
            return view.animate().getDuration();
        }
        return 0L;
    }

    public C0261e0 f(long j3) {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().setDuration(j3);
        }
        return this;
    }

    public C0261e0 g(Interpolator interpolator) {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().setInterpolator(interpolator);
        }
        return this;
    }

    public C0261e0 h(InterfaceC0263f0 interfaceC0263f0) {
        View view = (View) this.f4466a.get();
        if (view != null) {
            i(view, interfaceC0263f0);
        }
        return this;
    }

    public C0261e0 j(long j3) {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().setStartDelay(j3);
        }
        return this;
    }

    public C0261e0 k(final InterfaceC0267h0 interfaceC0267h0) {
        final View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().setUpdateListener(interfaceC0267h0 != null ? new ValueAnimator.AnimatorUpdateListener() { // from class: androidx.core.view.d0
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                    interfaceC0267h0.a(view);
                }
            } : null);
        }
        return this;
    }

    public void l() {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().start();
        }
    }

    public C0261e0 m(float f3) {
        View view = (View) this.f4466a.get();
        if (view != null) {
            view.animate().translationY(f3);
        }
        return this;
    }
}
