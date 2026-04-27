package androidx.appcompat.widget;

import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewParent;

/* JADX INFO: loaded from: classes.dex */
public abstract class S implements View.OnTouchListener, View.OnAttachStateChangeListener {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f3793b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f3794c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f3795d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final View f3796e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Runnable f3797f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Runnable f3798g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f3799h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f3800i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int[] f3801j = new int[2];

    private class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            ViewParent parent = S.this.f3796e.getParent();
            if (parent != null) {
                parent.requestDisallowInterceptTouchEvent(true);
            }
        }
    }

    private class b implements Runnable {
        b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            S.this.e();
        }
    }

    public S(View view) {
        this.f3796e = view;
        view.setLongClickable(true);
        view.addOnAttachStateChangeListener(this);
        this.f3793b = ViewConfiguration.get(view.getContext()).getScaledTouchSlop();
        int tapTimeout = ViewConfiguration.getTapTimeout();
        this.f3794c = tapTimeout;
        this.f3795d = (tapTimeout + ViewConfiguration.getLongPressTimeout()) / 2;
    }

    private void a() {
        Runnable runnable = this.f3798g;
        if (runnable != null) {
            this.f3796e.removeCallbacks(runnable);
        }
        Runnable runnable2 = this.f3797f;
        if (runnable2 != null) {
            this.f3796e.removeCallbacks(runnable2);
        }
    }

    private boolean f(MotionEvent motionEvent) {
        P p3;
        View view = this.f3796e;
        i.e eVarB = b();
        if (eVarB == null || !eVarB.a() || (p3 = (P) eVarB.g()) == null || !p3.isShown()) {
            return false;
        }
        MotionEvent motionEventObtainNoHistory = MotionEvent.obtainNoHistory(motionEvent);
        i(view, motionEventObtainNoHistory);
        j(p3, motionEventObtainNoHistory);
        boolean zE = p3.e(motionEventObtainNoHistory, this.f3800i);
        motionEventObtainNoHistory.recycle();
        int actionMasked = motionEvent.getActionMasked();
        return zE && (actionMasked != 1 && actionMasked != 3);
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean g(android.view.MotionEvent r6) {
        /*
            r5 = this;
            android.view.View r0 = r5.f3796e
            boolean r1 = r0.isEnabled()
            r2 = 0
            if (r1 != 0) goto La
            return r2
        La:
            int r1 = r6.getActionMasked()
            if (r1 == 0) goto L41
            r3 = 1
            if (r1 == r3) goto L3d
            r4 = 2
            if (r1 == r4) goto L1a
            r6 = 3
            if (r1 == r6) goto L3d
            goto L6d
        L1a:
            int r1 = r5.f3800i
            int r1 = r6.findPointerIndex(r1)
            if (r1 < 0) goto L6d
            float r4 = r6.getX(r1)
            float r6 = r6.getY(r1)
            float r1 = r5.f3793b
            boolean r6 = h(r0, r4, r6, r1)
            if (r6 != 0) goto L6d
            r5.a()
            android.view.ViewParent r6 = r0.getParent()
            r6.requestDisallowInterceptTouchEvent(r3)
            return r3
        L3d:
            r5.a()
            goto L6d
        L41:
            int r6 = r6.getPointerId(r2)
            r5.f3800i = r6
            java.lang.Runnable r6 = r5.f3797f
            if (r6 != 0) goto L52
            androidx.appcompat.widget.S$a r6 = new androidx.appcompat.widget.S$a
            r6.<init>()
            r5.f3797f = r6
        L52:
            java.lang.Runnable r6 = r5.f3797f
            int r1 = r5.f3794c
            long r3 = (long) r1
            r0.postDelayed(r6, r3)
            java.lang.Runnable r6 = r5.f3798g
            if (r6 != 0) goto L65
            androidx.appcompat.widget.S$b r6 = new androidx.appcompat.widget.S$b
            r6.<init>()
            r5.f3798g = r6
        L65:
            java.lang.Runnable r6 = r5.f3798g
            int r1 = r5.f3795d
            long r3 = (long) r1
            r0.postDelayed(r6, r3)
        L6d:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.S.g(android.view.MotionEvent):boolean");
    }

    private static boolean h(View view, float f3, float f4, float f5) {
        float f6 = -f5;
        return f3 >= f6 && f4 >= f6 && f3 < ((float) (view.getRight() - view.getLeft())) + f5 && f4 < ((float) (view.getBottom() - view.getTop())) + f5;
    }

    private boolean i(View view, MotionEvent motionEvent) {
        view.getLocationOnScreen(this.f3801j);
        motionEvent.offsetLocation(r0[0], r0[1]);
        return true;
    }

    private boolean j(View view, MotionEvent motionEvent) {
        view.getLocationOnScreen(this.f3801j);
        motionEvent.offsetLocation(-r0[0], -r0[1]);
        return true;
    }

    public abstract i.e b();

    protected abstract boolean c();

    protected boolean d() {
        i.e eVarB = b();
        if (eVarB == null || !eVarB.a()) {
            return true;
        }
        eVarB.dismiss();
        return true;
    }

    void e() {
        a();
        View view = this.f3796e;
        if (view.isEnabled() && !view.isLongClickable() && c()) {
            view.getParent().requestDisallowInterceptTouchEvent(true);
            long jUptimeMillis = SystemClock.uptimeMillis();
            MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, 0.0f, 0.0f, 0);
            view.onTouchEvent(motionEventObtain);
            motionEventObtain.recycle();
            this.f3799h = true;
        }
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        boolean z3;
        boolean z4 = this.f3799h;
        if (z4) {
            z3 = f(motionEvent) || !d();
        } else {
            z3 = g(motionEvent) && c();
            if (z3) {
                long jUptimeMillis = SystemClock.uptimeMillis();
                MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, 0.0f, 0.0f, 0);
                this.f3796e.onTouchEvent(motionEventObtain);
                motionEventObtain.recycle();
            }
        }
        this.f3799h = z3;
        return z3 || z4;
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewAttachedToWindow(View view) {
    }

    @Override // android.view.View.OnAttachStateChangeListener
    public void onViewDetachedFromWindow(View view) {
        this.f3799h = false;
        this.f3800i = -1;
        Runnable runnable = this.f3797f;
        if (runnable != null) {
            this.f3796e.removeCallbacks(runnable);
        }
    }
}
