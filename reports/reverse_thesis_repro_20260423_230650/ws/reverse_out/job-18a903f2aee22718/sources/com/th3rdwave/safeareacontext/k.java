package com.th3rdwave.safeareacontext;

import android.content.Context;
import android.util.Log;
import android.view.View;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.uimanager.A0;
import com.facebook.react.uimanager.UIManagerModule;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/* JADX INFO: loaded from: classes.dex */
public final class k extends com.facebook.react.views.view.g implements ViewTreeObserver.OnPreDrawListener {

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private o f8752t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private a f8753u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private m f8754v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private View f8755w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private A0 f8756x;

    public k(Context context) {
        super(context);
        this.f8752t = o.f8769b;
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final View H() {
        for (ViewParent parent = getParent(); parent != 0; parent = parent.getParent()) {
            if (parent instanceof f) {
                return (View) parent;
            }
        }
        return this;
    }

    private final boolean I() {
        a aVarE;
        View view = this.f8755w;
        if (view == null || (aVarE = h.e(view)) == null || t2.j.b(this.f8753u, aVarE)) {
            return false;
        }
        this.f8753u = aVarE;
        J();
        return true;
    }

    private final void J() {
        a aVar = this.f8753u;
        if (aVar != null) {
            m mVar = this.f8754v;
            if (mVar == null) {
                l lVar = l.f8758c;
                mVar = new m(lVar, lVar, lVar, lVar);
            }
            A0 stateWrapper = getStateWrapper();
            if (stateWrapper != null) {
                WritableMap writableMapCreateMap = Arguments.createMap();
                writableMapCreateMap.putMap("insets", q.b(aVar));
                t2.j.c(writableMapCreateMap);
                stateWrapper.b(writableMapCreateMap);
                return;
            }
            n nVar = new n(aVar, this.f8752t, mVar);
            ReactContext reactContextA = r.a(this);
            final UIManagerModule uIManagerModule = (UIManagerModule) reactContextA.getNativeModule(UIManagerModule.class);
            if (uIManagerModule != null) {
                uIManagerModule.setViewLocalData(getId(), nVar);
                reactContextA.runOnNativeModulesQueueThread(new Runnable() { // from class: com.th3rdwave.safeareacontext.i
                    @Override // java.lang.Runnable
                    public final void run() {
                        k.K(uIManagerModule);
                    }
                });
                L();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void K(UIManagerModule uIManagerModule) {
        uIManagerModule.getUIImplementation().m(-1);
    }

    private final void L() {
        final t2.q qVar = new t2.q();
        final ReentrantLock reentrantLock = new ReentrantLock();
        final Condition conditionNewCondition = reentrantLock.newCondition();
        long jNanoTime = System.nanoTime();
        r.a(this).runOnNativeModulesQueueThread(new Runnable() { // from class: com.th3rdwave.safeareacontext.j
            @Override // java.lang.Runnable
            public final void run() {
                k.M(reentrantLock, qVar, conditionNewCondition);
            }
        });
        reentrantLock.lock();
        long jNanoTime2 = 0;
        while (!qVar.f10213b && jNanoTime2 < 500000000) {
            try {
                try {
                    conditionNewCondition.awaitNanos(500000000L);
                } catch (InterruptedException unused) {
                    qVar.f10213b = true;
                }
                jNanoTime2 += System.nanoTime() - jNanoTime;
            } catch (Throwable th) {
                reentrantLock.unlock();
                throw th;
            }
        }
        h2.r rVar = h2.r.f9288a;
        reentrantLock.unlock();
        if (jNanoTime2 >= 500000000) {
            Log.w("SafeAreaView", "Timed out waiting for layout.");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void M(ReentrantLock reentrantLock, t2.q qVar, Condition condition) {
        reentrantLock.lock();
        try {
            if (!qVar.f10213b) {
                qVar.f10213b = true;
                condition.signal();
            }
            h2.r rVar = h2.r.f9288a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public final A0 getStateWrapper() {
        return this.f8756x;
    }

    @Override // com.facebook.react.views.view.g, android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        ViewTreeObserver viewTreeObserver;
        super.onAttachedToWindow();
        View viewH = H();
        this.f8755w = viewH;
        if (viewH != null && (viewTreeObserver = viewH.getViewTreeObserver()) != null) {
            viewTreeObserver.addOnPreDrawListener(this);
        }
        I();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        ViewTreeObserver viewTreeObserver;
        super.onDetachedFromWindow();
        View view = this.f8755w;
        if (view != null && (viewTreeObserver = view.getViewTreeObserver()) != null) {
            viewTreeObserver.removeOnPreDrawListener(this);
        }
        this.f8755w = null;
    }

    @Override // android.view.ViewTreeObserver.OnPreDrawListener
    public boolean onPreDraw() {
        boolean zI = I();
        if (zI) {
            requestLayout();
        }
        return !zI;
    }

    public final void setEdges(m mVar) {
        t2.j.f(mVar, "edges");
        this.f8754v = mVar;
        J();
    }

    public final void setMode(o oVar) {
        t2.j.f(oVar, "mode");
        this.f8752t = oVar;
        J();
    }

    public final void setStateWrapper(A0 a02) {
        this.f8756x = a02;
    }
}
