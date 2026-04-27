package com.facebook.react.views.progressbar;

import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import c1.AbstractC0339k;
import com.facebook.react.bridge.JSApplicationIllegalArgumentException;
import com.facebook.react.views.progressbar.ReactProgressBarViewManager;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends FrameLayout {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final C0117a f7864g = new C0117a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Integer f7865b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f7866c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f7867d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private double f7868e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private ProgressBar f7869f;

    /* JADX INFO: renamed from: com.facebook.react.views.progressbar.a$a, reason: collision with other inner class name */
    private static final class C0117a {
        public /* synthetic */ C0117a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private C0117a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Context context) {
        super(context);
        j.f(context, "context");
        this.f7866c = true;
        this.f7867d = true;
    }

    private final void setColor(ProgressBar progressBar) {
        Drawable indeterminateDrawable = progressBar.isIndeterminate() ? progressBar.getIndeterminateDrawable() : progressBar.getProgressDrawable();
        if (indeterminateDrawable == null) {
            return;
        }
        Integer num = this.f7865b;
        if (num != null) {
            indeterminateDrawable.setColorFilter(num.intValue(), PorterDuff.Mode.SRC_IN);
        } else {
            indeterminateDrawable.clearColorFilter();
        }
    }

    public final void a() {
        ProgressBar progressBar = this.f7869f;
        if (progressBar == null) {
            throw new JSApplicationIllegalArgumentException("setStyle() not called");
        }
        progressBar.setIndeterminate(this.f7866c);
        setColor(progressBar);
        progressBar.setProgress((int) (this.f7868e * ((double) 1000)));
        progressBar.setVisibility(this.f7867d ? 0 : 4);
    }

    public final boolean getAnimating$ReactAndroid_release() {
        return this.f7867d;
    }

    public final Integer getColor$ReactAndroid_release() {
        return this.f7865b;
    }

    public final boolean getIndeterminate$ReactAndroid_release() {
        return this.f7866c;
    }

    public final double getProgress$ReactAndroid_release() {
        return this.f7868e;
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        j.f(accessibilityNodeInfo, "info");
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        String str = (String) getTag(AbstractC0339k.f5596t);
        if (str != null) {
            accessibilityNodeInfo.setViewIdResourceName(str);
        }
    }

    public final void setAnimating$ReactAndroid_release(boolean z3) {
        this.f7867d = z3;
    }

    public final void setColor$ReactAndroid_release(Integer num) {
        this.f7865b = num;
    }

    public final void setIndeterminate$ReactAndroid_release(boolean z3) {
        this.f7866c = z3;
    }

    public final void setProgress$ReactAndroid_release(double d3) {
        this.f7868e = d3;
    }

    public final void setStyle$ReactAndroid_release(String str) {
        ReactProgressBarViewManager.a aVar = ReactProgressBarViewManager.Companion;
        ProgressBar progressBarA = aVar.a(getContext(), aVar.b(str));
        progressBarA.setMax(1000);
        this.f7869f = progressBarA;
        removeAllViews();
        addView(this.f7869f, new ViewGroup.LayoutParams(-1, -1));
    }
}
