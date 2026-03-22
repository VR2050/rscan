package com.jbzd.media.movecartoons.core;

import android.annotation.SuppressLint;
import android.view.MotionEvent;
import android.view.View;
import androidx.exifinterface.media.ExifInterface;
import androidx.fragment.app.FragmentActivity;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseThemeFragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005\b&\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u000f\u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\u001d\u0010\r\u001a\u00020\u0005*\u00020\n2\b\b\u0002\u0010\f\u001a\u00020\u000bH\u0007¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/qunidayede/supportlibrary/core/view/BaseThemeFragment;", "", "isDay", "", "setThemeRes", "(Z)V", "notifyThemeChanged", "()V", "Landroid/view/View;", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class MyThemeFragment<T> extends BaseThemeFragment {
    public static /* synthetic */ void fadeWhenTouch$default(MyThemeFragment myThemeFragment, View view, float f2, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: fadeWhenTouch");
        }
        if ((i2 & 1) != 0) {
            f2 = 0.7f;
        }
        myThemeFragment.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-0, reason: not valid java name */
    public static final boolean m5739fadeWhenTouch$lambda0(float f2, View view, MotionEvent motionEvent) {
        Integer valueOf = motionEvent == null ? null : Integer.valueOf(motionEvent.getAction());
        if (valueOf != null && valueOf.intValue() == 0) {
            if (view == null) {
                return false;
            }
            view.setAlpha(f2);
            return false;
        }
        if (valueOf != null && valueOf.intValue() == 1) {
            if (view == null) {
                return false;
            }
            view.setAlpha(1.0f);
            return false;
        }
        if (valueOf == null || valueOf.intValue() != 3 || view == null) {
            return false;
        }
        view.setAlpha(1.0f);
        return false;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.a.a.a.n.n
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m5739fadeWhenTouch$lambda0;
                m5739fadeWhenTouch$lambda0 = MyThemeFragment.m5739fadeWhenTouch$lambda0(f2, view2, motionEvent);
                return m5739fadeWhenTouch$lambda0;
            }
        });
    }

    @Override // p005b.p327w.p330b.p331b.InterfaceC2829b
    public void notifyThemeChanged() {
        FragmentActivity activity = getActivity();
        if (activity == null) {
            return;
        }
        activity.recreate();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeFragment
    public void setThemeRes(boolean isDay) {
        FragmentActivity activity = getActivity();
        if (activity == null) {
            return;
        }
        activity.setTheme(R.style.AppTheme);
    }
}
