package com.jbzd.media.movecartoons.core;

import android.annotation.SuppressLint;
import android.view.MotionEvent;
import android.view.View;
import androidx.fragment.app.FragmentActivity;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\b\u0012\u0004\u0012\u00028\u00000\u0003B\u0007¢\u0006\u0004\b\u0010\u0010\nJ\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u000e\u001a\u00020\u0006*\u00020\u000b2\b\b\u0002\u0010\r\u001a\u00020\fH\u0007¢\u0006\u0004\b\u000e\u0010\u000f¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseThemeViewModelFragment;", "", "isDay", "", "setThemeRes", "(Z)V", "notifyThemeChanged", "()V", "Landroid/view/View;", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class MyThemeViewModelFragment<VM extends BaseViewModel> extends BaseThemeViewModelFragment<VM> {
    public static /* synthetic */ void fadeWhenTouch$default(MyThemeViewModelFragment myThemeViewModelFragment, View view, float f2, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: fadeWhenTouch");
        }
        if ((i2 & 1) != 0) {
            f2 = 0.8f;
        }
        myThemeViewModelFragment.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-0, reason: not valid java name */
    public static final boolean m5741fadeWhenTouch$lambda0(float f2, View view, MotionEvent motionEvent) {
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

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.a.a.a.n.p
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m5741fadeWhenTouch$lambda0;
                m5741fadeWhenTouch$lambda0 = MyThemeViewModelFragment.m5741fadeWhenTouch$lambda0(f2, view2, motionEvent);
                return m5741fadeWhenTouch$lambda0;
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

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment
    public void setThemeRes(boolean isDay) {
        FragmentActivity activity = getActivity();
        if (activity == null) {
            return;
        }
        activity.setTheme(R.style.AppTheme);
    }
}
