package com.jbzd.media.movecartoons.core;

import android.annotation.SuppressLint;
import android.view.MotionEvent;
import android.view.View;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p023s.C0959d0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\b\u0012\u0004\u0012\u00028\u00000\u0003B\u0007¢\u0006\u0004\b\u0015\u0010\nJ\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u000e\u001a\u00020\u0006*\u00020\u000b2\b\b\u0002\u0010\r\u001a\u00020\fH\u0007¢\u0006\u0004\b\u000e\u0010\u000fR\u0019\u0010\u0011\u001a\u00020\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseThemeViewModelActivity;", "", "isDay", "", "setThemeRes", "(Z)V", "notifyThemeChanged", "()V", "Landroid/view/View;", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "Lb/a/a/a/s/d0;", "audioService", "Lb/a/a/a/s/d0;", "getAudioService", "()Lb/a/a/a/s/d0;", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class MyThemeViewModelActivity<VM extends BaseViewModel> extends BaseThemeViewModelActivity<VM> {

    @NotNull
    private final C0959d0 audioService;

    public MyThemeViewModelActivity() {
        if (C0959d0.f570a == null) {
            synchronized (C0959d0.class) {
                if (C0959d0.f570a == null) {
                    C0959d0.f570a = new C0959d0(null);
                }
                Unit unit = Unit.INSTANCE;
            }
        }
        C0959d0 c0959d0 = C0959d0.f570a;
        Intrinsics.checkNotNull(c0959d0);
        this.audioService = c0959d0;
    }

    public static /* synthetic */ void fadeWhenTouch$default(MyThemeViewModelActivity myThemeViewModelActivity, View view, float f2, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: fadeWhenTouch");
        }
        if ((i2 & 1) != 0) {
            f2 = 0.7f;
        }
        myThemeViewModelActivity.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-0, reason: not valid java name */
    public static final boolean m5740fadeWhenTouch$lambda0(float f2, View view, MotionEvent motionEvent) {
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

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.a.a.a.n.o
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m5740fadeWhenTouch$lambda0;
                m5740fadeWhenTouch$lambda0 = MyThemeViewModelActivity.m5740fadeWhenTouch$lambda0(f2, view2, motionEvent);
                return m5740fadeWhenTouch$lambda0;
            }
        });
    }

    @NotNull
    public final C0959d0 getAudioService() {
        return this.audioService;
    }

    @Override // p005b.p327w.p330b.p331b.InterfaceC2829b
    public void notifyThemeChanged() {
        recreate();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity
    public void setThemeRes(boolean isDay) {
        setTheme(R.style.AppTheme);
    }
}
