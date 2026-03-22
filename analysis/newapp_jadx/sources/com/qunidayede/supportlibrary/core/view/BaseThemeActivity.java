package com.qunidayede.supportlibrary.core.view;

import android.annotation.SuppressLint;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;
import com.gyf.immersionbar.ImmersionBar;
import com.qunidayede.supportlibrary.core.view.BaseThemeActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.InterfaceC2829b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005\b&\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0017\u0010\tJ\u0019\u0010\u0006\u001a\u00020\u00052\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\u0014¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u0017\u0010\u000e\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u0017\u0010\u0010\u001a\u00020\u00052\u0006\u0010\r\u001a\u00020\nH&¢\u0006\u0004\b\u0010\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0011\u0010\tJ\u001d\u0010\u0015\u001a\u00020\u0005*\u00020\u00122\b\b\u0002\u0010\u0014\u001a\u00020\u0013H\u0007¢\u0006\u0004\b\u0015\u0010\u0016¨\u0006\u0018"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseThemeActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "Lb/w/b/b/b;", "Landroid/os/Bundle;", "savedInstanceState", "", "onCreate", "(Landroid/os/Bundle;)V", "loadingCurrentTheme", "()V", "", "getCurThemeFlag", "()Z", "isDay", "setCurThemeFlag", "(Z)V", "setThemeRes", "initStatusBar", "Landroid/view/View;", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseThemeActivity extends BaseActivity implements InterfaceC2829b {
    public static /* synthetic */ void fadeWhenTouch$default(BaseThemeActivity baseThemeActivity, View view, float f2, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: fadeWhenTouch");
        }
        if ((i2 & 1) != 0) {
            f2 = 0.6f;
        }
        baseThemeActivity.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-1, reason: not valid java name */
    public static final boolean m6045fadeWhenTouch$lambda1(float f2, View view, MotionEvent motionEvent) {
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

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.w.b.b.e.c
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m6045fadeWhenTouch$lambda1;
                m6045fadeWhenTouch$lambda1 = BaseThemeActivity.m6045fadeWhenTouch$lambda1(f2, view2, motionEvent);
                return m6045fadeWhenTouch$lambda1;
            }
        });
    }

    public boolean getCurThemeFlag() {
        Intrinsics.checkNotNullParameter("MY_THEME_KEY", "key");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        return sharedPreferences.getBoolean("MY_THEME_KEY", false);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.autoStatusBarDarkModeEnable(true, 0.2f);
        with.init();
    }

    @Override // p005b.p327w.p330b.p331b.InterfaceC2829b
    public void loadingCurrentTheme() {
        setThemeRes(getCurThemeFlag());
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        ApplicationC2828a.m3282c(this);
        loadingCurrentTheme();
        super.onCreate(savedInstanceState);
    }

    public void setCurThemeFlag(boolean isDay) {
        Intrinsics.checkNotNullParameter("MY_THEME_KEY", "key");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putBoolean("MY_THEME_KEY", isDay);
        editor.commit();
        ApplicationC2828a.m3280a();
    }

    public abstract void setThemeRes(boolean isDay);
}
