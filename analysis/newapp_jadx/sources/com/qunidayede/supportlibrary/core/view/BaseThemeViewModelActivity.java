package com.qunidayede.supportlibrary.core.view;

import android.content.SharedPreferences;
import android.os.Bundle;
import com.gyf.immersionbar.ImmersionBar;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.InterfaceC2829b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\t\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\b\u0012\u0004\u0012\u00028\u00000\u00032\u00020\u0004B\u0007¢\u0006\u0004\b\u0014\u0010\u000bJ\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0014¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0017\u0010\u0010\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u0017\u0010\u0012\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\fH&¢\u0006\u0004\b\u0012\u0010\u0011J\u000f\u0010\u0013\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u0013\u0010\u000b¨\u0006\u0015"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseThemeViewModelActivity;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseViewModelActivity;", "Lb/w/b/b/b;", "Landroid/os/Bundle;", "savedInstanceState", "", "onCreate", "(Landroid/os/Bundle;)V", "loadingCurrentTheme", "()V", "", "getCurThemeFlag", "()Z", "isDay", "setCurThemeFlag", "(Z)V", "setThemeRes", "initStatusBar", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseThemeViewModelActivity<VM extends BaseViewModel> extends BaseViewModelActivity<VM> implements InterfaceC2829b {
    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
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
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#000000").statusBarDarkFont(true).init();
    }

    @Override // p005b.p327w.p330b.p331b.InterfaceC2829b
    public void loadingCurrentTheme() {
        setThemeRes(getCurThemeFlag());
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
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
