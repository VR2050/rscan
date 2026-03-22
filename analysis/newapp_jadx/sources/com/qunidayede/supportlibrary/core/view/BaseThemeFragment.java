package com.qunidayede.supportlibrary.core.view;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.InterfaceC2829b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\b\b&\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0016\u0010\u000eJ-\u0010\n\u001a\u0004\u0018\u00010\t2\u0006\u0010\u0004\u001a\u00020\u00032\b\u0010\u0006\u001a\u0004\u0018\u00010\u00052\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u0017\u0010\u0013\u001a\u00020\f2\u0006\u0010\u0012\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u0017\u0010\u0015\u001a\u00020\f2\u0006\u0010\u0012\u001a\u00020\u000fH&¢\u0006\u0004\b\u0015\u0010\u0014¨\u0006\u0017"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseThemeFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseFragment;", "Lb/w/b/b/b;", "Landroid/view/LayoutInflater;", "inflater", "Landroid/view/ViewGroup;", "container", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/view/View;", "onCreateView", "(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;", "", "loadingCurrentTheme", "()V", "", "getCurThemeFlag", "()Z", "isDay", "setCurThemeFlag", "(Z)V", "setThemeRes", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseThemeFragment extends BaseFragment implements InterfaceC2829b {
    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
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

    @Override // p005b.p327w.p330b.p331b.InterfaceC2829b
    public void loadingCurrentTheme() {
        setThemeRes(getCurThemeFlag());
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    @Nullable
    public View onCreateView(@NotNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        ApplicationC2828a.m3282c(this);
        loadingCurrentTheme();
        return super.onCreateView(inflater, container, savedInstanceState);
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
