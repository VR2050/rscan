package com.qunidayede.supportlibrary.core.view;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\b\b&\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b#\u0010\rJ-\u0010\t\u001a\u0004\u0018\u00010\b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\u0006H\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u000e\u0010\rJ\u000f\u0010\u000f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u000f\u0010\rJ%\u0010\u0013\u001a\u00020\u000b2\u0016\u0010\u0012\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00110\u0010\"\u0004\u0018\u00010\u0011¢\u0006\u0004\b\u0013\u0010\u0014J!\u0010\u0019\u001a\u00020\u000b2\b\b\u0002\u0010\u0016\u001a\u00020\u00152\b\b\u0002\u0010\u0018\u001a\u00020\u0017¢\u0006\u0004\b\u0019\u0010\u001aJ\r\u0010\u001b\u001a\u00020\u000b¢\u0006\u0004\b\u001b\u0010\rJ\u000f\u0010\u001d\u001a\u00020\u001cH&¢\u0006\u0004\b\u001d\u0010\u001eR\u0018\u0010\u001f\u001a\u0004\u0018\u00010\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001f\u0010 R\u0016\u0010!\u001a\u00020\u00178\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b!\u0010\"¨\u0006$"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseFragment;", "Landroidx/fragment/app/Fragment;", "Landroid/view/LayoutInflater;", "inflater", "Landroid/view/ViewGroup;", "container", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/view/View;", "onCreateView", "(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;", "", "onResume", "()V", "initViews", "initEvents", "", "Lc/a/d1;", "jobs", "cancelJob", "([Lkotlinx/coroutines/Job;)V", "", NotificationCompat.CATEGORY_MESSAGE, "", "now", "showLoadingDialog", "(Ljava/lang/String;Z)V", "hideLoadingDialog", "", "getLayout", "()I", "contentView", "Landroid/view/View;", "isFirstVisible", "Z", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseFragment extends Fragment {

    @Nullable
    private View contentView;
    private boolean isFirstVisible = true;

    public static /* synthetic */ void showLoadingDialog$default(BaseFragment baseFragment, String str, boolean z, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showLoadingDialog");
        }
        if ((i2 & 1) != 0) {
            str = "loading...";
        }
        if ((i2 & 2) != 0) {
            z = false;
        }
        baseFragment.showLoadingDialog(str, z);
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void cancelJob(@NotNull InterfaceC3053d1... jobs) {
        Intrinsics.checkNotNullParameter(jobs, "jobs");
        for (InterfaceC3053d1 interfaceC3053d1 : jobs) {
            if (interfaceC3053d1 != null && interfaceC3053d1.mo3507b()) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
        }
    }

    public abstract int getLayout();

    public final void hideLoadingDialog() {
        FragmentActivity activity = getActivity();
        if (activity == null) {
            return;
        }
        ((BaseActivity) activity).hideLoadingDialog();
    }

    public void initEvents() {
    }

    public void initViews() {
    }

    @Override // androidx.fragment.app.Fragment
    @Nullable
    public View onCreateView(@NotNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        if (this.contentView == null) {
            this.contentView = inflater.inflate(getLayout(), container, false);
        }
        return this.contentView;
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        if (this.isFirstVisible) {
            initViews();
            initEvents();
            this.isFirstVisible = false;
        }
    }

    public final void showLoadingDialog(@NotNull String msg, boolean now) {
        Intrinsics.checkNotNullParameter(msg, "msg");
        FragmentActivity activity = getActivity();
        if (activity == null) {
            return;
        }
        ((BaseActivity) activity).showLoadingDialog(msg, now);
    }
}
