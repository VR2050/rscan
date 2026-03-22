package com.qunidayede.supportlibrary.core.view;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.View;
import androidx.lifecycle.Observer;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.p331b.p335f.C2848a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\u00020\u0003B\u0007¢\u0006\u0004\b\u0011\u0010\bJ\u000f\u0010\u0004\u001a\u00028\u0000H&¢\u0006\u0004\b\u0004\u0010\u0005J\r\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\u0007\u0010\bJ\u0019\u0010\u000b\u001a\u00020\u00062\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0016¢\u0006\u0004\b\u000b\u0010\fJ!\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u000e\u001a\u00020\r2\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0017¢\u0006\u0004\b\u000f\u0010\u0010¨\u0006\u0012"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseViewModelFragment;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseFragment;", "viewModelInstance", "()Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "registerModelObserve", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onActivityCreated", "(Landroid/os/Bundle;)V", "Landroid/view/View;", "view", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseViewModelFragment<VM extends BaseViewModel> extends BaseFragment {
    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(@Nullable Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        registerModelObserve();
    }

    @Override // androidx.fragment.app.Fragment
    @SuppressLint({"FragmentLiveDataObserve"})
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
        viewModelInstance().getLoading().observe(this, new Observer<T>() { // from class: com.qunidayede.supportlibrary.core.view.BaseViewModelFragment$onViewCreated$$inlined$observe$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                C2848a c2848a = (C2848a) t;
                if (c2848a.f7763a) {
                    BaseViewModelFragment.this.showLoadingDialog(c2848a.f7764b, c2848a.f7765c);
                } else {
                    BaseViewModelFragment.this.hideLoadingDialog();
                }
            }
        });
    }

    public final void registerModelObserve() {
        getLifecycle().addObserver(viewModelInstance());
    }

    @NotNull
    public abstract VM viewModelInstance();
}
