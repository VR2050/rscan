package com.qunidayede.supportlibrary.core.view;

import android.os.Bundle;
import androidx.lifecycle.Observer;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.p331b.p335f.C2848a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\u00020\u0003B\u0007¢\u0006\u0004\b\r\u0010\bJ\u000f\u0010\u0004\u001a\u00028\u0000H&¢\u0006\u0004\b\u0004\u0010\u0005J\r\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\u0007\u0010\bJ\u0019\u0010\u000b\u001a\u00020\u00062\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0014¢\u0006\u0004\b\u000b\u0010\f¨\u0006\u000e"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseViewModelActivity;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "viewModelInstance", "()Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "registerModelObserve", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseViewModelActivity<VM extends BaseViewModel> extends BaseActivity {
    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        registerModelObserve();
        viewModelInstance().getLoading().observe(this, new Observer<T>() { // from class: com.qunidayede.supportlibrary.core.view.BaseViewModelActivity$onCreate$$inlined$observe$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                C2848a c2848a = (C2848a) t;
                if (c2848a.f7763a) {
                    BaseViewModelActivity.this.showLoadingDialog(c2848a.f7764b, c2848a.f7765c);
                } else {
                    BaseViewModelActivity.this.hideLoadingDialog();
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
