package com.qunidayede.supportlibrary.core.view;

import android.os.Bundle;
import androidx.annotation.CallSuper;
import androidx.databinding.ViewDataBinding;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p331b.p335f.C2849b;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u0001*\b\b\u0001\u0010\u0004*\u00020\u00032\b\u0012\u0004\u0012\u00028\u00000\u0005B\u0007¢\u0006\u0004\b\u0017\u0010\bJ\u000f\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0019\u0010\u000b\u001a\u00020\u00062\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0015¢\u0006\u0004\b\u000b\u0010\fJ&\u0010\u0010\u001a\u00020\u00062\u0017\u0010\u000f\u001a\u0013\u0012\u0004\u0012\u00028\u0001\u0012\u0004\u0012\u00020\u00060\r¢\u0006\u0002\b\u000e¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0016\u001a\u00028\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015¨\u0006\u0018"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Landroidx/viewbinding/ViewBinding;", "VB", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "", "initLoadingObserver", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "block", "viewModels", "(Lkotlin/jvm/functions/Function1;)V", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "()Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "viewModel", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseVMActivity<VB extends ViewBinding, VM extends BaseViewModel> extends BaseBindingActivity<VB> {

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = LazyKt__LazyJVMKt.lazy(new C4049a(this));

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseVMActivity$a */
    public static final class C4049a extends Lambda implements Function0<VM> {

        /* renamed from: c */
        public final /* synthetic */ BaseVMActivity<VB, VM> f10324c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4049a(BaseVMActivity<VB, VM> baseVMActivity) {
            super(0);
            this.f10324c = baseVMActivity;
        }

        @Override // kotlin.jvm.functions.Function0
        public Object invoke() {
            Type genericSuperclass = this.f10324c.getClass().getGenericSuperclass();
            Objects.requireNonNull(genericSuperclass, "null cannot be cast to non-null type java.lang.reflect.ParameterizedType");
            Type type = ((ParameterizedType) genericSuperclass).getActualTypeArguments()[1];
            Objects.requireNonNull(type, "null cannot be cast to non-null type java.lang.Class<VM of com.qunidayede.supportlibrary.core.view.BaseVMActivity>");
            BaseVMActivity<VB, VM> baseVMActivity = this.f10324c;
            ViewModel viewModel = new ViewModelProvider(baseVMActivity, baseVMActivity.getDefaultViewModelProviderFactory()).get((Class) type);
            Intrinsics.checkNotNullExpressionValue(viewModel, "ViewModelProvider(this, defaultViewModelProviderFactory)[modelClass]");
            return (BaseViewModel) viewModel;
        }
    }

    private final void initLoadingObserver() {
        getViewModel().getLoading().observe(this, new Observer() { // from class: b.w.b.b.e.e
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                BaseVMActivity.m6046initLoadingObserver$lambda0(BaseVMActivity.this, (C2848a) obj);
            }
        });
        getViewModel().getNetError().observe(this, new Observer() { // from class: b.w.b.b.e.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                BaseVMActivity.m6047initLoadingObserver$lambda1(BaseVMActivity.this, (C2849b) obj);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initLoadingObserver$lambda-0, reason: not valid java name */
    public static final void m6046initLoadingObserver$lambda0(BaseVMActivity this$0, C2848a c2848a) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (!c2848a.f7763a) {
            this$0.hideLoading();
        } else if (c2848a.f7766d) {
            this$0.loadingDialog();
        } else {
            this$0.loadingView();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initLoadingObserver$lambda-1, reason: not valid java name */
    public static final void m6047initLoadingObserver$lambda1(BaseVMActivity this$0, C2849b c2849b) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (!c2849b.f7767a) {
            this$0.removeFailedView();
        } else if (c2849b.f7769c) {
            this$0.showFailedView();
        } else {
            C4325a.m4899b(this$0, c2849b.f7768b).show();
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final VM getViewModel() {
        return (VM) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    @CallSuper
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getBodyBinding() instanceof ViewDataBinding) {
            ((ViewDataBinding) getBodyBinding()).setLifecycleOwner(this);
            ((ViewDataBinding) getBodyBinding()).setVariable(C2827a.f7671b, getViewModel());
        }
        initLoadingObserver();
    }

    public final void viewModels(@NotNull Function1<? super VM, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        block.invoke(getViewModel());
    }
}
