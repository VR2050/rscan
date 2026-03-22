package com.qunidayede.supportlibrary.core.view;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;
import androidx.annotation.CallSuper;
import androidx.databinding.ViewDataBinding;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.core.view.BaseVMFragment;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p331b.p335f.C2849b;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\t\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u0001*\b\b\u0001\u0010\u0004*\u00020\u00032\b\u0012\u0004\u0012\u00028\u00000\u0005B\u0007¢\u0006\u0004\b\u001b\u0010\bJ\u000f\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\u0007\u0010\bJ!\u0010\r\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t2\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0017¢\u0006\u0004\b\r\u0010\u000eJ\u001d\u0010\u0011\u001a\u00020\u0006*\u00020\t2\b\b\u0002\u0010\u0010\u001a\u00020\u000fH\u0007¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015R\u001d\u0010\u001a\u001a\u00028\u00018D@\u0004X\u0084\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0019¨\u0006\u001c"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseVMFragment;", "Landroidx/viewbinding/ViewBinding;", "VB", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "VM", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingFragment;", "", "initLoadingObserver", "()V", "Landroid/view/View;", "view", "Landroid/os/Bundle;", "savedInstanceState", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "", "useParentModel", "()Z", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "()Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "viewModel", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseVMFragment<VB extends ViewBinding, VM extends BaseViewModel> extends BaseBindingFragment<VB> {

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = LazyKt__LazyJVMKt.lazy(new C4050a(this));

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseVMFragment$a */
    public static final class C4050a extends Lambda implements Function0<VM> {

        /* renamed from: c */
        public final /* synthetic */ BaseVMFragment<VB, VM> f10325c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4050a(BaseVMFragment<VB, VM> baseVMFragment) {
            super(0);
            this.f10325c = baseVMFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public Object invoke() {
            ViewModelStoreOwner requireActivity;
            Type genericSuperclass = this.f10325c.getClass().getGenericSuperclass();
            Objects.requireNonNull(genericSuperclass, "null cannot be cast to non-null type java.lang.reflect.ParameterizedType");
            Type type = ((ParameterizedType) genericSuperclass).getActualTypeArguments()[1];
            Objects.requireNonNull(type, "null cannot be cast to non-null type java.lang.Class<VM of com.qunidayede.supportlibrary.core.view.BaseVMFragment>");
            Class cls = (Class) type;
            if (this.f10325c.useParentModel()) {
                requireActivity = this.f10325c.requireActivity();
                Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
            } else {
                requireActivity = this.f10325c;
            }
            ViewModel viewModel = new ViewModelProvider(requireActivity, !this.f10325c.useParentModel() ? this.f10325c.getDefaultViewModelProviderFactory() : this.f10325c.requireActivity().getDefaultViewModelProviderFactory()).get(cls);
            Intrinsics.checkNotNullExpressionValue(viewModel, "ViewModelProvider(\n            if (!useParentModel()) this else requireActivity(),\n            if (!useParentModel()) defaultViewModelProviderFactory else requireActivity().defaultViewModelProviderFactory\n        )[modelClass]");
            return (BaseViewModel) viewModel;
        }
    }

    public static /* synthetic */ void fadeWhenTouch$default(BaseVMFragment baseVMFragment, View view, float f2, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: fadeWhenTouch");
        }
        if ((i2 & 1) != 0) {
            f2 = 0.6f;
        }
        baseVMFragment.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-0, reason: not valid java name */
    public static final boolean m6048fadeWhenTouch$lambda0(float f2, View view, MotionEvent motionEvent) {
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

    private final void initLoadingObserver() {
        getViewModel().getLoading().observe(getViewLifecycleOwner(), new Observer() { // from class: b.w.b.b.e.f
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                BaseVMFragment.m6049initLoadingObserver$lambda1(BaseVMFragment.this, (C2848a) obj);
            }
        });
        getViewModel().getNetError().observe(getViewLifecycleOwner(), new Observer() { // from class: b.w.b.b.e.h
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                BaseVMFragment.m6050initLoadingObserver$lambda2(BaseVMFragment.this, (C2849b) obj);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initLoadingObserver$lambda-1, reason: not valid java name */
    public static final void m6049initLoadingObserver$lambda1(BaseVMFragment this$0, C2848a c2848a) {
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
    /* renamed from: initLoadingObserver$lambda-2, reason: not valid java name */
    public static final void m6050initLoadingObserver$lambda2(BaseVMFragment this$0, C2849b c2849b) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (!c2849b.f7767a) {
            this$0.removeFailedView();
        } else if (c2849b.f7769c) {
            this$0.showFailedView();
        } else {
            C4325a.m4899b(this$0.requireContext(), c2849b.f7768b).show();
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.w.b.b.e.g
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m6048fadeWhenTouch$lambda0;
                m6048fadeWhenTouch$lambda0 = BaseVMFragment.m6048fadeWhenTouch$lambda0(f2, view2, motionEvent);
                return m6048fadeWhenTouch$lambda0;
            }
        });
    }

    @NotNull
    public final VM getViewModel() {
        return (VM) this.viewModel.getValue();
    }

    @Override // androidx.fragment.app.Fragment
    @CallSuper
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
        if (getBodyBinding() instanceof ViewDataBinding) {
            ((ViewDataBinding) getBodyBinding()).setLifecycleOwner(this);
            ((ViewDataBinding) getBodyBinding()).setVariable(C2827a.f7671b, getViewModel());
        }
        initLoadingObserver();
    }

    public boolean useParentModel() {
        return false;
    }
}
