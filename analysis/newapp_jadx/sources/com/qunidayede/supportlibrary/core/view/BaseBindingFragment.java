package com.qunidayede.supportlibrary.core.view;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.CallSuper;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.LifecycleCoroutineScope;
import androidx.lifecycle.LifecycleOwnerKt;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.databinding.LayoutNetworkErrorBinding;
import com.qunidayede.supportlibrary.databinding.ViewRootBinding;
import java.lang.reflect.Method;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p332c.C2831b;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2846i;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000d\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0003\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\f\b\u0016\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\u00020\u00032\u00020\u0004B\u0007¢\u0006\u0004\b9\u0010\u0014J\r\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\u0006\u0010\u0007J(\u0010\f\u001a\u00020\t2\u0017\u0010\u000b\u001a\u0013\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\t0\b¢\u0006\u0002\b\nH\u0016¢\u0006\u0004\b\f\u0010\rJ8\u0010\u000f\u001a\u00020\t\"\n\b\u0001\u0010\u000e\u0018\u0001*\u00020\u00012\u0017\u0010\u000b\u001a\u0013\u0012\u0004\u0012\u00028\u0001\u0012\u0004\u0012\u00020\t0\b¢\u0006\u0002\b\nH\u0086\bø\u0001\u0000¢\u0006\u0004\b\u000f\u0010\rJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0015\u0010\u0014J\u0017\u0010\u0018\u001a\u00020\t2\u0006\u0010\u0017\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u0011\u0010\u001a\u001a\u0004\u0018\u00010\u0001H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ+\u0010#\u001a\u00020\"2\u0006\u0010\u001d\u001a\u00020\u001c2\b\u0010\u001f\u001a\u0004\u0018\u00010\u001e2\b\u0010!\u001a\u0004\u0018\u00010 H\u0007¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u00020\tH\u0016¢\u0006\u0004\b%\u0010\u0014J\u000f\u0010&\u001a\u00020\tH\u0016¢\u0006\u0004\b&\u0010\u0014J\u000f\u0010'\u001a\u00020\tH\u0016¢\u0006\u0004\b'\u0010\u0014J\u000f\u0010)\u001a\u00020(H\u0016¢\u0006\u0004\b)\u0010*R\u001d\u0010\f\u001a\u00028\u00008D@\u0004X\u0084\u0084\u0002¢\u0006\f\n\u0004\b+\u0010,\u001a\u0004\b-\u0010\u001bR\u001d\u00102\u001a\u00020.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b/\u0010,\u001a\u0004\b0\u00101R\"\u00103\u001a\u00020\u00058\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b3\u00104\u001a\u0004\b5\u0010\u0007\"\u0004\b6\u00107R\u0018\u0010\u000f\u001a\u0004\u0018\u00010\u00018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u00108\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006:"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseBindingFragment;", "Landroidx/viewbinding/ViewBinding;", "VB", "Lcom/qunidayede/supportlibrary/core/view/BaseFragment;", "Lb/w/b/b/e/i;", "Lcom/qunidayede/supportlibrary/databinding/ViewRootBinding;", "getRootBanding", "()Lcom/qunidayede/supportlibrary/databinding/ViewRootBinding;", "Lkotlin/Function1;", "", "Lkotlin/ExtensionFunctionType;", "block", "bodyBinding", "(Lkotlin/jvm/functions/Function1;)V", "FVB", "failedBinding", "Landroidx/lifecycle/LifecycleCoroutineScope;", "scope", "()Landroidx/lifecycle/LifecycleCoroutineScope;", "showFailedView", "()V", "removeFailedView", "", "t", "onError", "(Ljava/lang/Throwable;)V", "getFailedBinding", "()Landroidx/viewbinding/ViewBinding;", "Landroid/view/LayoutInflater;", "inflater", "Landroid/view/ViewGroup;", "container", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/view/View;", "onCreateView", "(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;", "loadingView", "loadingDialog", "hideLoading", "", "getLayout", "()I", "bodyBinding$delegate", "Lkotlin/Lazy;", "getBodyBinding", "Lb/w/b/b/c/b;", "loadingViewController$delegate", "getLoadingViewController", "()Lb/w/b/b/c/b;", "loadingViewController", "rootBinding", "Lcom/qunidayede/supportlibrary/databinding/ViewRootBinding;", "getRootBinding", "setRootBinding", "(Lcom/qunidayede/supportlibrary/databinding/ViewRootBinding;)V", "Landroidx/viewbinding/ViewBinding;", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public class BaseBindingFragment<VB extends ViewBinding> extends BaseFragment implements InterfaceC2846i {

    @Nullable
    private ViewBinding failedBinding;
    public ViewRootBinding rootBinding;

    /* renamed from: bodyBinding$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bodyBinding = LazyKt__LazyJVMKt.lazy(new C4047a(this));

    /* renamed from: loadingViewController$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loadingViewController = LazyKt__LazyJVMKt.lazy(new C4048b(this));

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingFragment$a */
    public static final class C4047a extends Lambda implements Function0<VB> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingFragment<VB> f10322c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4047a(BaseBindingFragment<VB> baseBindingFragment) {
            super(0);
            this.f10322c = baseBindingFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public Object invoke() {
            Method declaredMethod = C2354n.m2457b0(this.f10322c.getClass()).getDeclaredMethod("inflate", LayoutInflater.class);
            BaseBindingFragment<VB> baseBindingFragment = this.f10322c;
            Object invoke = declaredMethod.invoke(baseBindingFragment, baseBindingFragment.getLayoutInflater());
            Objects.requireNonNull(invoke, "null cannot be cast to non-null type VB of com.qunidayede.supportlibrary.core.view.BaseBindingFragment");
            return (ViewBinding) invoke;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingFragment$b */
    public static final class C4048b extends Lambda implements Function0<C2831b> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingFragment<VB> f10323c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4048b(BaseBindingFragment<VB> baseBindingFragment) {
            super(0);
            this.f10323c = baseBindingFragment;
        }

        @Override // kotlin.jvm.functions.Function0
        public C2831b invoke() {
            FragmentActivity requireActivity = this.f10323c.requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
            return new C2831b(requireActivity, this.f10323c.getRootBinding());
        }
    }

    private final C2831b getLoadingViewController() {
        return (C2831b) this.loadingViewController.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public void bodyBinding(@NotNull Function1<? super VB, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        block.invoke(getBodyBinding());
    }

    public final /* synthetic */ void failedBinding(Function1 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        ViewBinding failedBinding = getFailedBinding();
        if (failedBinding == null) {
            return;
        }
        Intrinsics.reifiedOperationMarker(1, "FVB");
        block.invoke(failedBinding);
    }

    @NotNull
    public final VB getBodyBinding() {
        return (VB) this.bodyBinding.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    @Nullable
    public ViewBinding getFailedBinding() {
        if (this.failedBinding == null) {
            this.failedBinding = LayoutNetworkErrorBinding.inflate(getLayoutInflater());
        }
        return this.failedBinding;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return -1;
    }

    @NotNull
    public final ViewRootBinding getRootBanding() {
        return getRootBinding();
    }

    @NotNull
    public final ViewRootBinding getRootBinding() {
        ViewRootBinding viewRootBinding = this.rootBinding;
        if (viewRootBinding != null) {
            return viewRootBinding;
        }
        Intrinsics.throwUninitializedPropertyAccessException("rootBinding");
        throw null;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void hideLoading() {
        getLoadingViewController().m3283a();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void loadingDialog() {
        getLoadingViewController().m3284b();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void loadingView() {
        getLoadingViewController().m3285c();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    @CallSuper
    @NotNull
    public final View onCreateView(@NotNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        if (this.rootBinding == null) {
            ViewRootBinding inflate = ViewRootBinding.inflate(inflater, container, false);
            Intrinsics.checkNotNullExpressionValue(inflate, "inflate(inflater, container, false)");
            setRootBinding(inflate);
            getRootBinding().layoutBody.addView(getBodyBinding().getRoot(), 0, new ViewGroup.LayoutParams(-1, -1));
        }
        FrameLayout root = getRootBinding().getRoot();
        Intrinsics.checkNotNullExpressionValue(root, "rootBinding.root");
        return root;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void onError(@NotNull Throwable t) {
        Intrinsics.checkNotNullParameter(t, "t");
        Context requireContext = requireContext();
        String message = t.getMessage();
        if (message == null) {
            message = "";
        }
        C4325a.m4899b(requireContext, message).show();
    }

    public void onFailedReload(boolean z, int i2, @NotNull Function1<? super View, Unit> function1) {
        C2354n.m2484i1(this, z, i2, function1);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void removeFailedView() {
        ViewBinding viewBinding = this.failedBinding;
        if (viewBinding == null) {
            return;
        }
        getRootBinding().layoutBody.removeView(viewBinding.getRoot());
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    @NotNull
    public LifecycleCoroutineScope scope() {
        return LifecycleOwnerKt.getLifecycleScope(this);
    }

    public final void setRootBinding(@NotNull ViewRootBinding viewRootBinding) {
        Intrinsics.checkNotNullParameter(viewRootBinding, "<set-?>");
        this.rootBinding = viewRootBinding;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void showFailedView() {
        ViewBinding failedBinding = getFailedBinding();
        if (failedBinding == null) {
            return;
        }
        getRootBinding().layoutBody.addView(failedBinding.getRoot());
    }
}
