package androidx.databinding;

import androidx.annotation.RestrictTo;
import androidx.databinding.ViewDataBindingKtx;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.LifecycleOwnerKt;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\bÇ\u0002\u0018\u00002\u00020\u0001:\u0001\u0010B\t\b\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ-\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\f\u0010\u0007\u001a\b\u0012\u0002\b\u0003\u0018\u00010\u0006H\u0007¢\u0006\u0004\b\t\u0010\nR\u0016\u0010\f\u001a\u00020\u000b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\f\u0010\r¨\u0006\u0011"}, m5311d2 = {"Landroidx/databinding/ViewDataBindingKtx;", "", "Landroidx/databinding/ViewDataBinding;", "viewDataBinding", "", "localFieldId", "Lc/a/b2/b;", "observable", "", "updateStateFlowRegistration", "(Landroidx/databinding/ViewDataBinding;ILc/a/b2/b;)Z", "Landroidx/databinding/CreateWeakListener;", "CREATE_STATE_FLOW_LISTENER", "Landroidx/databinding/CreateWeakListener;", "<init>", "()V", "StateFlowListener", "databindingKtx_release"}, m5312k = 1, m5313mv = {1, 4, 2})
@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public final class ViewDataBindingKtx {

    @NotNull
    public static final ViewDataBindingKtx INSTANCE = new ViewDataBindingKtx();
    private static final CreateWeakListener CREATE_STATE_FLOW_LISTENER = new CreateWeakListener() { // from class: androidx.databinding.ViewDataBindingKtx$CREATE_STATE_FLOW_LISTENER$1
        @Override // androidx.databinding.CreateWeakListener
        public final WeakListener<Object> create(ViewDataBinding viewDataBinding, int i2, ReferenceQueue<ViewDataBinding> referenceQueue) {
            Intrinsics.checkNotNullExpressionValue(referenceQueue, "referenceQueue");
            return new ViewDataBindingKtx.StateFlowListener(viewDataBinding, i2, referenceQueue).getListener();
        }
    };

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0000\u0018\u00002\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u00020\u0001B'\u0012\b\u0010\u001d\u001a\u0004\u0018\u00010\u001c\u0012\u0006\u0010\u001f\u001a\u00020\u001e\u0012\f\u0010!\u001a\b\u0012\u0004\u0012\u00020\u001c0 ¢\u0006\u0004\b\"\u0010#J'\u0010\b\u001a\u00020\u00072\u0006\u0010\u0005\u001a\u00020\u00042\u000e\u0010\u0006\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u0002H\u0002¢\u0006\u0004\b\b\u0010\tJ\u001d\u0010\u000b\u001a\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ!\u0010\u000e\u001a\u00020\u00072\u0010\u0010\r\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0003\u0018\u00010\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ!\u0010\u0010\u001a\u00020\u00072\u0010\u0010\r\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0003\u0018\u00010\u0002H\u0016¢\u0006\u0004\b\u0010\u0010\u000fJ\u0019\u0010\u0012\u001a\u00020\u00072\b\u0010\u0011\u001a\u0004\u0018\u00010\u0004H\u0016¢\u0006\u0004\b\u0012\u0010\u0013R\u0018\u0010\u0015\u001a\u0004\u0018\u00010\u00148\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016R$\u0010\u0017\u001a\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00030\u00020\n8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0017\u0010\u0018R\u001e\u0010\u001a\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u00198\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001a\u0010\u001b¨\u0006$"}, m5311d2 = {"Landroidx/databinding/ViewDataBindingKtx$StateFlowListener;", "Landroidx/databinding/ObservableReference;", "Lc/a/b2/b;", "", "Landroidx/lifecycle/LifecycleOwner;", "owner", "flow", "", "startCollection", "(Landroidx/lifecycle/LifecycleOwner;Lc/a/b2/b;)V", "Landroidx/databinding/WeakListener;", "getListener", "()Landroidx/databinding/WeakListener;", "target", "addListener", "(Lc/a/b2/b;)V", "removeListener", "lifecycleOwner", "setLifecycleOwner", "(Landroidx/lifecycle/LifecycleOwner;)V", "Lc/a/d1;", "observerJob", "Lc/a/d1;", "listener", "Landroidx/databinding/WeakListener;", "Ljava/lang/ref/WeakReference;", "_lifecycleOwnerRef", "Ljava/lang/ref/WeakReference;", "Landroidx/databinding/ViewDataBinding;", "binder", "", "localFieldId", "Ljava/lang/ref/ReferenceQueue;", "referenceQueue", "<init>", "(Landroidx/databinding/ViewDataBinding;ILjava/lang/ref/ReferenceQueue;)V", "databindingKtx_release"}, m5312k = 1, m5313mv = {1, 4, 2})
    public static final class StateFlowListener implements ObservableReference<InterfaceC3006b<? extends Object>> {
        private WeakReference<LifecycleOwner> _lifecycleOwnerRef;
        private final WeakListener<InterfaceC3006b<Object>> listener;
        private InterfaceC3053d1 observerJob;

        public StateFlowListener(@Nullable ViewDataBinding viewDataBinding, int i2, @NotNull ReferenceQueue<ViewDataBinding> referenceQueue) {
            Intrinsics.checkNotNullParameter(referenceQueue, "referenceQueue");
            this.listener = new WeakListener<>(viewDataBinding, i2, this, referenceQueue);
        }

        private final void startCollection(LifecycleOwner owner, InterfaceC3006b<? extends Object> flow) {
            InterfaceC3053d1 interfaceC3053d1 = this.observerJob;
            if (interfaceC3053d1 != null) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
            this.observerJob = LifecycleOwnerKt.getLifecycleScope(owner).launchWhenCreated(new ViewDataBindingKtx$StateFlowListener$startCollection$1(this, flow, null));
        }

        @Override // androidx.databinding.ObservableReference
        @NotNull
        public WeakListener<InterfaceC3006b<? extends Object>> getListener() {
            return this.listener;
        }

        @Override // androidx.databinding.ObservableReference
        public void setLifecycleOwner(@Nullable LifecycleOwner lifecycleOwner) {
            WeakReference<LifecycleOwner> weakReference = this._lifecycleOwnerRef;
            if ((weakReference != null ? weakReference.get() : null) == lifecycleOwner) {
                return;
            }
            InterfaceC3053d1 interfaceC3053d1 = this.observerJob;
            if (interfaceC3053d1 != null) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
            if (lifecycleOwner == null) {
                this._lifecycleOwnerRef = null;
                return;
            }
            this._lifecycleOwnerRef = new WeakReference<>(lifecycleOwner);
            InterfaceC3006b<? extends Object> interfaceC3006b = (InterfaceC3006b) this.listener.getTarget();
            if (interfaceC3006b != null) {
                startCollection(lifecycleOwner, interfaceC3006b);
            }
        }

        @Override // androidx.databinding.ObservableReference
        public void addListener(@Nullable InterfaceC3006b<? extends Object> target) {
            LifecycleOwner lifecycleOwner;
            WeakReference<LifecycleOwner> weakReference = this._lifecycleOwnerRef;
            if (weakReference == null || (lifecycleOwner = weakReference.get()) == null) {
                return;
            }
            Intrinsics.checkNotNullExpressionValue(lifecycleOwner, "_lifecycleOwnerRef?.get() ?: return");
            if (target != null) {
                startCollection(lifecycleOwner, target);
            }
        }

        @Override // androidx.databinding.ObservableReference
        public void removeListener(@Nullable InterfaceC3006b<? extends Object> target) {
            InterfaceC3053d1 interfaceC3053d1 = this.observerJob;
            if (interfaceC3053d1 != null) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
            this.observerJob = null;
        }
    }

    private ViewDataBindingKtx() {
    }

    @JvmStatic
    @RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
    public static final boolean updateStateFlowRegistration(@NotNull ViewDataBinding viewDataBinding, int localFieldId, @Nullable InterfaceC3006b<?> observable) {
        Intrinsics.checkNotNullParameter(viewDataBinding, "viewDataBinding");
        viewDataBinding.mInStateFlowRegisterObserver = true;
        try {
            return viewDataBinding.updateRegistration(localFieldId, observable, CREATE_STATE_FLOW_LISTENER);
        } finally {
            viewDataBinding.mInStateFlowRegisterObserver = false;
        }
    }
}
