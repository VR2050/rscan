package com.qunidayede.supportlibrary.core.viewmodel;

import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.OnLifecycleEvent;
import androidx.lifecycle.ViewModel;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p331b.p335f.C2849b;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\b&\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u0019\u0010\u0005J\r\u0010\u0004\u001a\u00020\u0003¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H'¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\u0007\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\b\u0010\u0005J%\u0010\f\u001a\u00020\u00032\u0016\u0010\u000b\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\n0\t\"\u0004\u0018\u00010\n¢\u0006\u0004\b\f\u0010\rR#\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u000f0\u000e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R#\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00150\u000e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0011\u001a\u0004\b\u0017\u0010\u0013¨\u0006\u001a"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "Landroidx/lifecycle/ViewModel;", "Landroidx/lifecycle/LifecycleObserver;", "", "dismissLineDialog", "()V", "onCreate", "onResume", "onDestroy", "", "Lc/a/d1;", "jobs", "cancelJob", "([Lkotlinx/coroutines/Job;)V", "Landroidx/lifecycle/MutableLiveData;", "Lb/w/b/b/f/a;", "loading$delegate", "Lkotlin/Lazy;", "getLoading", "()Landroidx/lifecycle/MutableLiveData;", "loading", "Lb/w/b/b/f/b;", "netError$delegate", "getNetError", "netError", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseViewModel extends ViewModel implements LifecycleObserver {

    /* renamed from: loading$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loading = LazyKt__LazyJVMKt.lazy(C4051a.f10328c);

    /* renamed from: netError$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy netError = LazyKt__LazyJVMKt.lazy(C4052b.f10329c);

    /* renamed from: com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel$a */
    public static final class C4051a extends Lambda implements Function0<MutableLiveData<C2848a>> {

        /* renamed from: c */
        public static final C4051a f10328c = new C4051a();

        public C4051a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public MutableLiveData<C2848a> invoke() {
            return new MutableLiveData<>(new C2848a(false, null, false, false, 15));
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel$b */
    public static final class C4052b extends Lambda implements Function0<MutableLiveData<C2849b>> {

        /* renamed from: c */
        public static final C4052b f10329c = new C4052b();

        public C4052b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public MutableLiveData<C2849b> invoke() {
            return new MutableLiveData<>();
        }
    }

    public final void cancelJob(@NotNull InterfaceC3053d1... jobs) {
        Intrinsics.checkNotNullParameter(jobs, "jobs");
        for (InterfaceC3053d1 interfaceC3053d1 : jobs) {
            if (interfaceC3053d1 != null && interfaceC3053d1.mo3507b()) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
        }
    }

    public final void dismissLineDialog() {
        getLoading().postValue(new C2848a(false, null, false, false, 14));
    }

    @NotNull
    public final MutableLiveData<C2848a> getLoading() {
        return (MutableLiveData) this.loading.getValue();
    }

    @NotNull
    public final MutableLiveData<C2849b> getNetError() {
        return (MutableLiveData) this.netError.getValue();
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_CREATE)
    public abstract void onCreate();

    @OnLifecycleEvent(Lifecycle.Event.ON_DESTROY)
    public void onDestroy() {
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_RESUME)
    public void onResume() {
    }
}
