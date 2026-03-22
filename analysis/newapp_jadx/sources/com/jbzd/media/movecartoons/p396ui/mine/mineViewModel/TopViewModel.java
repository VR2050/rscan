package com.jbzd.media.movecartoons.p396ui.mine.mineViewModel;

import androidx.lifecycle.MutableLiveData;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0013\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004R#\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00070\u00068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000bR\u0018\u0010\u000e\u001a\u0004\u0018\u00010\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000e\u0010\u000fR#\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00070\u00068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\t\u001a\u0004\b\u0011\u0010\u000b¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/mineViewModel/TopViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "Landroidx/lifecycle/MutableLiveData;", "", "historyUpdateSuccess$delegate", "Lkotlin/Lazy;", "getHistoryUpdateSuccess", "()Landroidx/lifecycle/MutableLiveData;", "historyUpdateSuccess", "Lc/a/d1;", "job", "Lc/a/d1;", "cacheAllData$delegate", "getCacheAllData", "cacheAllData", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TopViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: historyUpdateSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy historyUpdateSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.mineViewModel.TopViewModel$historyUpdateSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: cacheAllData$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy cacheAllData = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.mineViewModel.TopViewModel$cacheAllData$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @NotNull
    public final MutableLiveData<Boolean> getCacheAllData() {
        return (MutableLiveData) this.cacheAllData.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getHistoryUpdateSuccess() {
        return (MutableLiveData) this.historyUpdateSuccess.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }
}
