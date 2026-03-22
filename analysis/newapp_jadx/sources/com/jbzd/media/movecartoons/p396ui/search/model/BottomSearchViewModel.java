package com.jbzd.media.movecartoons.p396ui.search.model;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.SearchBottomBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0017\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u0017\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\b\u0010\tR#\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR#\u0010\u0013\u001a\b\u0012\u0004\u0012\u00020\u00060\n8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\r\u001a\u0004\b\u0012\u0010\u000fR\u0018\u0010\u0015\u001a\u0004\u0018\u00010\u00148\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/model/BottomSearchViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "hasLoading", "loadInfo", "(Z)V", "Landroidx/lifecycle/MutableLiveData;", "Lcom/jbzd/media/movecartoons/bean/response/SearchBottomBean;", "infoBean$delegate", "Lkotlin/Lazy;", "getInfoBean", "()Landroidx/lifecycle/MutableLiveData;", "infoBean", "success$delegate", "getSuccess", FindBean.status_success, "Lc/a/d1;", "job", "Lc/a/d1;", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BottomSearchViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: infoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy infoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<SearchBottomBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.BottomSearchViewModel$infoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<SearchBottomBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: success$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy success = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.BottomSearchViewModel$success$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.TRUE);
        }
    });

    public static /* synthetic */ void loadInfo$default(BottomSearchViewModel bottomSearchViewModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        bottomSearchViewModel.loadInfo(z);
    }

    @NotNull
    public final MutableLiveData<SearchBottomBean> getInfoBean() {
        return (MutableLiveData) this.infoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getSuccess() {
        return (MutableLiveData) this.success.getValue();
    }

    public final void loadInfo(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.job = C0917a.m221e(C0917a.f372a, "video/searchRecommend", SearchBottomBean.class, new HashMap(), new Function1<SearchBottomBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.BottomSearchViewModel$loadInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(SearchBottomBean searchBottomBean) {
                invoke2(searchBottomBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable SearchBottomBean searchBottomBean) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getInfoBean().setValue(searchBottomBean);
                this.getSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.BottomSearchViewModel$loadInfo$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
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
