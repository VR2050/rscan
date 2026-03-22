package com.jbzd.media.movecartoons.p396ui.index.home.model;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.HashMap;
import java.util.List;
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
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0019\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u0017\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\b\u0010\tJ\u0015\u0010\f\u001a\u00020\u00022\u0006\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\f\u0010\rR\u0018\u0010\u000f\u001a\u0004\u0018\u00010\u000e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u0010\u0010R)\u0010\u0018\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00130\u00120\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/model/TopViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "hasLoading", "loadInfo", "(Z)V", "", "tagIds", "updateUserSelectedTags", "(Ljava/lang/String;)V", "Lc/a/d1;", "job", "Lc/a/d1;", "Landroidx/lifecycle/MutableLiveData;", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "tags$delegate", "Lkotlin/Lazy;", "getTags", "()Landroidx/lifecycle/MutableLiveData;", "tags", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TopViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: tags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tags = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends TagBean>>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.model.TopViewModel$tags$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends TagBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    public static /* synthetic */ void loadInfo$default(TopViewModel topViewModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        topViewModel.loadInfo(z);
    }

    @NotNull
    public final MutableLiveData<List<TagBean>> getTags() {
        return (MutableLiveData) this.tags.getValue();
    }

    public final void loadInfo(boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap m595Q = C1499a.m595Q("order_by", "is_recommend");
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m222f(C0917a.f372a, "tag/list", TagBean.class, m595Q, new Function1<List<? extends TagBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.model.TopViewModel$loadInfo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends TagBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends TagBean> list) {
                TopViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                TopViewModel.this.getTags().setValue(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.model.TopViewModel$loadInfo$3
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
                TopViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
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

    public final void updateUserSelectedTags(@NotNull String tagIds) {
        Intrinsics.checkNotNullParameter(tagIds, "tagIds");
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("field", "tag_ids", "value", tagIds);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/updateInfo", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.model.TopViewModel$updateUserSelectedTags$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
            }
        }, null, false, false, null, false, 496);
    }
}
