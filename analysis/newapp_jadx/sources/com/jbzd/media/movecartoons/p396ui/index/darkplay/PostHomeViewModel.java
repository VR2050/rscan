package com.jbzd.media.movecartoons.p396ui.index.darkplay;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
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
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u001b\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u001f\u0010\n\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bR)\u0010\u0013\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u000e0\r0\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012R\u0018\u0010\u0015\u001a\u0004\u0018\u00010\u00148\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016R#\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00170\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0010\u001a\u0004\b\u0019\u0010\u0012¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/PostHomeViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "filter", "", "hasLoading", "postHome", "(Ljava/lang/String;Z)V", "Landroidx/lifecycle/MutableLiveData;", "", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "mPostListBean$delegate", "Lkotlin/Lazy;", "getMPostListBean", "()Landroidx/lifecycle/MutableLiveData;", "mPostListBean", "Lc/a/d1;", "job", "Lc/a/d1;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse;", "mPostHomeResponse$delegate", "getMPostHomeResponse", "mPostHomeResponse", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostHomeViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: mPostHomeResponse$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostHomeResponse = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PostHomeResponse>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.PostHomeViewModel$mPostHomeResponse$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PostHomeResponse> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mPostListBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostListBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends PostListBean>>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.PostHomeViewModel$mPostListBean$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends PostListBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    public static /* synthetic */ void postHome$default(PostHomeViewModel postHomeViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        postHomeViewModel.postHome(str, z);
    }

    @NotNull
    public final MutableLiveData<PostHomeResponse> getMPostHomeResponse() {
        return (MutableLiveData) this.mPostHomeResponse.getValue();
    }

    @NotNull
    public final MutableLiveData<List<PostListBean>> getMPostListBean() {
        return (MutableLiveData) this.mPostListBean.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }

    public final void postHome(@NotNull String filter, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(filter, "filter");
        HashMap hashMap = new HashMap();
        hashMap.put("filter", filter);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "post/home", PostHomeResponse.class, hashMap, new Function1<PostHomeResponse, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.PostHomeViewModel$postHome$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PostHomeResponse postHomeResponse) {
                invoke2(postHomeResponse);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PostHomeResponse postHomeResponse) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                if (postHomeResponse != null) {
                    this.getMPostHomeResponse().setValue(postHomeResponse);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.PostHomeViewModel$postHome$3
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
            }
        }, false, false, null, false, 480);
    }
}
