package com.jbzd.media.movecartoons.p396ui.search.model;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.ArrayList;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b0\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J;\u0010\f\u001a\u00020\u00022\"\u0010\t\u001a\u001e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\u00070\u0006j\u000e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\u0007`\b2\b\b\u0002\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\f\u0010\rJ;\u0010\u000e\u001a\u00020\u00022\"\u0010\t\u001a\u001e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\u00070\u0006j\u000e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\u0007`\b2\b\b\u0002\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\u000e\u0010\rJ\u0017\u0010\u000f\u001a\u00020\u00022\b\b\u0002\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\u000f\u0010\u0010JO\u0010\u0015\u001a\u00020\u00022\"\u0010\t\u001a\u001e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\u00070\u0006j\u000e\u0012\u0004\u0012\u00020\u0007\u0012\u0004\u0012\u00020\u0007`\b2\u0012\u0010\u0014\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00130\u00120\u00112\b\b\u0002\u0010\u000b\u001a\u00020\n¢\u0006\u0004\b\u0015\u0010\u0016R)\u0010\u001b\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00130\u00120\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001aR\u0018\u0010\u001d\u001a\u0004\u0018\u00010\u001c8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001d\u0010\u001eR#\u0010!\u001a\b\u0012\u0004\u0012\u00020\n0\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0018\u001a\u0004\b \u0010\u001aR)\u0010%\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\"0\u00120\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u0018\u001a\u0004\b$\u0010\u001aR)\u0010(\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00130\u00120\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u0018\u001a\u0004\b'\u0010\u001aR)\u0010+\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00130\u00120\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0018\u001a\u0004\b*\u0010\u001aR#\u0010.\u001a\b\u0012\u0004\u0012\u00020\n0\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u0018\u001a\u0004\b-\u0010\u001aR\u0018\u0010/\u001a\u0004\u0018\u00010\u001c8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u0010\u001e¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/model/SearchResultModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "body", "", "hasLoading", "doSearchLongVideo", "(Ljava/util/HashMap;Z)V", "doSearchShortVideo", "getGuess", "(Z)V", "Landroidx/lifecycle/MutableLiveData;", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "videoItemBeans", "doSearch", "(Ljava/util/HashMap;Landroidx/lifecycle/MutableLiveData;Z)V", "guessVideoItemBeans$delegate", "Lkotlin/Lazy;", "getGuessVideoItemBeans", "()Landroidx/lifecycle/MutableLiveData;", "guessVideoItemBeans", "Lc/a/d1;", "guessJob", "Lc/a/d1;", "buySuccess$delegate", "getBuySuccess", "buySuccess", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "postListBeans$delegate", "getPostListBeans", "postListBeans", "longVideoItemBeans$delegate", "getLongVideoItemBeans", "longVideoItemBeans", "shortVideoItemBeans$delegate", "getShortVideoItemBeans", "shortVideoItemBeans", "success$delegate", "getSuccess", FindBean.status_success, "resultJob", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchResultModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 guessJob;

    @Nullable
    private InterfaceC3053d1 resultJob;

    /* renamed from: postListBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy postListBeans = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends PostListBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$postListBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends PostListBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: buySuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy buySuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$buySuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: longVideoItemBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy longVideoItemBeans = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends VideoItemBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$longVideoItemBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends VideoItemBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: shortVideoItemBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy shortVideoItemBeans = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends VideoItemBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$shortVideoItemBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends VideoItemBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: guessVideoItemBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy guessVideoItemBeans = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends VideoItemBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$guessVideoItemBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends VideoItemBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: success$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy success = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$success$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.TRUE);
        }
    });

    public static /* synthetic */ void doSearch$default(SearchResultModel searchResultModel, HashMap hashMap, MutableLiveData mutableLiveData, boolean z, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            z = true;
        }
        searchResultModel.doSearch(hashMap, mutableLiveData, z);
    }

    public static /* synthetic */ void doSearchLongVideo$default(SearchResultModel searchResultModel, HashMap hashMap, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        searchResultModel.doSearchLongVideo(hashMap, z);
    }

    public static /* synthetic */ void doSearchShortVideo$default(SearchResultModel searchResultModel, HashMap hashMap, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        searchResultModel.doSearchShortVideo(hashMap, z);
    }

    public static /* synthetic */ void getGuess$default(SearchResultModel searchResultModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        searchResultModel.getGuess(z);
    }

    public final void doSearch(@NotNull HashMap<String, String> body, @NotNull final MutableLiveData<List<VideoItemBean>> videoItemBeans, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(body, "body");
        Intrinsics.checkNotNullParameter(videoItemBeans, "videoItemBeans");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.resultJob = C0917a.m222f(C0917a.f372a, "movie/search", VideoItemBean.class, body, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$doSearch$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends VideoItemBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends VideoItemBean> list) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                videoItemBeans.setValue(list);
                ArrayList arrayList = new ArrayList();
                Intrinsics.checkNotNull(list);
                for (VideoItemBean videoItemBean : list) {
                    if (videoItemBean.f10000id != null) {
                        arrayList.add(videoItemBean);
                    }
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$doSearch$2
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

    public final void doSearchLongVideo(@NotNull HashMap<String, String> body, boolean hasLoading) {
        Intrinsics.checkNotNullParameter(body, "body");
        body.put("canvas", "long");
        doSearch(body, getLongVideoItemBeans(), hasLoading);
    }

    public final void doSearchShortVideo(@NotNull HashMap<String, String> body, boolean hasLoading) {
        Intrinsics.checkNotNullParameter(body, "body");
        body.put("canvas", "short");
        doSearch(body, getShortVideoItemBeans(), hasLoading);
    }

    @NotNull
    public final MutableLiveData<Boolean> getBuySuccess() {
        return (MutableLiveData) this.buySuccess.getValue();
    }

    public final void getGuess(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.guessJob = C0917a.m222f(C0917a.f372a, "video/guess", VideoItemBean.class, new HashMap(), new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$getGuess$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends VideoItemBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends VideoItemBean> list) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getGuessVideoItemBeans().setValue(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.SearchResultModel$getGuess$2
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

    @NotNull
    public final MutableLiveData<List<VideoItemBean>> getGuessVideoItemBeans() {
        return (MutableLiveData) this.guessVideoItemBeans.getValue();
    }

    @NotNull
    public final MutableLiveData<List<VideoItemBean>> getLongVideoItemBeans() {
        return (MutableLiveData) this.longVideoItemBeans.getValue();
    }

    @NotNull
    public final MutableLiveData<List<PostListBean>> getPostListBeans() {
        return (MutableLiveData) this.postListBeans.getValue();
    }

    @NotNull
    public final MutableLiveData<List<VideoItemBean>> getShortVideoItemBeans() {
        return (MutableLiveData) this.shortVideoItemBeans.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getSuccess() {
        return (MutableLiveData) this.success.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.resultJob);
        cancelJob(this.guessJob);
    }
}
