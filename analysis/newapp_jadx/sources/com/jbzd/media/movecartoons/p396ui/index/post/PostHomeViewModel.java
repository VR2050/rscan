package com.jbzd.media.movecartoons.p396ui.index.post;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.PostCategoryDetailBean;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment;
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
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000l\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b<\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J'\u0010\u000b\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u00062\b\b\u0002\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\u000e\u001a\u00020\u00022\u0006\u0010\r\u001a\u00020\u00062\b\b\u0002\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000e\u0010\u000fJ\u001f\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00062\b\b\u0002\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u0011\u0010\u000fJ\u0015\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\u0006¢\u0006\u0004\b\u0013\u0010\u0014Je\u0010 \u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00062%\b\u0002\u0010\u001b\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0017¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00020\u00162'\b\u0002\u0010\u001f\u001a!\u0012\u0017\u0012\u00150\u001cj\u0002`\u001d¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00020\u0016¢\u0006\u0004\b \u0010!R)\u0010)\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020$0#0\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(R\u0018\u0010+\u001a\u0004\u0018\u00010*8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b+\u0010,R#\u00100\u001a\b\u0012\u0004\u0012\u00020-0\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b.\u0010&\u001a\u0004\b/\u0010(R#\u00103\u001a\b\u0012\u0004\u0012\u00020\u00060\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010&\u001a\u0004\b2\u0010(R#\u00107\u001a\b\u0012\u0004\u0012\u0002040\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b5\u0010&\u001a\u0004\b6\u0010(R)\u0010;\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u0002080#0\"8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b9\u0010&\u001a\u0004\b:\u0010(¨\u0006="}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "userId", "currentPage", "", "hasLoading", "postSearch", "(Ljava/lang/String;Ljava/lang/String;Z)V", "filter", "postHome", "(Ljava/lang/String;Z)V", "page", "userUp", BaseCommonPostListFragment.KEY_BLOCK_ID, "postCategoryHome", "(Ljava/lang/String;)V", "object_id", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "response", FindBean.status_success, "Ljava/lang/Exception;", "Lkotlin/Exception;", C1568e.f1949a, "error", "followBlock", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "Landroidx/lifecycle/MutableLiveData;", "", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$HLSFollowerBean;", "mHLSFollowerBeans$delegate", "Lkotlin/Lazy;", "getMHLSFollowerBeans", "()Landroidx/lifecycle/MutableLiveData;", "mHLSFollowerBeans", "Lc/a/d1;", "job", "Lc/a/d1;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse;", "mPostHomeResponse$delegate", "getMPostHomeResponse", "mPostHomeResponse", "currentBloggerId$delegate", "getCurrentBloggerId", "currentBloggerId", "Lcom/jbzd/media/movecartoons/bean/response/PostCategoryDetailBean;", "mPostCategoryDetailBean$delegate", "getMPostCategoryDetailBean", "mPostCategoryDetailBean", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "mPostListBean$delegate", "getMPostListBean", "mPostListBean", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostHomeViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: mPostHomeResponse$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostHomeResponse = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PostHomeResponse>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$mPostHomeResponse$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PostHomeResponse> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: currentBloggerId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy currentBloggerId = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$currentBloggerId$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mHLSFollowerBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mHLSFollowerBeans = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends PostHomeResponse.HLSFollowerBean>>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$mHLSFollowerBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends PostHomeResponse.HLSFollowerBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mPostCategoryDetailBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostCategoryDetailBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PostCategoryDetailBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$mPostCategoryDetailBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PostCategoryDetailBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mPostListBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostListBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends PostListBean>>>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$mPostListBean$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends PostListBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void followBlock$default(PostHomeViewModel postHomeViewModel, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$followBlock$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$followBlock$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        postHomeViewModel.followBlock(str, function1, function12);
    }

    public static /* synthetic */ void postHome$default(PostHomeViewModel postHomeViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        postHomeViewModel.postHome(str, z);
    }

    public static /* synthetic */ void postSearch$default(PostHomeViewModel postHomeViewModel, String str, String str2, boolean z, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            z = true;
        }
        postHomeViewModel.postSearch(str, str2, z);
    }

    public static /* synthetic */ void userUp$default(PostHomeViewModel postHomeViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        postHomeViewModel.userUp(str, z);
    }

    public final void followBlock(@NotNull String object_id, @NotNull final Function1<Object, Unit> success, @NotNull final Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(object_id, "object_id");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        HashMap hashMap = new HashMap();
        hashMap.put("object_id", object_id);
        hashMap.put("object_type", "post_category");
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "system/doFollow", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$followBlock$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                success.invoke(str);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$followBlock$5
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                error.invoke(it);
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<String> getCurrentBloggerId() {
        return (MutableLiveData) this.currentBloggerId.getValue();
    }

    @NotNull
    public final MutableLiveData<List<PostHomeResponse.HLSFollowerBean>> getMHLSFollowerBeans() {
        return (MutableLiveData) this.mHLSFollowerBeans.getValue();
    }

    @NotNull
    public final MutableLiveData<PostCategoryDetailBean> getMPostCategoryDetailBean() {
        return (MutableLiveData) this.mPostCategoryDetailBean.getValue();
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

    public final void postCategoryHome(@NotNull String block_id) {
        Intrinsics.checkNotNullParameter(block_id, "block_id");
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", block_id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "post/category", PostCategoryDetailBean.class, m595Q, new Function1<PostCategoryDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$postCategoryHome$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PostCategoryDetailBean postCategoryDetailBean) {
                invoke2(postCategoryDetailBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PostCategoryDetailBean postCategoryDetailBean) {
                if (postCategoryDetailBean != null) {
                    PostHomeViewModel.this.getMPostCategoryDetailBean().setValue(postCategoryDetailBean);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$postCategoryHome$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    public final void postHome(@NotNull String filter, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(filter, "filter");
        HashMap hashMap = new HashMap();
        hashMap.put("filter", filter);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "post/home", PostHomeResponse.class, hashMap, new Function1<PostHomeResponse, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$postHome$2
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
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$postHome$3
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

    public final void postSearch(@NotNull String userId, @NotNull String currentPage, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(userId, "userId");
        Intrinsics.checkNotNullParameter(currentPage, "currentPage");
        HashMap hashMap = new HashMap();
        hashMap.put("home_id", userId);
        hashMap.put("page", currentPage);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "post/search", PostHomeResponse.class, hashMap, new Function1<PostHomeResponse, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$postSearch$2
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
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$postSearch$3
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

    public final void userUp(@NotNull String page, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(page, "page");
        HashMap hashMap = new HashMap();
        hashMap.put("page", page);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m222f(C0917a.f372a, "user/up", PostHomeResponse.HLSFollowerBean.class, hashMap, new Function1<List<? extends PostHomeResponse.HLSFollowerBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$userUp$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends PostHomeResponse.HLSFollowerBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends PostHomeResponse.HLSFollowerBean> list) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                if (list != null) {
                    this.getMHLSFollowerBeans().setValue(list);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeViewModel$userUp$3
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
