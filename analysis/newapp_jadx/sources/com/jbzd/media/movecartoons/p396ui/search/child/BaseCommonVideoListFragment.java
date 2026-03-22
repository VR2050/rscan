package com.jbzd.media.movecartoons.p396ui.search.child;

import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import java.util.HashMap;
import java.util.Iterator;
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
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b%\b&\u0018\u0000 ?2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001?B\u0007¢\u0006\u0004\b=\u0010>J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J)\u0010\b\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0006j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0007¢\u0006\u0004\b\b\u0010\tJ+\u0010\n\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0006j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0007H&¢\u0006\u0004\b\n\u0010\tJ\u001b\u0010\r\u001a\u00020\f2\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u001b\u0010\u0010\u001a\u00020\f2\n\b\u0002\u0010\u000f\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u0010\u0010\u000eJ\u001b\u0010\u0012\u001a\u00020\f2\n\b\u0002\u0010\u0011\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u0012\u0010\u000eJ\u001b\u0010\u0014\u001a\u00020\f2\n\b\u0002\u0010\u0013\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u0014\u0010\u000eJ\u001b\u0010\u0016\u001a\u00020\f2\n\b\u0002\u0010\u0015\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u0016\u0010\u000eJ\u001b\u0010\u0018\u001a\u00020\f2\n\b\u0002\u0010\u0017\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u0018\u0010\u000eJ\u001b\u0010\u001a\u001a\u00020\f2\n\b\u0002\u0010\u0019\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u001a\u0010\u000eJ\u0011\u0010\u001c\u001a\u0004\u0018\u00010\u001bH\u0016¢\u0006\u0004\b\u001c\u0010\u001dR9\u0010!\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0006j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u00078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010\tR\u001f\u0010$\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u001f\u001a\u0004\b#\u0010\u0005R\u001f\u0010'\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001f\u001a\u0004\b&\u0010\u0005R\u001f\u0010*\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u001f\u001a\u0004\b)\u0010\u0005R\u001f\u0010-\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u001f\u001a\u0004\b,\u0010\u0005R\u001f\u00100\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u001f\u001a\u0004\b/\u0010\u0005R\u001f\u00103\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u001f\u001a\u0004\b2\u0010\u0005R\u001f\u00106\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u001f\u001a\u0004\b5\u0010\u0005R\u001f\u00109\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001f\u001a\u0004\b8\u0010\u0005R\u001f\u0010<\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010\u001f\u001a\u0004\b;\u0010\u0005¨\u0006@"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/BaseCommonVideoListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "", "getRequestUrl", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "createEmptyRequestBody", "()Ljava/util/HashMap;", "getRequestBody", "user_id", "", "updateUserId", "(Ljava/lang/String;)V", "tags", "updateTags", "keywords", "updateKeywords", "order_by", "updateOrderBy", "video_type", "updateVideoType", "canvas", "updateCanvas", "group_id", "updateGroupId", "Lc/a/d1;", "request", "()Lc/a/d1;", "requestRoomParameter$delegate", "Lkotlin/Lazy;", "getRequestRoomParameter", "requestRoomParameter", "mDefaultUserId$delegate", "getMDefaultUserId", "mDefaultUserId", "mDefaultModuleId$delegate", "getMDefaultModuleId", "mDefaultModuleId", "mDefaultKeywords$delegate", "getMDefaultKeywords", "mDefaultKeywords", "mDefaultVideoType$delegate", "getMDefaultVideoType", "mDefaultVideoType", "mDefaultCategoryId$delegate", "getMDefaultCategoryId", "mDefaultCategoryId", "mDefaultCanvas$delegate", "getMDefaultCanvas", "mDefaultCanvas", "mDefaultGroupId$delegate", "getMDefaultGroupId", "mDefaultGroupId", "mDefaultTags$delegate", "getMDefaultTags", "mDefaultTags", "mDefaultOrderBy$delegate", "getMDefaultOrderBy", "mDefaultOrderBy", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseCommonVideoListFragment extends BaseListFragment<VideoItemBean> {

    @NotNull
    public static final String KEY_CANVAS = "canvas";

    @NotNull
    public static final String KEY_CATEGORY_ID = "cat_id";

    @NotNull
    public static final String KEY_GROUP_ID = "group_id";

    @NotNull
    public static final String KEY_IDS = "ids";

    @NotNull
    public static final String KEY_INTENT_MAP = "params_map";

    @NotNull
    public static final String KEY_ISHOT = "is_hot";

    @NotNull
    public static final String KEY_ISNEW = "is_new";

    @NotNull
    public static final String KEY_KEYWORDS = "keywords";

    @NotNull
    public static final String KEY_MODULE_ID = "module_id";

    @NotNull
    public static final String KEY_ORDER_BY = "order";

    @NotNull
    public static final String KEY_PAGE = "page";

    @NotNull
    public static final String KEY_PAGE_SIZE = "page_size";

    @NotNull
    public static final String KEY_PAY_TYPE = "pay_type";

    @NotNull
    public static final String KEY_POSITION = "position";

    @NotNull
    public static final String KEY_TAGS = "tag_id";

    @NotNull
    public static final String KEY_USER_ID = "user_id";

    @NotNull
    public static final String KEY_VIDEO_TYPE = "video_type";

    @NotNull
    public static final String PAGE_CHAPTER = "page_chapter";

    /* renamed from: mDefaultKeywords$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultKeywords = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultKeywords$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("keywords");
        }
    });

    /* renamed from: mDefaultUserId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultUserId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultUserId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("user_id");
        }
    });

    /* renamed from: mDefaultTags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultTags = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultTags$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("tag_id");
        }
    });

    /* renamed from: mDefaultOrderBy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultOrderBy = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultOrderBy$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("order");
        }
    });

    /* renamed from: mDefaultCanvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultCanvas = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultCanvas$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("canvas");
        }
    });

    /* renamed from: mDefaultGroupId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultGroupId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultGroupId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("group_id");
        }
    });

    /* renamed from: mDefaultVideoType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultVideoType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultVideoType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("video_type");
        }
    });

    /* renamed from: mDefaultCategoryId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultCategoryId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultCategoryId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("cat_id");
        }
    });

    /* renamed from: mDefaultModuleId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultModuleId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$mDefaultModuleId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseCommonVideoListFragment.this.getRequestRoomParameter().get("module_id");
        }
    });

    /* renamed from: requestRoomParameter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy requestRoomParameter = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$requestRoomParameter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return BaseCommonVideoListFragment.this.getRequestBody();
        }
    });

    public static /* synthetic */ void updateCanvas$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateCanvas");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateCanvas(str);
    }

    public static /* synthetic */ void updateGroupId$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateGroupId");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateGroupId(str);
    }

    public static /* synthetic */ void updateKeywords$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateKeywords");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateKeywords(str);
    }

    public static /* synthetic */ void updateOrderBy$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateOrderBy");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateOrderBy(str);
    }

    public static /* synthetic */ void updateTags$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateTags");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateTags(str);
    }

    public static /* synthetic */ void updateUserId$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateUserId");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateUserId(str);
    }

    public static /* synthetic */ void updateVideoType$default(BaseCommonVideoListFragment baseCommonVideoListFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateVideoType");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseCommonVideoListFragment.updateVideoType(str);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final HashMap<String, String> createEmptyRequestBody() {
        HashMap<String, String> m596R = C1499a.m596R("user_id", "", "keywords", "");
        m596R.put("tag_id", "");
        m596R.put("order", "");
        m596R.put("canvas", "");
        m596R.put("group_id", "");
        m596R.put("video_type", "");
        m596R.put("cat_id", "");
        m596R.put("module_id", "");
        return m596R;
    }

    @Nullable
    public final String getMDefaultCanvas() {
        return (String) this.mDefaultCanvas.getValue();
    }

    @Nullable
    public final String getMDefaultCategoryId() {
        return (String) this.mDefaultCategoryId.getValue();
    }

    @Nullable
    public final String getMDefaultGroupId() {
        return (String) this.mDefaultGroupId.getValue();
    }

    @Nullable
    public final String getMDefaultKeywords() {
        return (String) this.mDefaultKeywords.getValue();
    }

    @Nullable
    public final String getMDefaultModuleId() {
        return (String) this.mDefaultModuleId.getValue();
    }

    @Nullable
    public final String getMDefaultOrderBy() {
        return (String) this.mDefaultOrderBy.getValue();
    }

    @Nullable
    public final String getMDefaultTags() {
        return (String) this.mDefaultTags.getValue();
    }

    @Nullable
    public final String getMDefaultUserId() {
        return (String) this.mDefaultUserId.getValue();
    }

    @Nullable
    public final String getMDefaultVideoType() {
        return (String) this.mDefaultVideoType.getValue();
    }

    @NotNull
    public abstract HashMap<String, String> getRequestBody();

    @NotNull
    public final HashMap<String, String> getRequestRoomParameter() {
        return (HashMap) this.requestRoomParameter.getValue();
    }

    @NotNull
    public String getRequestUrl() {
        return "movie/search";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        getRequestRoomParameter().put("page", String.valueOf(getCurrentPage()));
        getRequestRoomParameter().put("ad_code", "video_mix_vertical");
        final int currentPage = getCurrentPage();
        return C0917a.m222f(C0917a.f372a, getRequestUrl(), VideoItemBean.class, getRequestRoomParameter(), new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$request$1
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
                if (list != null) {
                    int i2 = currentPage;
                    Iterator<T> it = list.iterator();
                    while (it.hasNext()) {
                        ((VideoItemBean) it.next()).realPage = i2;
                    }
                }
                Integer valueOf = list == null ? null : Integer.valueOf(list.size());
                Intrinsics.checkNotNull(valueOf);
                if (valueOf.intValue() > 2) {
                    BaseCommonVideoListFragment.this.didRequestComplete(list);
                    return;
                }
                Integer valueOf2 = list == null ? null : Integer.valueOf(list.size());
                Intrinsics.checkNotNull(valueOf2);
                if (valueOf2.intValue() == 1) {
                    C1318f loadMoreModule = BaseCommonVideoListFragment.this.getAdapter().getLoadMoreModule();
                    if (loadMoreModule != null) {
                        C1318f.m324h(loadMoreModule, false, 1, null);
                    }
                    SwipeRefreshLayout mSwipeLayout = BaseCommonVideoListFragment.this.getMSwipeLayout();
                    if (mSwipeLayout != null) {
                        mSwipeLayout.setRefreshing(false);
                    }
                    BaseCommonVideoListFragment.this.didRequestComplete(list);
                    return;
                }
                C1318f loadMoreModule2 = BaseCommonVideoListFragment.this.getAdapter().getLoadMoreModule();
                if (loadMoreModule2 != null) {
                    C1318f.m324h(loadMoreModule2, false, 1, null);
                }
                SwipeRefreshLayout mSwipeLayout2 = BaseCommonVideoListFragment.this.getMSwipeLayout();
                if (mSwipeLayout2 != null) {
                    mSwipeLayout2.setRefreshing(false);
                }
                BaseCommonVideoListFragment.this.showEmptyDataView();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseCommonVideoListFragment$request$2
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
                BaseCommonVideoListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    public void updateCanvas(@Nullable String canvas) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (canvas == null) {
            canvas = "";
        }
        requestRoomParameter.put("canvas", canvas);
        reset();
    }

    public void updateGroupId(@Nullable String group_id) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (group_id == null) {
            group_id = "";
        }
        requestRoomParameter.put("module_id", group_id);
        reset();
    }

    public void updateKeywords(@Nullable String keywords) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (keywords == null) {
            keywords = "";
        }
        requestRoomParameter.put("keywords", keywords);
        reset();
    }

    public void updateOrderBy(@Nullable String order_by) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (order_by == null) {
            order_by = "";
        }
        requestRoomParameter.put("order", order_by);
        reset();
    }

    public void updateTags(@Nullable String tags) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (tags == null) {
            tags = "";
        }
        requestRoomParameter.put("tag_id", tags);
        reset();
    }

    public void updateUserId(@Nullable String user_id) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (user_id == null) {
            user_id = "";
        }
        requestRoomParameter.put("user_id", user_id);
        reset();
    }

    public void updateVideoType(@Nullable String video_type) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (video_type == null) {
            video_type = "";
        }
        requestRoomParameter.put("video_type", video_type);
        reset();
    }
}
