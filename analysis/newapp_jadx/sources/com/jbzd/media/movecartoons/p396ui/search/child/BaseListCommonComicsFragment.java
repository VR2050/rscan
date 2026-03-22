package com.jbzd.media.movecartoons.p396ui.search.child;

import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsItemBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b%\b&\u0018\u0000 02\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00010B\u0007¢\u0006\u0004\b.\u0010/J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J)\u0010\b\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0006j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0007¢\u0006\u0004\b\b\u0010\tJ+\u0010\n\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0006j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0007H&¢\u0006\u0004\b\n\u0010\tJ\u001b\u0010\r\u001a\u00020\f2\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u001f\u0010\u0012\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0005R\u001f\u0010\u0015\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0010\u001a\u0004\b\u0014\u0010\u0005R\u001f\u0010\u0018\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0010\u001a\u0004\b\u0017\u0010\u0005R9\u0010\u001b\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0006j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u00078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u0010\u001a\u0004\b\u001a\u0010\tR\u001f\u0010\u001e\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0010\u001a\u0004\b\u001d\u0010\u0005R\u001f\u0010!\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0010\u001a\u0004\b \u0010\u0005R\u001f\u0010$\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u0010\u001a\u0004\b#\u0010\u0005R\u001f\u0010'\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u0010\u001a\u0004\b&\u0010\u0005R\u001f\u0010*\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0010\u001a\u0004\b)\u0010\u0005R\u001f\u0010-\u001a\u0004\u0018\u00010\u00038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u0010\u001a\u0004\b,\u0010\u0005¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/BaseListCommonComicsFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsItemBean;", "", "getRequestUrl", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "createEmptyRequestBody", "()Ljava/util/HashMap;", "getRequestBody", "order_by", "", "updateOrderBy", "(Ljava/lang/String;)V", "mDefaultCategoryId$delegate", "Lkotlin/Lazy;", "getMDefaultCategoryId", "mDefaultCategoryId", "mDefaultVideoType$delegate", "getMDefaultVideoType", "mDefaultVideoType", "mDefaultModuleId$delegate", "getMDefaultModuleId", "mDefaultModuleId", "requestRoomParameter$delegate", "getRequestRoomParameter", "requestRoomParameter", "mDefaultGroupId$delegate", "getMDefaultGroupId", "mDefaultGroupId", "mDefaultOrderBy$delegate", "getMDefaultOrderBy", "mDefaultOrderBy", "mDefaultTags$delegate", "getMDefaultTags", "mDefaultTags", "mDefaultKeywords$delegate", "getMDefaultKeywords", "mDefaultKeywords", "mDefaultCanvas$delegate", "getMDefaultCanvas", "mDefaultCanvas", "mDefaultUserId$delegate", "getMDefaultUserId", "mDefaultUserId", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseListCommonComicsFragment extends BaseListFragment<ComicsItemBean> {

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
    public static final String KEY_SHOW_TYPE = "show_type";

    @NotNull
    public static final String KEY_TAGS = "tag_id";

    @NotNull
    public static final String KEY_USER_ID = "user_id";

    @NotNull
    public static final String KEY_VIDEO_TYPE = "video_type";

    /* renamed from: mDefaultKeywords$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultKeywords = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultKeywords$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("keywords");
        }
    });

    /* renamed from: mDefaultUserId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultUserId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultUserId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("user_id");
        }
    });

    /* renamed from: mDefaultTags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultTags = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultTags$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("tag_id");
        }
    });

    /* renamed from: mDefaultOrderBy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultOrderBy = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultOrderBy$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("order");
        }
    });

    /* renamed from: mDefaultCanvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultCanvas = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultCanvas$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("canvas");
        }
    });

    /* renamed from: mDefaultGroupId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultGroupId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultGroupId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("group_id");
        }
    });

    /* renamed from: mDefaultVideoType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultVideoType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultVideoType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("video_type");
        }
    });

    /* renamed from: mDefaultCategoryId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultCategoryId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultCategoryId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("cat_id");
        }
    });

    /* renamed from: mDefaultModuleId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultModuleId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$mDefaultModuleId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return BaseListCommonComicsFragment.this.getRequestRoomParameter().get("module_id");
        }
    });

    /* renamed from: requestRoomParameter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy requestRoomParameter = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.search.child.BaseListCommonComicsFragment$requestRoomParameter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return BaseListCommonComicsFragment.this.getRequestBody();
        }
    });

    public static /* synthetic */ void updateOrderBy$default(BaseListCommonComicsFragment baseListCommonComicsFragment, String str, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: updateOrderBy");
        }
        if ((i2 & 1) != 0) {
            str = null;
        }
        baseListCommonComicsFragment.updateOrderBy(str);
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
        return "comics/search";
    }

    public void updateOrderBy(@Nullable String order_by) {
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (order_by == null) {
            order_by = "";
        }
        requestRoomParameter.put("order", order_by);
        getRequestRoomParameter().put("ad_code", "comic_list_ad");
        reset();
    }
}
