package com.jbzd.media.movecartoons.p396ui.index.post;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import androidx.core.view.GravityCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment$bloggerAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment$categoriesAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.post.PostHomeBottomFragment;
import com.jbzd.media.movecartoons.p396ui.index.post.block.ModulePostBlockActivity;
import com.jbzd.media.movecartoons.p396ui.index.view.BloodColorText;
import com.jbzd.media.movecartoons.p396ui.mine.MyFansAndFollowsActivity;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
import com.jbzd.media.movecartoons.utils.GravitySnapHelper;
import com.jbzd.media.movecartoons.utils.MyAdAdapter;
import com.jbzd.media.movecartoons.utils.SpaceViewItemLine;
import com.jbzd.media.movecartoons.view.RecyclerViewAtViewPager2;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH2;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseViewModelFragment;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007*\u0002DQ\u0018\u0000 n2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001nB\u0007¢\u0006\u0004\bm\u0010\u000fJ\u001f\u0010\u0007\u001a\u00020\u00062\u000e\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0010\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0011\u0010\u000fJ!\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0013\u001a\u00020\u00122\b\u0010\u0015\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u001d\u0010\"\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u001a\u001a\u0004\b \u0010!R\u001d\u0010'\u001a\u00020#8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u001a\u001a\u0004\b%\u0010&R\u001d\u0010,\u001a\u00020(8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u001a\u001a\u0004\b*\u0010+R\u001d\u0010/\u001a\u00020(8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u001a\u001a\u0004\b.\u0010+R\"\u00101\u001a\u0002008\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b1\u00102\u001a\u0004\b3\u00104\"\u0004\b5\u00106R\u001d\u00109\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001a\u001a\u0004\b8\u0010\rR\u0016\u0010;\u001a\u00020:8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b;\u0010<R\"\u0010>\u001a\u00020=8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b>\u0010?\u001a\u0004\b@\u0010A\"\u0004\bB\u0010CR\u001d\u0010H\u001a\u00020D8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u001a\u001a\u0004\bF\u0010GR\u001d\u0010K\u001a\u00020(8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010\u001a\u001a\u0004\bJ\u0010+R\u001d\u0010P\u001a\u00020L8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bM\u0010\u001a\u001a\u0004\bN\u0010OR\u001d\u0010U\u001a\u00020Q8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bR\u0010\u001a\u001a\u0004\bS\u0010TR)\u0010\\\u001a\u000e\u0012\u0004\u0012\u00020W\u0012\u0004\u0012\u00020X0V8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bY\u0010\u001a\u001a\u0004\bZ\u0010[R\u001d\u0010_\u001a\u00020L8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010\u001a\u001a\u0004\b^\u0010OR\u001d\u0010b\u001a\u00020L8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010\u001a\u001a\u0004\ba\u0010OR\u001d\u0010g\u001a\u00020c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bd\u0010\u001a\u001a\u0004\be\u0010fR\u001f\u0010l\u001a\u0004\u0018\u00010h8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bi\u0010\u001a\u001a\u0004\bj\u0010k¨\u0006o"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeViewModel;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "banners", "", "initBannerView", "(Ljava/util/List;)V", "", "getLayout", "()I", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeViewModel;", "initViews", "()V", "initEvents", "onDestroyView", "Landroid/view/View;", "view", "Landroid/os/Bundle;", "savedInstanceState", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "Lcom/jbzd/media/movecartoons/ui/index/view/BloodColorText;", "tv_title_block$delegate", "Lkotlin/Lazy;", "getTv_title_block", "()Lcom/jbzd/media/movecartoons/ui/index/view/BloodColorText;", "tv_title_block", "Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;", "bannerNew$delegate", "getBannerNew", "()Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;", "bannerNew", "Lcom/qunidayede/supportlibrary/widget/MarqueeTextView;", "tv_user_new_tips$delegate", "getTv_user_new_tips", "()Lcom/qunidayede/supportlibrary/widget/MarqueeTextView;", "tv_user_new_tips", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list_categories$delegate", "getRv_list_categories", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_list_categories", "rv_list_type$delegate", "getRv_list_type", "rv_list_type", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "mSearchPostListFragment", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "getMSearchPostListFragment", "()Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "setMSearchPostListFragment", "(Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;)V", "viewModel$delegate", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "mAdAdapter", "Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "mPostHomeBottomFragment", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "getMPostHomeBottomFragment", "()Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "setMPostHomeBottomFragment", "(Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;)V", "com/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$categoriesAdapter$2$1", "categoriesAdapter$delegate", "getCategoriesAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$categoriesAdapter$2$1;", "categoriesAdapter", "rv_bloggers$delegate", "getRv_bloggers", "rv_bloggers", "Landroid/widget/LinearLayout;", "ll_module_header_posthome$delegate", "getLl_module_header_posthome", "()Landroid/widget/LinearLayout;", "ll_module_header_posthome", "com/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$bloggerAdapter$2$1", "bloggerAdapter$delegate", "getBloggerAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$bloggerAdapter$2$1;", "bloggerAdapter", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$OrdersBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "orderTypeAdapter$delegate", "getOrderTypeAdapter", "()Lcom/chad/library/adapter/base/BaseQuickAdapter;", "orderTypeAdapter", "ll_posthome_categories$delegate", "getLl_posthome_categories", "ll_posthome_categories", "ll_post_blogger_hot$delegate", "getLl_post_blogger_hot", "ll_post_blogger_hot", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_bloggerMore$delegate", "getItv_bloggerMore", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_bloggerMore", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommunityTabSingleFragment extends BaseViewModelFragment<PostHomeViewModel> {

    @NotNull
    private static final String KEY_TAB = "tab_bean";

    /* renamed from: bannerNew$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bannerNew;

    /* renamed from: bloggerAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bloggerAdapter;

    /* renamed from: categoriesAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy categoriesAdapter;

    /* renamed from: itv_bloggerMore$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_bloggerMore;

    /* renamed from: ll_module_header_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_module_header_posthome;

    /* renamed from: ll_post_blogger_hot$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_post_blogger_hot;

    /* renamed from: ll_posthome_categories$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_posthome_categories;

    @NotNull
    private final MyAdAdapter mAdAdapter;
    public PostHomeBottomFragment mPostHomeBottomFragment;
    public CommonPostListFragment mSearchPostListFragment;

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = CommunityTabSingleFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: orderTypeAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy orderTypeAdapter;

    /* renamed from: rv_bloggers$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_bloggers;

    /* renamed from: rv_list_categories$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_list_categories;

    /* renamed from: rv_list_type$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_list_type;

    /* renamed from: tv_title_block$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_title_block;

    /* renamed from: tv_user_new_tips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_user_new_tips;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String search_type = "search_type";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0010\u0010\u0011J\u001f\u0010\u0007\u001a\u00020\u00062\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u0016\u0010\u000f\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000f\u0010\n¨\u0006\u0012"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "", "type", "Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment;", "search_type", "Ljava/lang/String;", "getSearch_type", "()Ljava/lang/String;", "setSearch_type", "(Ljava/lang/String;)V", "KEY_TAB", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getSearch_type() {
            return CommunityTabSingleFragment.search_type;
        }

        @NotNull
        public final CommunityTabSingleFragment newInstance(@Nullable MainMenusBean tabBean, @NotNull String type) {
            Intrinsics.checkNotNullParameter(type, "type");
            setSearch_type(type);
            CommunityTabSingleFragment communityTabSingleFragment = new CommunityTabSingleFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("tab_bean", tabBean);
            Unit unit = Unit.INSTANCE;
            communityTabSingleFragment.setArguments(bundle);
            return communityTabSingleFragment;
        }

        public final void setSearch_type(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            CommunityTabSingleFragment.search_type = str;
        }
    }

    public CommunityTabSingleFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$special$$inlined$viewModels$default$1
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Fragment invoke() {
                return Fragment.this;
            }
        };
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(PostHomeViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$special$$inlined$viewModels$default$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewModelStore invoke() {
                ViewModelStore viewModelStore = ((ViewModelStoreOwner) Function0.this.invoke()).getViewModelStore();
                Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "ownerProducer().viewModelStore");
                return viewModelStore;
            }
        }, null);
        this.ll_post_blogger_hot = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$ll_post_blogger_hot$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_post_blogger_hot);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.itv_bloggerMore = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$itv_bloggerMore$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageTextView invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_bloggerMore);
                Intrinsics.checkNotNull(imageTextView);
                return imageTextView;
            }
        });
        this.rv_bloggers = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$rv_bloggers$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_bloggers);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.ll_posthome_categories = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$ll_posthome_categories$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_posthome_categories);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.tv_title_block = LazyKt__LazyJVMKt.lazy(new Function0<BloodColorText>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$tv_title_block$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final BloodColorText invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                BloodColorText bloodColorText = view == null ? null : (BloodColorText) view.findViewById(R.id.tv_title_block);
                Intrinsics.checkNotNull(bloodColorText);
                return bloodColorText;
            }
        });
        this.rv_list_categories = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$rv_list_categories$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_list_categories);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.ll_module_header_posthome = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$ll_module_header_posthome$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_module_header_posthome);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.rv_list_type = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$rv_list_type$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_list_type);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.tv_user_new_tips = LazyKt__LazyJVMKt.lazy(new Function0<MarqueeTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$tv_user_new_tips$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final MarqueeTextView invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                MarqueeTextView marqueeTextView = view == null ? null : (MarqueeTextView) view.findViewById(R.id.tv_user_new_tips);
                Intrinsics.checkNotNull(marqueeTextView);
                return marqueeTextView;
            }
        });
        this.mAdAdapter = new MyAdAdapter();
        this.bannerNew = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerViewAtViewPager2>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$bannerNew$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerViewAtViewPager2 invoke() {
                View view = CommunityTabSingleFragment.this.getView();
                RecyclerViewAtViewPager2 recyclerViewAtViewPager2 = view == null ? null : (RecyclerViewAtViewPager2) view.findViewById(R.id.bannerNew);
                Intrinsics.checkNotNull(recyclerViewAtViewPager2);
                return recyclerViewAtViewPager2;
            }
        });
        this.categoriesAdapter = LazyKt__LazyJVMKt.lazy(new CommunityTabSingleFragment$categoriesAdapter$2(this));
        this.orderTypeAdapter = LazyKt__LazyJVMKt.lazy(new Function0<CommunityTabSingleFragment$orderTypeAdapter$2.C37701>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2

            @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0007*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0015¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\n\u001a\u00020\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000f¨\u0006\u0010"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$orderTypeAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$OrdersBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$OrdersBean;)V", "", "defaultIndex", "I", "getDefaultIndex", "()I", "setDefaultIndex", "(I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
            /* renamed from: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1 */
            public static final class C37701 extends BaseQuickAdapter<PostHomeResponse.OrdersBean, BaseViewHolder> {
                private int defaultIndex;
                public final /* synthetic */ CommunityTabSingleFragment this$0;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                public C37701(CommunityTabSingleFragment communityTabSingleFragment) {
                    super(R.layout.item_post_type, null, 2, null);
                    this.this$0 = communityTabSingleFragment;
                }

                public final int getDefaultIndex() {
                    return this.defaultIndex;
                }

                public final void setDefaultIndex(int i2) {
                    this.defaultIndex = i2;
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                @SuppressLint({"SuspiciousIndentation"})
                public void convert(@NotNull final BaseViewHolder helper, @NotNull final PostHomeResponse.OrdersBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    final CommunityTabSingleFragment communityTabSingleFragment = this.this$0;
                    View m3912b = helper.m3912b(R.id.view_item_posttype);
                    boolean z = true;
                    m3912b.setSelected(getDefaultIndex() == helper.getAdapterPosition());
                    helper.m3919i(R.id.tv_posttype_name, item.getName());
                    helper.m3912b(R.id.iv_posttype_bottom).setVisibility(m3912b.isSelected() ? 0 : 8);
                    if (getDefaultIndex() == helper.getAdapterPosition() && getDefaultIndex() == 0 && item.getFilter() != null) {
                        communityTabSingleFragment.getMTabBean();
                        CommonPostListFragment.Companion companion = CommonPostListFragment.INSTANCE;
                        String filter = item.getFilter();
                        HashMap<String, String> hashMap = new HashMap<>();
                        if (filter != null && filter.length() != 0) {
                            z = false;
                        }
                        if (!z) {
                            try {
                                JSONObject jSONObject = new JSONObject(filter);
                                Iterator<String> keys = jSONObject.keys();
                                while (keys.hasNext()) {
                                    String key = keys.next();
                                    String value = jSONObject.getString(key);
                                    Intrinsics.checkNotNullExpressionValue(key, "key");
                                    Intrinsics.checkNotNullExpressionValue(value, "value");
                                    hashMap.put(key, value);
                                }
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                        communityTabSingleFragment.setMSearchPostListFragment(companion.newInstance(hashMap, false, ""));
                        communityTabSingleFragment.getChildFragmentManager().beginTransaction().replace(R.id.frag_content, communityTabSingleFragment.getMSearchPostListFragment()).commit();
                    }
                    helper.m3918h(R.id.view_item_posttype, 
                    /*  JADX ERROR: Method code generation error
                        jadx.core.utils.exceptions.CodegenException: Error generate insn: 0x00c4: INVOKE 
                          (r11v0 'helper' com.chad.library.adapter.base.viewholder.BaseViewHolder)
                          (wrap:int:SGET  A[WRAPPED] com.qnmd.adnnm.da0yzo.R.id.view_item_posttype int)
                          (wrap:kotlin.jvm.functions.Function0<kotlin.Unit>:0x00c1: CONSTRUCTOR 
                          (r10v0 'this' com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1 A[DONT_INLINE, IMMUTABLE_TYPE, THIS])
                          (r11v0 'helper' com.chad.library.adapter.base.viewholder.BaseViewHolder A[DONT_INLINE])
                          (r12v0 'item' com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean A[DONT_INLINE])
                          (r0v2 'communityTabSingleFragment' com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment A[DONT_INLINE])
                         A[MD:(com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1, com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean, com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment):void (m), WRAPPED] (LINE:26) call: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1$convert$1$1.<init>(com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1, com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean, com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment):void type: CONSTRUCTOR)
                         VIRTUAL call: com.chad.library.adapter.base.viewholder.BaseViewHolder.h(int, kotlin.jvm.functions.Function0):com.chad.library.adapter.base.viewholder.BaseViewHolder A[MD:(int, kotlin.jvm.functions.Function0<kotlin.Unit>):com.chad.library.adapter.base.viewholder.BaseViewHolder (m)] (LINE:26) in method: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2.1.convert(com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean):void, file: classes2.dex
                        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:310)
                        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:273)
                        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:94)
                        	at jadx.core.dex.nodes.IBlock.generate(IBlock.java:15)
                        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                        	at jadx.core.dex.regions.Region.generate(Region.java:35)
                        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:66)
                        	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:297)
                        	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:276)
                        	at jadx.core.codegen.ClassGen.addMethodCode(ClassGen.java:406)
                        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:335)
                        	at jadx.core.codegen.ClassGen.lambda$addInnerClsAndMethods$3(ClassGen.java:301)
                        	at java.base/java.util.stream.ForEachOps$ForEachOp$OfRef.accept(ForEachOps.java:184)
                        	at java.base/java.util.ArrayList.forEach(ArrayList.java:1596)
                        	at java.base/java.util.stream.SortedOps$RefSortingSink.end(SortedOps.java:395)
                        	at java.base/java.util.stream.Sink$ChainedReference.end(Sink.java:261)
                        Caused by: jadx.core.utils.exceptions.JadxRuntimeException: Expected class to be processed at this point, class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1$convert$1$1, state: NOT_LOADED
                        	at jadx.core.dex.nodes.ClassNode.ensureProcessed(ClassNode.java:305)
                        	at jadx.core.codegen.InsnGen.inlineAnonymousConstructor(InsnGen.java:807)
                        	at jadx.core.codegen.InsnGen.makeConstructor(InsnGen.java:730)
                        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:418)
                        	at jadx.core.codegen.InsnGen.addWrappedArg(InsnGen.java:145)
                        	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:121)
                        	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:108)
                        	at jadx.core.codegen.InsnGen.generateMethodArguments(InsnGen.java:1143)
                        	at jadx.core.codegen.InsnGen.makeInvoke(InsnGen.java:910)
                        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:422)
                        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:303)
                        	... 15 more
                        */
                    /*
                        this = this;
                        java.lang.String r0 = "helper"
                        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r0)
                        java.lang.String r0 = "item"
                        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r0)
                        com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment r0 = r10.this$0
                        r1 = 2131363880(0x7f0a0828, float:1.8347581E38)
                        android.view.View r2 = r11.m3912b(r1)
                        int r3 = r10.getDefaultIndex()
                        int r4 = r11.getAdapterPosition()
                        r5 = 1
                        r6 = 0
                        if (r3 != r4) goto L21
                        r3 = 1
                        goto L22
                    L21:
                        r3 = 0
                    L22:
                        r2.setSelected(r3)
                        r3 = 2131363672(0x7f0a0758, float:1.834716E38)
                        java.lang.String r4 = r12.getName()
                        r11.m3919i(r3, r4)
                        r3 = 2131362557(0x7f0a02fd, float:1.8344898E38)
                        android.view.View r3 = r11.m3912b(r3)
                        boolean r2 = r2.isSelected()
                        if (r2 == 0) goto L3e
                        r2 = 0
                        goto L40
                    L3e:
                        r2 = 8
                    L40:
                        r3.setVisibility(r2)
                        int r2 = r10.getDefaultIndex()
                        int r3 = r11.getAdapterPosition()
                        if (r2 != r3) goto Lbf
                        int r2 = r10.getDefaultIndex()
                        if (r2 != 0) goto Lbf
                        java.lang.String r2 = r12.getFilter()
                        if (r2 == 0) goto Lbf
                        com.jbzd.media.movecartoons.bean.response.system.MainMenusBean r2 = com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment.access$getMTabBean(r0)
                        com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$Companion r2 = com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment.INSTANCE
                        java.lang.String r3 = r12.getFilter()
                        java.util.HashMap r4 = new java.util.HashMap
                        r4.<init>()
                        if (r3 == 0) goto L72
                        int r7 = r3.length()
                        if (r7 != 0) goto L71
                        goto L72
                    L71:
                        r5 = 0
                    L72:
                        if (r5 == 0) goto L75
                        goto La0
                    L75:
                        org.json.JSONObject r5 = new org.json.JSONObject     // Catch: java.lang.Exception -> L9c
                        r5.<init>(r3)     // Catch: java.lang.Exception -> L9c
                        java.util.Iterator r3 = r5.keys()     // Catch: java.lang.Exception -> L9c
                    L7e:
                        boolean r7 = r3.hasNext()     // Catch: java.lang.Exception -> L9c
                        if (r7 == 0) goto La0
                        java.lang.Object r7 = r3.next()     // Catch: java.lang.Exception -> L9c
                        java.lang.String r7 = (java.lang.String) r7     // Catch: java.lang.Exception -> L9c
                        java.lang.String r8 = r5.getString(r7)     // Catch: java.lang.Exception -> L9c
                        java.lang.String r9 = "key"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r9)     // Catch: java.lang.Exception -> L9c
                        java.lang.String r9 = "value"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r9)     // Catch: java.lang.Exception -> L9c
                        r4.put(r7, r8)     // Catch: java.lang.Exception -> L9c
                        goto L7e
                    L9c:
                        r3 = move-exception
                        r3.printStackTrace()
                    La0:
                        java.lang.String r3 = ""
                        com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment r2 = r2.newInstance(r4, r6, r3)
                        r0.setMSearchPostListFragment(r2)
                        androidx.fragment.app.FragmentManager r2 = r0.getChildFragmentManager()
                        androidx.fragment.app.FragmentTransaction r2 = r2.beginTransaction()
                        r3 = 2131362274(0x7f0a01e2, float:1.8344324E38)
                        com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment r4 = r0.getMSearchPostListFragment()
                        androidx.fragment.app.FragmentTransaction r2 = r2.replace(r3, r4)
                        r2.commit()
                    Lbf:
                        com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1$convert$1$1 r2 = new com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2$1$convert$1$1
                        r2.<init>(r10, r11, r12, r0)
                        r11.m3918h(r1, r2)
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment$orderTypeAdapter$2.C37701.convert(com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean):void");
                }
            }

            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final C37701 invoke() {
                return new C37701(CommunityTabSingleFragment.this);
            }
        });
        this.bloggerAdapter = LazyKt__LazyJVMKt.lazy(new CommunityTabSingleFragment$bloggerAdapter$2(this));
    }

    private final CommunityTabSingleFragment$bloggerAdapter$2.C37681 getBloggerAdapter() {
        return (CommunityTabSingleFragment$bloggerAdapter$2.C37681) this.bloggerAdapter.getValue();
    }

    private final CommunityTabSingleFragment$categoriesAdapter$2.C37691 getCategoriesAdapter() {
        return (CommunityTabSingleFragment$categoriesAdapter$2.C37691) this.categoriesAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
    }

    private final void initBannerView(List<? extends AdBean> banners) {
        if (banners == null || !C2354n.m2414N0(banners)) {
            getBannerNew().setVisibility(8);
            return;
        }
        getBannerNew().setVisibility(0);
        RecyclerViewAtViewPager2 bannerNew = getBannerNew();
        List asMutableList = TypeIntrinsics.asMutableList(banners);
        MyAdAdapter mAdAdapter = this.mAdAdapter;
        Intrinsics.checkNotNullParameter(bannerNew, "<this>");
        Intrinsics.checkNotNullParameter(mAdAdapter, "mAdAdapter");
        if (asMutableList == null || asMutableList.isEmpty()) {
            bannerNew.setVisibility(8);
            return;
        }
        bannerNew.setVisibility(0);
        if (bannerNew.getItemDecorationCount() == 0) {
            SpaceViewItemLine spaceViewItemLine = new SpaceViewItemLine(C4195m.m4785R(6.0f));
            spaceViewItemLine.f10124b = false;
            spaceViewItemLine.f10125c = false;
            bannerNew.addItemDecoration(spaceViewItemLine);
        }
        if (bannerNew.getOnFlingListener() == null) {
            new GravitySnapHelper(GravityCompat.START).attachToRecyclerView(bannerNew);
        }
        mAdAdapter.setNewData(asMutableList);
        Unit unit = Unit.INSTANCE;
        bannerNew.setAdapter(mAdAdapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-0, reason: not valid java name */
    public static final void m5837initViews$lambda9$lambda0(CommunityTabSingleFragment this$0, String it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        PostHomeBottomFragment.Companion companion = PostHomeBottomFragment.INSTANCE;
        Intrinsics.checkNotNullExpressionValue(it, "it");
        this$0.setMPostHomeBottomFragment(companion.newInstance(it));
        this$0.getChildFragmentManager().beginTransaction().replace(R.id.frag_content, this$0.getMPostHomeBottomFragment()).commit();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-3, reason: not valid java name */
    public static final void m5838initViews$lambda9$lambda3(final CommunityTabSingleFragment this$0, List it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (!(!it.isEmpty())) {
            this$0.getLl_post_blogger_hot().setVisibility(8);
            return;
        }
        this$0.getLl_post_blogger_hot().setVisibility(0);
        C2354n.m2374A(this$0.getItv_bloggerMore(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$initViews$1$3$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it2) {
                Intrinsics.checkNotNullParameter(it2, "it");
                MyFansAndFollowsActivity.Companion companion = MyFansAndFollowsActivity.INSTANCE;
                Context requireContext = CommunityTabSingleFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, "hot");
            }
        }, 1);
        this$0.getBloggerAdapter().setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) it));
        RecyclerView rv_bloggers = this$0.getRv_bloggers();
        this$0.hideLoadingDialog();
        rv_bloggers.setNestedScrollingEnabled(true);
        rv_bloggers.setAdapter(this$0.getBloggerAdapter());
        rv_bloggers.setLayoutManager(new LinearLayoutManager(this$0.requireContext(), 0, false));
        if (rv_bloggers.getItemDecorationCount() == 0) {
            rv_bloggers.addItemDecoration(new ItemDecorationH2(C2354n.m2425R(this$0.requireContext(), 6.0f), C2354n.m2425R(this$0.requireContext(), 6.0f), C2354n.m2425R(this$0.requireContext(), 56.0f)));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-7, reason: not valid java name */
    public static final void m5839initViews$lambda9$lambda7(final CommunityTabSingleFragment this$0, final PostHomeViewModel this_run, PostHomeResponse postHomeResponse) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        List<AdBean> list = postHomeResponse.banner;
        if (list != null) {
            this$0.initBannerView(list);
        }
        if (postHomeResponse.categories.size() != 0) {
            this$0.getLl_posthome_categories().setVisibility(0);
            this$0.getTv_title_block().setText("推荐圈子");
            RecyclerView rv_list_categories = this$0.getRv_list_categories();
            rv_list_categories.setAdapter(this$0.getCategoriesAdapter());
            if (postHomeResponse.categories != null) {
                this$0.getCategoriesAdapter().setNewData(postHomeResponse.categories);
            }
            rv_list_categories.setLayoutManager(new GridLayoutManager(this$0.requireContext(), 3));
            if (rv_list_categories.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_list_categories.getContext());
                c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_list_categories, 6.0d);
                c4053a.f10337e = C2354n.m2437V(rv_list_categories.getContext(), 6.0d);
                c4053a.f10339g = false;
                c4053a.f10340h = false;
                c4053a.f10338f = false;
                C1499a.m604Z(c4053a, rv_list_categories);
            }
            C2354n.m2374A(this$0.getLl_module_header_posthome(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$initViews$1$4$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                    invoke2(linearLayout);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull LinearLayout it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    ModulePostBlockActivity.Companion companion = ModulePostBlockActivity.INSTANCE;
                    Context requireContext = CommunityTabSingleFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    PostHomeResponse value = this_run.getMPostHomeResponse().getValue();
                    Intrinsics.checkNotNull(value);
                    String str = value.block_name;
                    Intrinsics.checkNotNullExpressionValue(str, "mPostHomeResponse.value!!.block_name");
                    PostHomeResponse value2 = this_run.getMPostHomeResponse().getValue();
                    Intrinsics.checkNotNull(value2);
                    String str2 = value2.block_id;
                    Intrinsics.checkNotNullExpressionValue(str2, "mPostHomeResponse.value!!.block_id");
                    companion.start(requireContext, str, str2);
                }
            }, 1);
        } else {
            this$0.getLl_posthome_categories().setVisibility(8);
        }
        if (postHomeResponse.orders != null) {
            RecyclerView rv_list_type = this$0.getRv_list_type();
            rv_list_type.setAdapter(this$0.getOrderTypeAdapter());
            this$0.getOrderTypeAdapter().setNewData(postHomeResponse.orders);
            LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this$0.requireContext());
            linearLayoutManager.setOrientation(0);
            Unit unit = Unit.INSTANCE;
            rv_list_type.setLayoutManager(linearLayoutManager);
            if (rv_list_type.getItemDecorationCount() == 0) {
                rv_list_type.addItemDecoration(new ItemDecorationH(C2354n.m2425R(this$0.requireContext(), 2.0f), C2354n.m2425R(this$0.requireContext(), 2.0f)));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-8, reason: not valid java name */
    public static final void m5840initViews$lambda9$lambda8(List list) {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final RecyclerViewAtViewPager2 getBannerNew() {
        return (RecyclerViewAtViewPager2) this.bannerNew.getValue();
    }

    @NotNull
    public final ImageTextView getItv_bloggerMore() {
        return (ImageTextView) this.itv_bloggerMore.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_post_tabsingle;
    }

    @NotNull
    public final LinearLayout getLl_module_header_posthome() {
        return (LinearLayout) this.ll_module_header_posthome.getValue();
    }

    @NotNull
    public final LinearLayout getLl_post_blogger_hot() {
        return (LinearLayout) this.ll_post_blogger_hot.getValue();
    }

    @NotNull
    public final LinearLayout getLl_posthome_categories() {
        return (LinearLayout) this.ll_posthome_categories.getValue();
    }

    @NotNull
    public final PostHomeBottomFragment getMPostHomeBottomFragment() {
        PostHomeBottomFragment postHomeBottomFragment = this.mPostHomeBottomFragment;
        if (postHomeBottomFragment != null) {
            return postHomeBottomFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mPostHomeBottomFragment");
        throw null;
    }

    @NotNull
    public final CommonPostListFragment getMSearchPostListFragment() {
        CommonPostListFragment commonPostListFragment = this.mSearchPostListFragment;
        if (commonPostListFragment != null) {
            return commonPostListFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mSearchPostListFragment");
        throw null;
    }

    @NotNull
    public final BaseQuickAdapter<PostHomeResponse.OrdersBean, BaseViewHolder> getOrderTypeAdapter() {
        return (BaseQuickAdapter) this.orderTypeAdapter.getValue();
    }

    @NotNull
    public final RecyclerView getRv_bloggers() {
        return (RecyclerView) this.rv_bloggers.getValue();
    }

    @NotNull
    public final RecyclerView getRv_list_categories() {
        return (RecyclerView) this.rv_list_categories.getValue();
    }

    @NotNull
    public final RecyclerView getRv_list_type() {
        return (RecyclerView) this.rv_list_type.getValue();
    }

    @NotNull
    public final BloodColorText getTv_title_block() {
        return (BloodColorText) this.tv_title_block.getValue();
    }

    @NotNull
    public final MarqueeTextView getTv_user_new_tips() {
        return (MarqueeTextView) this.tv_user_new_tips.getValue();
    }

    @NotNull
    public final PostHomeViewModel getViewModel() {
        return (PostHomeViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        super.initEvents();
        getTv_user_new_tips().setVisibility(8);
        MyApp myApp = MyApp.f9891f;
        if (MyApp.m4185f().post_notice != null) {
            getTv_user_new_tips().setVisibility(0);
            getTv_user_new_tips().setText(MyApp.m4185f().post_notice.content);
            getTv_user_new_tips().m4583c();
        }
        MainMenusBean mTabBean = getMTabBean();
        if (StringsKt__StringsJVMKt.equals$default(mTabBean == null ? null : mTabBean.name, "关注", false, 2, null)) {
            PostHomeViewModel.userUp$default(getViewModel(), "1", false, 2, null);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        String str;
        super.initViews();
        final PostHomeViewModel viewModel = getViewModel();
        viewModel.getCurrentBloggerId().observe(this, new Observer() { // from class: b.a.a.a.t.g.l.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                CommunityTabSingleFragment.m5837initViews$lambda9$lambda0(CommunityTabSingleFragment.this, (String) obj);
            }
        });
        MainMenusBean mTabBean = getMTabBean();
        if (mTabBean != null && (str = mTabBean.filter) != null) {
            PostHomeViewModel.postHome$default(getViewModel(), str, false, 2, null);
        }
        viewModel.getMHLSFollowerBeans().observe(this, new Observer() { // from class: b.a.a.a.t.g.l.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                CommunityTabSingleFragment.m5838initViews$lambda9$lambda3(CommunityTabSingleFragment.this, (List) obj);
            }
        });
        viewModel.getMPostHomeResponse().observe(this, new Observer() { // from class: b.a.a.a.t.g.l.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                CommunityTabSingleFragment.m5839initViews$lambda9$lambda7(CommunityTabSingleFragment.this, viewModel, (PostHomeResponse) obj);
            }
        });
        viewModel.getMPostListBean().observe(this, new Observer() { // from class: b.a.a.a.t.g.l.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                CommunityTabSingleFragment.m5840initViews$lambda9$lambda8((List) obj);
            }
        });
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        getLifecycle().removeObserver(this.mAdAdapter);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
        getLifecycle().addObserver(this.mAdAdapter);
    }

    public final void setMPostHomeBottomFragment(@NotNull PostHomeBottomFragment postHomeBottomFragment) {
        Intrinsics.checkNotNullParameter(postHomeBottomFragment, "<set-?>");
        this.mPostHomeBottomFragment = postHomeBottomFragment;
    }

    public final void setMSearchPostListFragment(@NotNull CommonPostListFragment commonPostListFragment) {
        Intrinsics.checkNotNullParameter(commonPostListFragment, "<set-?>");
        this.mSearchPostListFragment = commonPostListFragment;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public PostHomeViewModel viewModelInstance() {
        return getViewModel();
    }
}
