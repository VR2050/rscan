package com.jbzd.media.movecartoons.p396ui.index.post.block;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.PostCategoryDetailBean;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.post.PostHomeViewModel;
import com.jbzd.media.movecartoons.p396ui.index.post.block.ModulePostBlockActivity;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity$categoriesAdapter$2;
import com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity;
import com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000}\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r*\u00018\u0018\u0000 ^2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001^B\u0007¢\u0006\u0004\b]\u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\tJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\r\u0010\u000e\u001a\u00020\u0002¢\u0006\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0015\u001a\u00020\u00108F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R\u001f\u0010\u001a\u001a\u0004\u0018\u00010\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0012\u001a\u0004\b\u0018\u0010\u0019R\u001f\u0010\u001d\u001a\u0004\u0018\u00010\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0012\u001a\u0004\b\u001c\u0010\u0019R\u001d\u0010\"\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0012\u001a\u0004\b \u0010!R\u001d\u0010%\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u0012\u001a\u0004\b$\u0010!R(\u0010(\u001a\b\u0012\u0004\u0012\u00020'0&8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b(\u0010)\u001a\u0004\b*\u0010+\"\u0004\b,\u0010-R\u001d\u00102\u001a\u00020.8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b/\u0010\u0012\u001a\u0004\b0\u00101R\u001d\u00107\u001a\u0002038F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u0012\u001a\u0004\b5\u00106R\u001d\u0010<\u001a\u0002088B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b9\u0010\u0012\u001a\u0004\b:\u0010;R\u001d\u0010A\u001a\u00020=8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b>\u0010\u0012\u001a\u0004\b?\u0010@R\u001d\u0010D\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bB\u0010\u0012\u001a\u0004\bC\u0010!R\u001d\u0010G\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u0012\u001a\u0004\bF\u0010\u000fR\u001d\u0010L\u001a\u00020H8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010\u0012\u001a\u0004\bJ\u0010KR\u001d\u0010Q\u001a\u00020M8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bN\u0010\u0012\u001a\u0004\bO\u0010PR\u001d\u0010V\u001a\u00020R8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bS\u0010\u0012\u001a\u0004\bT\u0010UR\u001d\u0010Y\u001a\u00020H8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010\u0012\u001a\u0004\bX\u0010KR\u001d\u0010\\\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010\u0012\u001a\u0004\b[\u0010!¨\u0006_"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/block/PostCategoryDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/PostCategoryDetailBean;", "mPostCategoryDetailBean", "", "setPostCategoryHomeInfo", "(Lcom/jbzd/media/movecartoons/bean/response/PostCategoryDetailBean;)V", "initStatusBar", "()V", "bindEvent", "", "getLayoutId", "()I", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeViewModel;", "Lcom/google/android/material/appbar/AppBarLayout;", "app_bar_layout$delegate", "Lkotlin/Lazy;", "getApp_bar_layout", "()Lcom/google/android/material/appbar/AppBarLayout;", "app_bar_layout", "", "mBlockId$delegate", "getMBlockId", "()Ljava/lang/String;", "mBlockId", "mPosition$delegate", "getMPosition", "mPosition", "Landroid/widget/TextView;", "tv_postcategory_name$delegate", "getTv_postcategory_name", "()Landroid/widget/TextView;", "tv_postcategory_name", "tv_title$delegate", "getTv_title", "tv_title", "", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$OrdersBean;", "ordersList", "Ljava/util/List;", "getOrdersList", "()Ljava/util/List;", "setOrdersList", "(Ljava/util/List;)V", "Lcom/jbzd/media/movecartoons/view/FollowTextView;", "itv_postuser_follow$delegate", "getItv_postuser_follow", "()Lcom/jbzd/media/movecartoons/view/FollowTextView;", "itv_postuser_follow", "Landroid/widget/ImageView;", "iv_category_img$delegate", "getIv_category_img", "()Landroid/widget/ImageView;", "iv_category_img", "com/jbzd/media/movecartoons/ui/index/post/block/PostCategoryDetailActivity$categoriesAdapter$2$1", "categoriesAdapter$delegate", "getCategoriesAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/post/block/PostCategoryDetailActivity$categoriesAdapter$2$1;", "categoriesAdapter", "Lcom/flyco/tablayout/SlidingTabLayout;", "tab_categor_detail_order$delegate", "getTab_categor_detail_order", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tab_categor_detail_order", "tv_postcategory_click$delegate", "getTv_postcategory_click", "tv_postcategory_click", "viewModel$delegate", "getViewModel", "viewModel", "Landroid/widget/LinearLayout;", "ll_posthome_categories$delegate", "getLl_posthome_categories", "()Landroid/widget/LinearLayout;", "ll_posthome_categories", "Landroidx/viewpager/widget/ViewPager;", "vp_bottom_categor_detail$delegate", "getVp_bottom_categor_detail", "()Landroidx/viewpager/widget/ViewPager;", "vp_bottom_categor_detail", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list_categories$delegate", "getRv_list_categories", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_list_categories", "ll_module_header_posthome$delegate", "getLl_module_header_posthome", "ll_module_header_posthome", "tv_postcategory_description$delegate", "getTv_postcategory_description", "tv_postcategory_description", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostCategoryDetailActivity extends MyThemeActivity<PostHomeViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_BLOCKID = BaseCommonPostListFragment.KEY_BLOCK_ID;

    @NotNull
    private static final String KEY_POSITION = "position";
    public List<PostHomeResponse.OrdersBean> ordersList;

    /* renamed from: mBlockId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBlockId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$mBlockId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return PostCategoryDetailActivity.this.getIntent().getStringExtra(PostCategoryDetailActivity.INSTANCE.getKEY_BLOCKID());
        }
    });

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$mPosition$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return PostCategoryDetailActivity.this.getIntent().getStringExtra(PostCategoryDetailActivity.INSTANCE.getKEY_POSITION());
        }
    });

    /* renamed from: app_bar_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy app_bar_layout = LazyKt__LazyJVMKt.lazy(new Function0<AppBarLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$app_bar_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppBarLayout invoke() {
            AppBarLayout appBarLayout = (AppBarLayout) PostCategoryDetailActivity.this.findViewById(R.id.app_bar_layout);
            Intrinsics.checkNotNull(appBarLayout);
            return appBarLayout;
        }
    });

    /* renamed from: tv_title$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_title = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$tv_title$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostCategoryDetailActivity.this.findViewById(R.id.tv_title);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: itv_postuser_follow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_postuser_follow = LazyKt__LazyJVMKt.lazy(new Function0<FollowTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$itv_postuser_follow$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FollowTextView invoke() {
            FollowTextView followTextView = (FollowTextView) PostCategoryDetailActivity.this.findViewById(R.id.itv_postuser_follow);
            Intrinsics.checkNotNull(followTextView);
            return followTextView;
        }
    });

    /* renamed from: categoriesAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy categoriesAdapter = LazyKt__LazyJVMKt.lazy(new PostCategoryDetailActivity$categoriesAdapter$2(this));

    /* renamed from: iv_category_img$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_category_img = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$iv_category_img$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) PostCategoryDetailActivity.this.findViewById(R.id.iv_category_img);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_postcategory_click$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_postcategory_click = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$tv_postcategory_click$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostCategoryDetailActivity.this.findViewById(R.id.tv_postcategory_click);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_postcategory_description$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_postcategory_description = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$tv_postcategory_description$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostCategoryDetailActivity.this.findViewById(R.id.tv_postcategory_description);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_postcategory_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_postcategory_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$tv_postcategory_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) PostCategoryDetailActivity.this.findViewById(R.id.tv_postcategory_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_posthome_categories$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_posthome_categories = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$ll_posthome_categories$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostCategoryDetailActivity.this.findViewById(R.id.ll_posthome_categories);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: rv_list_categories$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_list_categories = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$rv_list_categories$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) PostCategoryDetailActivity.this.findViewById(R.id.rv_list_categories);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: ll_module_header_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_module_header_posthome = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$ll_module_header_posthome$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) PostCategoryDetailActivity.this.findViewById(R.id.ll_module_header_posthome);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: vp_bottom_categor_detail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_bottom_categor_detail = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$vp_bottom_categor_detail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) PostCategoryDetailActivity.this.findViewById(R.id.vp_bottom_categor_detail);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tab_categor_detail_order$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tab_categor_detail_order = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$tab_categor_detail_order$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) PostCategoryDetailActivity.this.findViewById(R.id.tab_categor_detail_order);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(PostHomeViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$special$$inlined$viewModels$default$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelStore invoke() {
            ViewModelStore viewModelStore = ComponentActivity.this.getViewModelStore();
            Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "viewModelStore");
            return viewModelStore;
        }
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$special$$inlined$viewModels$default$1
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelProvider.Factory invoke() {
            ViewModelProvider.Factory defaultViewModelProviderFactory = ComponentActivity.this.getDefaultViewModelProviderFactory();
            Intrinsics.checkExpressionValueIsNotNull(defaultViewModelProviderFactory, "defaultViewModelProviderFactory");
            return defaultViewModelProviderFactory;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0010\u0010\u0011J%\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0004¢\u0006\u0004\b\b\u0010\tR\u001c\u0010\n\u001a\u00020\u00048\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u001c\u0010\u000e\u001a\u00020\u00048\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\b\u000e\u0010\u000b\u001a\u0004\b\u000f\u0010\r¨\u0006\u0012"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/block/PostCategoryDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "blockId", "position", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V", "KEY_BLOCKID", "Ljava/lang/String;", "getKEY_BLOCKID", "()Ljava/lang/String;", SearchHomeActivity.key_position, "getKEY_POSITION", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getKEY_BLOCKID() {
            return PostCategoryDetailActivity.KEY_BLOCKID;
        }

        @NotNull
        public final String getKEY_POSITION() {
            return PostCategoryDetailActivity.KEY_POSITION;
        }

        public final void start(@NotNull Context context, @NotNull String blockId, @NotNull String position) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(blockId, "blockId");
            Intrinsics.checkNotNullParameter(position, "position");
            Activity activity = (Activity) context;
            String localClassName = activity.getLocalClassName();
            Intrinsics.checkNotNullExpressionValue(localClassName, "activity.localClassName");
            if (StringsKt__StringsJVMKt.endsWith$default(localClassName, "PostCategoryDetailActivity", false, 2, null)) {
                activity.finish();
            }
            Intent intent = new Intent(context, (Class<?>) PostCategoryDetailActivity.class);
            intent.putExtra(getKEY_BLOCKID(), blockId);
            intent.putExtra(getKEY_POSITION(), position);
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-0, reason: not valid java name */
    public static final void m5844bindEvent$lambda0(PostCategoryDetailActivity this$0, AppBarLayout appBarLayout, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 == 0) {
            this$0.getTv_title().setTextColor(this$0.getResources().getColor(R.color.transparent));
        } else {
            this$0.getTv_title().setTextColor(this$0.getResources().getColor(R.color.white));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5845bindEvent$lambda3$lambda2(final PostCategoryDetailActivity this$0, final PostCategoryDetailBean bean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(bean, "bean");
        this$0.setPostCategoryHomeInfo(bean);
        C2354n.m2374A(this$0.getItv_postuser_follow(), 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$bindEvent$3$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FollowTextView followTextView) {
                invoke2(followTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FollowTextView it) {
                PostCategoryDetailBean.CatInfoBean catInfoBean;
                String str;
                PostCategoryDetailBean.CatInfoBean catInfoBean2;
                Intrinsics.checkNotNullParameter(it, "it");
                PostCategoryDetailBean postCategoryDetailBean = PostCategoryDetailBean.this;
                PostCategoryDetailBean.CatInfoBean catInfoBean3 = postCategoryDetailBean == null ? null : postCategoryDetailBean.cat_info;
                if (catInfoBean3 != null) {
                    catInfoBean3.has_follow = Intrinsics.areEqual((postCategoryDetailBean != null && (catInfoBean2 = postCategoryDetailBean.cat_info) != null) ? catInfoBean2.has_follow : null, "y") ? "n" : "y";
                }
                PostCategoryDetailBean postCategoryDetailBean2 = PostCategoryDetailBean.this;
                it.setFollowStatus(Intrinsics.areEqual((postCategoryDetailBean2 == null || (catInfoBean = postCategoryDetailBean2.cat_info) == null) ? null : catInfoBean.has_follow, "y"));
                PostCategoryDetailBean postCategoryDetailBean3 = PostCategoryDetailBean.this;
                PostCategoryDetailBean.CatInfoBean catInfoBean4 = postCategoryDetailBean3 != null ? postCategoryDetailBean3.cat_info : null;
                if (catInfoBean4 == null || (str = catInfoBean4.f9973id) == null) {
                    return;
                }
                this$0.getViewModel().followBlock(str, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$bindEvent$3$1$1$1$1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$bindEvent$3$1$1$1$2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
    }

    private final PostCategoryDetailActivity$categoriesAdapter$2.C37721 getCategoriesAdapter() {
        return (PostCategoryDetailActivity$categoriesAdapter$2.C37721) this.categoriesAdapter.getValue();
    }

    private final void setPostCategoryHomeInfo(final PostCategoryDetailBean mPostCategoryDetailBean) {
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        ((C2852c) ComponentCallbacks2C1553c.m738h(applicationC2828a)).m3298p(mPostCategoryDetailBean.cat_info.img).m3295i0().m757R(getIv_category_img());
        getTv_postcategory_click().setText(C0843e0.m182a(mPostCategoryDetailBean.cat_info.post_count) + "个帖子 " + C0843e0.m182a(mPostCategoryDetailBean.cat_info.post_click) + "浏览");
        getTv_postcategory_description().setText(mPostCategoryDetailBean.cat_info.description);
        getTv_postcategory_name().setText(Intrinsics.stringPlus("#", mPostCategoryDetailBean.cat_info.name));
        getTv_title().setText(mPostCategoryDetailBean.cat_info.name);
        getItv_postuser_follow().setFollowStatus(Intrinsics.areEqual(mPostCategoryDetailBean.cat_info.has_follow, "y"));
        if (mPostCategoryDetailBean.categories.size() != 0) {
            getLl_posthome_categories().setVisibility(0);
            RecyclerView rv_list_categories = getRv_list_categories();
            rv_list_categories.setAdapter(getCategoriesAdapter());
            if (mPostCategoryDetailBean.categories != null) {
                getCategoriesAdapter().setNewData(mPostCategoryDetailBean.categories);
            }
            rv_list_categories.setLayoutManager(new GridLayoutManager(this, 3));
            if (rv_list_categories.getItemDecorationCount() == 0) {
                ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
                if (applicationC2828a2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(applicationC2828a2);
                c4053a.m4576a(R.color.transparent);
                ApplicationC2828a applicationC2828a3 = C2827a.f7670a;
                if (applicationC2828a3 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                c4053a.f10337e = C2354n.m2437V(applicationC2828a3, 6.0d);
                ApplicationC2828a applicationC2828a4 = C2827a.f7670a;
                if (applicationC2828a4 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                c4053a.f10336d = C2354n.m2437V(applicationC2828a4, 6.0d);
                c4053a.f10339g = false;
                c4053a.f10340h = false;
                c4053a.f10338f = false;
                rv_list_categories.addItemDecoration(new GridItemDecoration(c4053a));
            }
            C2354n.m2374A(getLl_module_header_posthome(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$setPostCategoryHomeInfo$2
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
                    if (PostCategoryDetailActivity.this.getMPosition() == null) {
                        return;
                    }
                    PostCategoryDetailBean postCategoryDetailBean = mPostCategoryDetailBean;
                    ModulePostBlockActivity.Companion companion = ModulePostBlockActivity.INSTANCE;
                    ApplicationC2828a applicationC2828a5 = C2827a.f7670a;
                    if (applicationC2828a5 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("context");
                        throw null;
                    }
                    String str = postCategoryDetailBean.cat_info.block_name;
                    Intrinsics.checkNotNullExpressionValue(str, "mPostCategoryDetailBean.cat_info.block_name");
                    String str2 = postCategoryDetailBean.cat_info.block_id;
                    Intrinsics.checkNotNullExpressionValue(str2, "mPostCategoryDetailBean.cat_info.block_id");
                    companion.start(applicationC2828a5, str, str2);
                }
            }, 1);
        } else {
            getLl_posthome_categories().setVisibility(8);
        }
        if (mPostCategoryDetailBean.orders.size() != 0) {
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = new ArrayList();
            List<PostHomeResponse.OrdersBean> list = mPostCategoryDetailBean.orders;
            Intrinsics.checkNotNullExpressionValue(list, "mPostCategoryDetailBean.orders");
            setOrdersList(list);
            for (PostHomeResponse.OrdersBean ordersBean : getOrdersList()) {
                arrayList.add(ordersBean.getName());
                CommonPostListFragment.Companion companion = CommonPostListFragment.INSTANCE;
                String filter = ordersBean.getFilter();
                HashMap<String, String> hashMap = new HashMap<>();
                if (!(filter == null || filter.length() == 0)) {
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
                arrayList2.add(companion.newInstance(hashMap, false, ""));
            }
            FragmentManager supportFragmentManager = getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, arrayList2, 0, 4, null);
            ViewPager vp_bottom_categor_detail = getVp_bottom_categor_detail();
            vp_bottom_categor_detail.setOffscreenPageLimit(arrayList2.size());
            vp_bottom_categor_detail.setAdapter(viewPagerAdapter);
            SlidingTabLayout tab_categor_detail_order = getTab_categor_detail_order();
            tab_categor_detail_order.setTabSpaceEqual(true);
            ViewPager vp_bottom_categor_detail2 = getVp_bottom_categor_detail();
            Object[] array = arrayList.toArray(new String[0]);
            Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
            tab_categor_detail_order.m4011e(vp_bottom_categor_detail2, (String[]) array);
        }
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getApp_bar_layout().addOnOffsetChangedListener(new AppBarLayout.OnOffsetChangedListener() { // from class: b.a.a.a.t.g.l.g.b
            @Override // com.google.android.material.appbar.AppBarLayout.OnOffsetChangedListener, com.google.android.material.appbar.AppBarLayout.BaseOnOffsetChangedListener
            public final void onOffsetChanged(AppBarLayout appBarLayout, int i2) {
                PostCategoryDetailActivity.m5844bindEvent$lambda0(PostCategoryDetailActivity.this, appBarLayout, i2);
            }
        });
        String mBlockId = getMBlockId();
        if (mBlockId != null) {
            getViewModel().postCategoryHome(mBlockId);
        }
        getViewModel().getMPostCategoryDetailBean().observe(this, new Observer() { // from class: b.a.a.a.t.g.l.g.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PostCategoryDetailActivity.m5845bindEvent$lambda3$lambda2(PostCategoryDetailActivity.this, (PostCategoryDetailBean) obj);
            }
        });
    }

    @NotNull
    public final AppBarLayout getApp_bar_layout() {
        return (AppBarLayout) this.app_bar_layout.getValue();
    }

    @NotNull
    public final FollowTextView getItv_postuser_follow() {
        return (FollowTextView) this.itv_postuser_follow.getValue();
    }

    @NotNull
    public final ImageView getIv_category_img() {
        return (ImageView) this.iv_category_img.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_post_category_detail;
    }

    @NotNull
    public final LinearLayout getLl_module_header_posthome() {
        return (LinearLayout) this.ll_module_header_posthome.getValue();
    }

    @NotNull
    public final LinearLayout getLl_posthome_categories() {
        return (LinearLayout) this.ll_posthome_categories.getValue();
    }

    @Nullable
    public final String getMBlockId() {
        return (String) this.mBlockId.getValue();
    }

    @Nullable
    public final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    @NotNull
    public final List<PostHomeResponse.OrdersBean> getOrdersList() {
        List<PostHomeResponse.OrdersBean> list = this.ordersList;
        if (list != null) {
            return list;
        }
        Intrinsics.throwUninitializedPropertyAccessException("ordersList");
        throw null;
    }

    @NotNull
    public final RecyclerView getRv_list_categories() {
        return (RecyclerView) this.rv_list_categories.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTab_categor_detail_order() {
        return (SlidingTabLayout) this.tab_categor_detail_order.getValue();
    }

    @NotNull
    public final TextView getTv_postcategory_click() {
        return (TextView) this.tv_postcategory_click.getValue();
    }

    @NotNull
    public final TextView getTv_postcategory_description() {
        return (TextView) this.tv_postcategory_description.getValue();
    }

    @NotNull
    public final TextView getTv_postcategory_name() {
        return (TextView) this.tv_postcategory_name.getValue();
    }

    @NotNull
    public final TextView getTv_title() {
        return (TextView) this.tv_title.getValue();
    }

    @NotNull
    public final PostHomeViewModel getViewModel() {
        return (PostHomeViewModel) this.viewModel.getValue();
    }

    @NotNull
    public final ViewPager getVp_bottom_categor_detail() {
        return (ViewPager) this.vp_bottom_categor_detail.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#000000").statusBarDarkFont(false).init();
    }

    public final void setOrdersList(@NotNull List<PostHomeResponse.OrdersBean> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.ordersList = list;
    }

    @NotNull
    public final PostHomeViewModel viewModelInstance() {
        return getViewModel();
    }
}
