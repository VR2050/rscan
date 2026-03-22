package com.jbzd.media.movecartoons.p396ui.index.darkplay;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.DarkTabSingleFragment;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.DarkTabSingleFragment$categoriesAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.post.block.ModulePostBlockActivity;
import com.jbzd.media.movecartoons.p396ui.index.view.BloodColorText;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseViewModelFragment;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u000b*\u0002$Q\u0018\u0000 Z2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001ZB\u0007¢\u0006\u0004\bY\u0010\u000fJ\u001f\u0010\u0007\u001a\u00020\u00062\u000e\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0010\u0010\u000fR\u001d\u0010\u0016\u001a\u00020\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R\u001d\u0010\u001b\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0013\u001a\u0004\b\u0019\u0010\u001aR\u001d\u0010\u001e\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0013\u001a\u0004\b\u001d\u0010\u001aR\u001d\u0010#\u001a\u00020\u001f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u0013\u001a\u0004\b!\u0010\"R\u001d\u0010(\u001a\u00020$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u0013\u001a\u0004\b&\u0010'R\"\u0010*\u001a\u00020)8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b*\u0010+\u001a\u0004\b,\u0010-\"\u0004\b.\u0010/R\u001f\u00104\u001a\u0004\u0018\u0001008B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u0013\u001a\u0004\b2\u00103R\u001c\u00106\u001a\u0002058\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\b6\u00107\u001a\u0004\b8\u00109R\u001d\u0010>\u001a\u00020:8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u0013\u001a\u0004\b<\u0010=R\u001d\u0010A\u001a\u0002058B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u0013\u001a\u0004\b@\u00109R\u001c\u0010B\u001a\u0002058\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\bB\u00107\u001a\u0004\bC\u00109R\u001d\u0010H\u001a\u00020D8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u0013\u001a\u0004\bF\u0010GR\u001d\u0010K\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010\u0013\u001a\u0004\bJ\u0010\rR%\u0010P\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030L8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bM\u0010\u0013\u001a\u0004\bN\u0010OR\u001d\u0010U\u001a\u00020Q8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bR\u0010\u0013\u001a\u0004\bS\u0010TR\u001d\u0010X\u001a\u00020:8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bV\u0010\u0013\u001a\u0004\bW\u0010=¨\u0006["}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/PostHomeViewModel;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "banners", "", "initBannerView", "(Ljava/util/List;)V", "", "getLayout", "()I", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/PostHomeViewModel;", "initEvents", "()V", "initViews", "Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent$delegate", "Lkotlin/Lazy;", "getBanner_parent", "()Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list_type$delegate", "getRv_list_type", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_list_type", "rv_list_categories$delegate", "getRv_list_categories", "rv_list_categories", "Lcom/qunidayede/supportlibrary/widget/MarqueeTextView;", "tv_user_new_tips$delegate", "getTv_user_new_tips", "()Lcom/qunidayede/supportlibrary/widget/MarqueeTextView;", "tv_user_new_tips", "com/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment$categoriesAdapter$2$1", "categoriesAdapter$delegate", "getCategoriesAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment$categoriesAdapter$2$1;", "categoriesAdapter", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "mSearchPostListFragment", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "getMSearchPostListFragment", "()Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "setMSearchPostListFragment", "(Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;)V", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "", "KEY_TAB", "Ljava/lang/String;", "getKEY_TAB", "()Ljava/lang/String;", "Landroid/widget/LinearLayout;", "ll_posthome_categories$delegate", "getLl_posthome_categories", "()Landroid/widget/LinearLayout;", "ll_posthome_categories", "mSearchType$delegate", "getMSearchType", "mSearchType", "SEARCH_TYPE", "getSEARCH_TYPE", "Lcom/jbzd/media/movecartoons/ui/index/view/BloodColorText;", "tv_title_block$delegate", "getTv_title_block", "()Lcom/jbzd/media/movecartoons/ui/index/view/BloodColorText;", "tv_title_block", "viewModel$delegate", "getViewModel", "viewModel", "Lcom/youth/banner/Banner;", "banner$delegate", "getBanner", "()Lcom/youth/banner/Banner;", "banner", "com/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment$orderTypeAdapter$2$1", "orderTypeAdapter$delegate", "getOrderTypeAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment$orderTypeAdapter$2$1;", "orderTypeAdapter", "ll_module_header_posthome$delegate", "getLl_module_header_posthome", "ll_module_header_posthome", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DarkTabSingleFragment extends BaseViewModelFragment<PostHomeViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: banner$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner;

    /* renamed from: banner_parent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner_parent;

    /* renamed from: categoriesAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy categoriesAdapter;

    /* renamed from: ll_module_header_posthome$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_module_header_posthome;

    /* renamed from: ll_posthome_categories$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_posthome_categories;
    public CommonPostListFragment mSearchPostListFragment;

    /* renamed from: orderTypeAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy orderTypeAdapter;

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

    @NotNull
    private final String KEY_TAB = "tab_bean";

    @NotNull
    private final String SEARCH_TYPE = "search_type";

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = DarkTabSingleFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable(DarkTabSingleFragment.this.getKEY_TAB()));
        }
    });

    /* renamed from: mSearchType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mSearchType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$mSearchType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            Bundle arguments = DarkTabSingleFragment.this.getArguments();
            String string = arguments == null ? null : arguments.getString(DarkTabSingleFragment.this.getSEARCH_TYPE());
            Objects.requireNonNull(string, "null cannot be cast to non-null type kotlin.String");
            return string;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001f\u0010\u0007\u001a\u00020\u00062\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "", "type", "Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final DarkTabSingleFragment newInstance(@Nullable MainMenusBean tabBean, @NotNull String type) {
            Intrinsics.checkNotNullParameter(type, "type");
            DarkTabSingleFragment darkTabSingleFragment = new DarkTabSingleFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable(darkTabSingleFragment.getKEY_TAB(), tabBean);
            bundle.putString(darkTabSingleFragment.getSEARCH_TYPE(), type);
            Unit unit = Unit.INSTANCE;
            darkTabSingleFragment.setArguments(bundle);
            return darkTabSingleFragment;
        }
    }

    public DarkTabSingleFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(PostHomeViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$special$$inlined$viewModels$default$2
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
        this.tv_user_new_tips = LazyKt__LazyJVMKt.lazy(new Function0<MarqueeTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$tv_user_new_tips$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final MarqueeTextView invoke() {
                View view = DarkTabSingleFragment.this.getView();
                MarqueeTextView marqueeTextView = view == null ? null : (MarqueeTextView) view.findViewById(R.id.tv_user_new_tips);
                Intrinsics.checkNotNull(marqueeTextView);
                return marqueeTextView;
            }
        });
        this.banner_parent = LazyKt__LazyJVMKt.lazy(new Function0<ScaleRelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$banner_parent$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ScaleRelativeLayout invoke() {
                View view = DarkTabSingleFragment.this.getView();
                ScaleRelativeLayout scaleRelativeLayout = view == null ? null : (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
                Intrinsics.checkNotNull(scaleRelativeLayout);
                return scaleRelativeLayout;
            }
        });
        this.banner = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$banner$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Banner<?, ?> invoke() {
                View view = DarkTabSingleFragment.this.getView();
                Banner<?, ?> banner = view == null ? null : (Banner) view.findViewById(R.id.banner);
                Intrinsics.checkNotNull(banner);
                return banner;
            }
        });
        this.categoriesAdapter = LazyKt__LazyJVMKt.lazy(new DarkTabSingleFragment$categoriesAdapter$2(this));
        this.orderTypeAdapter = LazyKt__LazyJVMKt.lazy(new Function0<DarkTabSingleFragment$orderTypeAdapter$2.C37571>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2

            @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0007*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0015¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\n\u001a\u00020\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000f¨\u0006\u0010"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/darkplay/DarkTabSingleFragment$orderTypeAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$OrdersBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$OrdersBean;)V", "", "defaultIndex", "I", "getDefaultIndex", "()I", "setDefaultIndex", "(I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
            /* renamed from: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1 */
            public static final class C37571 extends BaseQuickAdapter<PostHomeResponse.OrdersBean, BaseViewHolder> {
                private int defaultIndex;
                public final /* synthetic */ DarkTabSingleFragment this$0;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                public C37571(DarkTabSingleFragment darkTabSingleFragment) {
                    super(R.layout.item_post_type, null, 2, null);
                    this.this$0 = darkTabSingleFragment;
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
                    final DarkTabSingleFragment darkTabSingleFragment = this.this$0;
                    View m3912b = helper.m3912b(R.id.view_item_posttype);
                    boolean z = true;
                    m3912b.setSelected(getDefaultIndex() == helper.getAdapterPosition());
                    helper.m3919i(R.id.tv_posttype_name, item.getName());
                    helper.m3912b(R.id.iv_posttype_bottom).setVisibility(m3912b.isSelected() ? 0 : 8);
                    if (getDefaultIndex() == helper.getAdapterPosition() && getDefaultIndex() == 0 && item.getFilter() != null) {
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
                        darkTabSingleFragment.setMSearchPostListFragment(companion.newInstance(hashMap, false, ""));
                        darkTabSingleFragment.getChildFragmentManager().beginTransaction().replace(R.id.frag_content, darkTabSingleFragment.getMSearchPostListFragment()).commit();
                    }
                    helper.m3918h(R.id.view_item_posttype, 
                    /*  JADX ERROR: Method code generation error
                        jadx.core.utils.exceptions.CodegenException: Error generate insn: 0x00c0: INVOKE 
                          (r11v0 'helper' com.chad.library.adapter.base.viewholder.BaseViewHolder)
                          (wrap:int:SGET  A[WRAPPED] com.qnmd.adnnm.da0yzo.R.id.view_item_posttype int)
                          (wrap:kotlin.jvm.functions.Function0<kotlin.Unit>:0x00bd: CONSTRUCTOR 
                          (r10v0 'this' com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1 A[DONT_INLINE, IMMUTABLE_TYPE, THIS])
                          (r11v0 'helper' com.chad.library.adapter.base.viewholder.BaseViewHolder A[DONT_INLINE])
                          (r12v0 'item' com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean A[DONT_INLINE])
                          (r0v2 'darkTabSingleFragment' com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment A[DONT_INLINE])
                         A[MD:(com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1, com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean, com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment):void (m), WRAPPED] (LINE:25) call: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1$convert$1$1.<init>(com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1, com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean, com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment):void type: CONSTRUCTOR)
                         VIRTUAL call: com.chad.library.adapter.base.viewholder.BaseViewHolder.h(int, kotlin.jvm.functions.Function0):com.chad.library.adapter.base.viewholder.BaseViewHolder A[MD:(int, kotlin.jvm.functions.Function0<kotlin.Unit>):com.chad.library.adapter.base.viewholder.BaseViewHolder (m)] (LINE:25) in method: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2.1.convert(com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean):void, file: classes2.dex
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
                        Caused by: jadx.core.utils.exceptions.JadxRuntimeException: Expected class to be processed at this point, class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1$convert$1$1, state: NOT_LOADED
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
                        com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment r0 = r10.this$0
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
                        if (r2 != r3) goto Lbb
                        int r2 = r10.getDefaultIndex()
                        if (r2 != 0) goto Lbb
                        java.lang.String r2 = r12.getFilter()
                        if (r2 == 0) goto Lbb
                        com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment$Companion r2 = com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment.INSTANCE
                        java.lang.String r3 = r12.getFilter()
                        java.util.HashMap r4 = new java.util.HashMap
                        r4.<init>()
                        if (r3 == 0) goto L6e
                        int r7 = r3.length()
                        if (r7 != 0) goto L6d
                        goto L6e
                    L6d:
                        r5 = 0
                    L6e:
                        if (r5 == 0) goto L71
                        goto L9c
                    L71:
                        org.json.JSONObject r5 = new org.json.JSONObject     // Catch: java.lang.Exception -> L98
                        r5.<init>(r3)     // Catch: java.lang.Exception -> L98
                        java.util.Iterator r3 = r5.keys()     // Catch: java.lang.Exception -> L98
                    L7a:
                        boolean r7 = r3.hasNext()     // Catch: java.lang.Exception -> L98
                        if (r7 == 0) goto L9c
                        java.lang.Object r7 = r3.next()     // Catch: java.lang.Exception -> L98
                        java.lang.String r7 = (java.lang.String) r7     // Catch: java.lang.Exception -> L98
                        java.lang.String r8 = r5.getString(r7)     // Catch: java.lang.Exception -> L98
                        java.lang.String r9 = "key"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r9)     // Catch: java.lang.Exception -> L98
                        java.lang.String r9 = "value"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r9)     // Catch: java.lang.Exception -> L98
                        r4.put(r7, r8)     // Catch: java.lang.Exception -> L98
                        goto L7a
                    L98:
                        r3 = move-exception
                        r3.printStackTrace()
                    L9c:
                        java.lang.String r3 = ""
                        com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment r2 = r2.newInstance(r4, r6, r3)
                        r0.setMSearchPostListFragment(r2)
                        androidx.fragment.app.FragmentManager r2 = r0.getChildFragmentManager()
                        androidx.fragment.app.FragmentTransaction r2 = r2.beginTransaction()
                        r3 = 2131362274(0x7f0a01e2, float:1.8344324E38)
                        com.jbzd.media.movecartoons.ui.search.child.CommonPostListFragment r4 = r0.getMSearchPostListFragment()
                        androidx.fragment.app.FragmentTransaction r2 = r2.replace(r3, r4)
                        r2.commit()
                    Lbb:
                        com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1$convert$1$1 r2 = new com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2$1$convert$1$1
                        r2.<init>(r10, r11, r12, r0)
                        r11.m3918h(r1, r2)
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.index.darkplay.DarkTabSingleFragment$orderTypeAdapter$2.C37571.convert(com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.PostHomeResponse$OrdersBean):void");
                }
            }

            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final C37571 invoke() {
                return new C37571(DarkTabSingleFragment.this);
            }
        });
        this.ll_posthome_categories = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$ll_posthome_categories$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = DarkTabSingleFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_posthome_categories);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.tv_title_block = LazyKt__LazyJVMKt.lazy(new Function0<BloodColorText>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$tv_title_block$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final BloodColorText invoke() {
                View view = DarkTabSingleFragment.this.getView();
                BloodColorText bloodColorText = view == null ? null : (BloodColorText) view.findViewById(R.id.tv_title_block);
                Intrinsics.checkNotNull(bloodColorText);
                return bloodColorText;
            }
        });
        this.rv_list_categories = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$rv_list_categories$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = DarkTabSingleFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_list_categories);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.ll_module_header_posthome = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$ll_module_header_posthome$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = DarkTabSingleFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_module_header_posthome);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.rv_list_type = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$rv_list_type$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = DarkTabSingleFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_list_type);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
    }

    private final DarkTabSingleFragment$categoriesAdapter$2.C37561 getCategoriesAdapter() {
        return (DarkTabSingleFragment$categoriesAdapter$2.C37561) this.categoriesAdapter.getValue();
    }

    private final String getMSearchType() {
        return (String) this.mSearchType.getValue();
    }

    private final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
    }

    private final DarkTabSingleFragment$orderTypeAdapter$2.C37571 getOrderTypeAdapter() {
        return (DarkTabSingleFragment$orderTypeAdapter$2.C37571) this.orderTypeAdapter.getValue();
    }

    private final void initBannerView(final List<? extends AdBean> banners) {
        if (banners == null || !C2354n.m2414N0(banners)) {
            getBanner_parent().setVisibility(8);
            return;
        }
        getBanner_parent().setVisibility(0);
        Banner<?, ?> banner = getBanner();
        banner.setIntercept(banners.size() != 1);
        Banner addBannerLifecycleObserver = banner.addBannerLifecycleObserver(requireActivity());
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(banners, 10));
        Iterator<T> it = banners.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(requireContext, arrayList, 0.0f, ShadowDrawableWrapper.COS_45, null, 16));
        banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.g.i.b
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                DarkTabSingleFragment.m5814initBannerView$lambda2$lambda1(DarkTabSingleFragment.this, banners, obj, i2);
            }
        });
        banner.setIndicator(new RectangleIndicator(requireContext()));
        banner.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$initBannerView$1$3
            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // com.youth.banner.listener.OnPageChangeListener
            @SuppressLint({"RestrictedApi"})
            public void onPageSelected(int position) {
            }
        });
        banner.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5814initBannerView$lambda2$lambda1(DarkTabSingleFragment this$0, List list, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        aVar.m176b(requireContext, (AdBean) list.get(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-7$lambda-6, reason: not valid java name */
    public static final void m5815initViews$lambda7$lambda6(final DarkTabSingleFragment this$0, final PostHomeViewModel this_run, PostHomeResponse postHomeResponse) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        List<AdBean> list = postHomeResponse.banner;
        if (list != null) {
            this$0.initBannerView(list);
        }
        if (postHomeResponse.categories.size() != 0) {
            this$0.getLl_posthome_categories().setVisibility(0);
            BloodColorText tv_title_block = this$0.getTv_title_block();
            PostHomeResponse value = this_run.getMPostHomeResponse().getValue();
            tv_title_block.setText(value == null ? null : value.block_name);
            RecyclerView rv_list_categories = this$0.getRv_list_categories();
            rv_list_categories.setAdapter(this$0.getCategoriesAdapter());
            List<PostHomeResponse.CategoriesBean> list2 = postHomeResponse.categories;
            if (list2 != null) {
                if (list2.size() > 3) {
                    this$0.getCategoriesAdapter().setNewData(postHomeResponse.categories.subList(0, 3));
                } else {
                    this$0.getCategoriesAdapter().setNewData(postHomeResponse.categories);
                }
            }
            rv_list_categories.setLayoutManager(new GridLayoutManager(this$0.requireContext(), 3));
            if (rv_list_categories.getItemDecorationCount() == 0) {
                rv_list_categories.addItemDecoration(new ItemDecorationH(C2354n.m2425R(this$0.requireContext(), 6.0f)));
            }
            C2354n.m2374A(this$0.getLl_module_header_posthome(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.DarkTabSingleFragment$initViews$1$2$2
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
                    Context requireContext = DarkTabSingleFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    PostHomeResponse value2 = this_run.getMPostHomeResponse().getValue();
                    Intrinsics.checkNotNull(value2);
                    String str = value2.block_name;
                    Intrinsics.checkNotNullExpressionValue(str, "mPostHomeResponse.value!!.block_name");
                    PostHomeResponse value3 = this_run.getMPostHomeResponse().getValue();
                    Intrinsics.checkNotNull(value3);
                    String str2 = value3.block_id;
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
            if (rv_list_type.getItemDecorationCount() == 0) {
                rv_list_type.addItemDecoration(new ItemDecorationH(C2354n.m2425R(this$0.requireContext(), 2.0f), C2354n.m2425R(this$0.requireContext(), 2.0f)));
            }
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Banner<?, ?> getBanner() {
        return (Banner) this.banner.getValue();
    }

    @NotNull
    public final ScaleRelativeLayout getBanner_parent() {
        return (ScaleRelativeLayout) this.banner_parent.getValue();
    }

    @NotNull
    public final String getKEY_TAB() {
        return this.KEY_TAB;
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
    public final LinearLayout getLl_posthome_categories() {
        return (LinearLayout) this.ll_posthome_categories.getValue();
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
    public final RecyclerView getRv_list_categories() {
        return (RecyclerView) this.rv_list_categories.getValue();
    }

    @NotNull
    public final RecyclerView getRv_list_type() {
        return (RecyclerView) this.rv_list_type.getValue();
    }

    @NotNull
    public final String getSEARCH_TYPE() {
        return this.SEARCH_TYPE;
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
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        String str;
        super.initViews();
        final PostHomeViewModel viewModel = getViewModel();
        MainMenusBean mTabBean = getMTabBean();
        if (mTabBean != null && (str = mTabBean.filter) != null) {
            PostHomeViewModel.postHome$default(getViewModel(), str, false, 2, null);
        }
        viewModel.getMPostHomeResponse().observe(this, new Observer() { // from class: b.a.a.a.t.g.i.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                DarkTabSingleFragment.m5815initViews$lambda7$lambda6(DarkTabSingleFragment.this, viewModel, (PostHomeResponse) obj);
            }
        });
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
