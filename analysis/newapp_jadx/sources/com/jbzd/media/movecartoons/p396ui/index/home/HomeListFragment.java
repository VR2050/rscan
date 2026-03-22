package com.jbzd.media.movecartoons.p396ui.index.home;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.RequiresApi;
import androidx.core.view.GravityCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.home.HomeTabBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.search.ModuleDetailActivity;
import com.jbzd.media.movecartoons.utils.GravitySnapHelper;
import com.jbzd.media.movecartoons.utils.MyAdAdapter;
import com.jbzd.media.movecartoons.utils.SpaceViewItemLine;
import com.jbzd.media.movecartoons.view.ProgressChangeButton;
import com.jbzd.media.movecartoons.view.RecyclerViewAtViewPager2;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;
import com.youth.banner.Banner;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0094\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0010\u000b\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 ^2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001^B\u0007¢\u0006\u0004\b]\u00107J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J?\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u00032\u000e\u0010\t\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\b2\u0006\u0010\u000b\u001a\u00020\n2\u000e\u0010\u000e\u001a\n\u0012\u0004\u0012\u00020\r\u0018\u00010\fH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J/\u0010\u0017\u001a\u00020\u00052\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u0014H\u0002¢\u0006\u0004\b\u0017\u0010\u0018J\u0017\u0010\u0019\u001a\u00020\u00052\u0006\u0010\u0013\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0019\u0010\u001aJ/\u0010\u001e\u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00020\u001b2\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u001d\u001a\u00020\u0014H\u0003¢\u0006\u0004\b\u001e\u0010\u001fJ\u001f\u0010 \u001a\u00020\u00052\u0006\u0010\u001c\u001a\u00020\u001b2\u0006\u0010\u0013\u001a\u00020\u0002H\u0002¢\u0006\u0004\b \u0010!J'\u0010%\u001a\u00020\u00052\u0006\u0010#\u001a\u00020\"2\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010$\u001a\u00020\u0014H\u0002¢\u0006\u0004\b%\u0010&J\u000f\u0010(\u001a\u00020'H\u0016¢\u0006\u0004\b(\u0010)J/\u0010,\u001a\"\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0014\u0018\u00010*j\u0010\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0014\u0018\u0001`+H\u0016¢\u0006\u0004\b,\u0010-J\u000f\u0010/\u001a\u00020.H\u0016¢\u0006\u0004\b/\u00100J\u0017\u00102\u001a\u00020\u00052\b\u00101\u001a\u0004\u0018\u00010'¢\u0006\u0004\b2\u00103J\u0017\u00105\u001a\u00020\u00052\b\u00104\u001a\u0004\u0018\u00010'¢\u0006\u0004\b5\u00103J\u000f\u00106\u001a\u00020\u0005H\u0016¢\u0006\u0004\b6\u00107J!\u0010<\u001a\u00020\u00052\u0006\u00109\u001a\u0002082\b\u0010;\u001a\u0004\u0018\u00010:H\u0016¢\u0006\u0004\b<\u0010=J\u001f\u0010@\u001a\u00020\u00052\u0006\u0010>\u001a\u00020\u001b2\u0006\u0010?\u001a\u00020\u0002H\u0016¢\u0006\u0004\b@\u0010!R\u001f\u0010D\u001a\u0004\u0018\u00010'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bA\u0010B\u001a\u0004\bC\u0010)R\u001d\u0010I\u001a\u00020E8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bF\u0010B\u001a\u0004\bG\u0010HR\u001d\u0010L\u001a\u00020E8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010B\u001a\u0004\bK\u0010HR\"\u0010M\u001a\u00020E8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bM\u0010N\u001a\u0004\bO\u0010H\"\u0004\bP\u0010QR\u0016\u0010S\u001a\u00020R8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bS\u0010TR\u001f\u0010Y\u001a\u0004\u0018\u00010U8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bV\u0010B\u001a\u0004\bW\u0010XR9\u0010\\\u001a\u001e\u0012\u0004\u0012\u00020'\u0012\u0004\u0012\u00020'0*j\u000e\u0012\u0004\u0012\u00020'\u0012\u0004\u0012\u00020'`+8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010B\u001a\u0004\b[\u0010-¨\u0006_"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;", "Landroid/view/ViewGroup;", "parentView", "", "initBannerGone", "(Landroid/view/ViewGroup;)V", "Lcom/youth/banner/Banner;", "bannerView", "Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;", "rv", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "banners", "initBannerView", "(Landroid/view/ViewGroup;Lcom/youth/banner/Banner;Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;Ljava/util/List;)V", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list", "outItem", "", "layout", "span", "setRecyclerView", "(Landroidx/recyclerview/widget/RecyclerView;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;II)V", "goToModuleDetail", "(Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;)V", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "outHelper", "mainSpan", "showVideoList", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;II)V", "showAD", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;)V", "Lcom/jbzd/media/movecartoons/view/ProgressChangeButton;", "pcb_change", "layoutPosition", "onChangeClick", "(Lcom/jbzd/media/movecartoons/view/ProgressChangeButton;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;I)V", "", "getEmptyTips", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "getAllItemType", "()Ljava/util/HashMap;", "Lc/a/d1;", "request", "()Lc/a/d1;", "tagIds", "updateTags", "(Ljava/lang/String;)V", "orderBy", "updateOrderBy", "onDestroyView", "()V", "Landroid/view/View;", "view", "Landroid/os/Bundle;", "savedInstanceState", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "helper", "item", "bindItem", "mPosition$delegate", "Lkotlin/Lazy;", "getMPosition", "mPosition", "", "mIsPersonalCustomize$delegate", "getMIsPersonalCustomize", "()Z", "mIsPersonalCustomize", "mIsFollow$delegate", "getMIsFollow", "mIsFollow", "hasShowMoreGood", "Z", "getHasShowMoreGood", "setHasShowMoreGood", "(Z)V", "Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "mAdAdapter", "Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "mParams$delegate", "getMParams", "mParams", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeListFragment extends BaseMutiListFragment<HomeTabBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_API = "key_api";

    @NotNull
    private static final String KEY_INDEX = "index";

    @NotNull
    private static final String KEY_IS_FOLLOW = "is_follow";

    @NotNull
    private static final String KEY_TAB = "tab_bean";

    @NotNull
    private static final String KEY_TAB_POS = "tab_position";
    private boolean hasShowMoreGood;

    /* renamed from: mIsFollow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIsFollow = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$mIsFollow$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Boolean invoke() {
            return Boolean.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final boolean invoke2() {
            Bundle arguments = HomeListFragment.this.getArguments();
            if (arguments == null) {
                return false;
            }
            return arguments.getBoolean(VideoListActivity.KEY_IS_FOLLOW, false);
        }
    });

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = HomeListFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$mPosition$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeListFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("tab_position");
        }
    });

    /* renamed from: mIsPersonalCustomize$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIsPersonalCustomize = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$mIsPersonalCustomize$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Boolean invoke() {
            return Boolean.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final boolean invoke2() {
            MainMenusBean mTabBean;
            mTabBean = HomeListFragment.this.getMTabBean();
            if (mTabBean == null) {
                return false;
            }
            return mTabBean.isPersonalCustomize();
        }
    });

    /* renamed from: mParams$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mParams = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$mParams$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return new HashMap<>();
        }
    });

    @NotNull
    private final MyAdAdapter mAdAdapter = new MyAdAdapter();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0014\u0010\u0015JA\u0010\f\u001a\u00020\u000b2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\b\b\u0002\u0010\u0007\u001a\u00020\u00062\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u00042\b\b\u0002\u0010\n\u001a\u00020\t¢\u0006\u0004\b\f\u0010\rR\u0016\u0010\u000e\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000e\u0010\u000fR\u0016\u0010\u0010\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0010\u0010\u000fR\u0016\u0010\u0011\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0011\u0010\u000fR\u0016\u0010\u0012\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0012\u0010\u000fR\u0016\u0010\u0013\u001a\u00020\u00048\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0013\u0010\u000f¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "", "position", "", "isFollow", "api", "", HomeListFragment.KEY_INDEX, "Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;Ljava/lang/String;ZLjava/lang/String;I)Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "KEY_API", "Ljava/lang/String;", "KEY_INDEX", "KEY_IS_FOLLOW", "KEY_TAB", "KEY_TAB_POS", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ HomeListFragment newInstance$default(Companion companion, MainMenusBean mainMenusBean, String str, boolean z, String str2, int i2, int i3, Object obj) {
            boolean z2 = (i3 & 4) != 0 ? false : z;
            if ((i3 & 8) != 0) {
                str2 = null;
            }
            return companion.newInstance(mainMenusBean, str, z2, str2, (i3 & 16) != 0 ? -1 : i2);
        }

        @NotNull
        public final HomeListFragment newInstance(@Nullable MainMenusBean tabBean, @Nullable String position, boolean isFollow, @Nullable String api, int index) {
            HomeListFragment homeListFragment = new HomeListFragment();
            Bundle bundle = new Bundle();
            bundle.putBoolean("is_follow", isFollow);
            bundle.putString(HomeListFragment.KEY_API, api);
            bundle.putSerializable("tab_bean", tabBean);
            bundle.putSerializable(HomeListFragment.KEY_TAB_POS, position);
            bundle.putInt(HomeListFragment.KEY_INDEX, index);
            Unit unit = Unit.INSTANCE;
            homeListFragment.setArguments(bundle);
            return homeListFragment;
        }
    }

    private final boolean getMIsFollow() {
        return ((Boolean) this.mIsFollow.getValue()).booleanValue();
    }

    private final boolean getMIsPersonalCustomize() {
        return ((Boolean) this.mIsPersonalCustomize.getValue()).booleanValue();
    }

    private final HashMap<String, String> getMParams() {
        return (HashMap) this.mParams.getValue();
    }

    private final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void goToModuleDetail(HomeTabBean outItem) {
        ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        HomeBlockBean homeBlockBean = outItem.block.get(0);
        Intrinsics.checkNotNullExpressionValue(homeBlockBean, "outItem.block[0]");
        companion.start(requireContext, homeBlockBean);
    }

    private final void initBannerGone(ViewGroup parentView) {
        parentView.setVisibility(8);
    }

    private final void initBannerView(ViewGroup parentView, Banner<?, ?> bannerView, RecyclerViewAtViewPager2 rv, List<? extends AdBean> banners) {
        if (banners == null || !C2354n.m2414N0(banners)) {
            rv.setVisibility(8);
            return;
        }
        rv.setVisibility(0);
        List asMutableList = TypeIntrinsics.asMutableList(banners);
        MyAdAdapter mAdAdapter = this.mAdAdapter;
        Intrinsics.checkNotNullParameter(rv, "<this>");
        Intrinsics.checkNotNullParameter(mAdAdapter, "mAdAdapter");
        if (asMutableList == null || asMutableList.isEmpty()) {
            rv.setVisibility(8);
            return;
        }
        rv.setVisibility(0);
        if (rv.getItemDecorationCount() == 0) {
            SpaceViewItemLine spaceViewItemLine = new SpaceViewItemLine(C4195m.m4785R(6.0f));
            spaceViewItemLine.f10124b = false;
            spaceViewItemLine.f10125c = false;
            rv.addItemDecoration(spaceViewItemLine);
        }
        if (rv.getOnFlingListener() == null) {
            new GravitySnapHelper(GravityCompat.START).attachToRecyclerView(rv);
        }
        mAdAdapter.setNewData(asMutableList);
        Unit unit = Unit.INSTANCE;
        rv.setAdapter(mAdAdapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void onChangeClick(final ProgressChangeButton pcb_change, final HomeTabBean outItem, final int layoutPosition) {
        boolean z = true;
        pcb_change.setProgress(true);
        String str = outItem.block.get(0).filter;
        HashMap hashMap = new HashMap();
        if (str != null && str.length() != 0) {
            z = false;
        }
        if (!z) {
            try {
                JSONObject jSONObject = new JSONObject(str);
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
        hashMap.put("page", String.valueOf(outItem.nextPage));
        hashMap.put("page_size", String.valueOf(outItem.block.get(0).page_size));
        hashMap.put("is_change", "1");
        C0917a.m222f(C0917a.f372a, "movie/search", VideoItemBean.class, hashMap, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$onChangeClick$1
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
                ProgressChangeButton.this.setProgress(false);
                try {
                    if (C2354n.m2414N0(list)) {
                        HomeTabBean homeTabBean = outItem;
                        Objects.requireNonNull(list, "null cannot be cast to non-null type java.util.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean>{ kotlin.collections.TypeAliasesKt.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean> }");
                        homeTabBean.items = (ArrayList) list;
                        homeTabBean.nextPage++;
                        this.getAdapter().notifyItemChanged(layoutPosition);
                    } else {
                        HomeTabBean homeTabBean2 = outItem;
                        if (homeTabBean2.nextPage != 1) {
                            homeTabBean2.nextPage = 1;
                        }
                    }
                } catch (Exception unused) {
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$onChangeClick$2
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

    private final void setRecyclerView(RecyclerView rv_list, final HomeTabBean outItem, final int layout, final int span) {
        if (rv_list.getAdapter() == null) {
            if (span == 0) {
                rv_list.setLayoutManager(new LinearLayoutManager(getContext(), 0, false));
            } else {
                rv_list.setLayoutManager(new GridLayoutManager(requireContext(), span));
            }
            if (rv_list.getItemDecorationCount() == 0 && outItem.getItemType() != 6) {
                if (outItem.getItemType() == 5) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
                    c4053a.m4576a(R.color.transparent);
                    c4053a.f10336d = C2354n.m2437V(getContext(), 2.0d);
                    c4053a.f10337e = C2354n.m2437V(getContext(), 3.0d);
                    c4053a.f10339g = false;
                    c4053a.f10340h = false;
                    c4053a.f10338f = false;
                    rv_list.addItemDecoration(new GridItemDecoration(c4053a));
                } else {
                    GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(getContext());
                    c4053a2.m4576a(R.color.transparent);
                    c4053a2.f10336d = C2354n.m2437V(getContext(), 3.0d);
                    c4053a2.f10337e = C2354n.m2437V(getContext(), 6.0d);
                    c4053a2.f10339g = false;
                    c4053a2.f10340h = false;
                    c4053a2.f10338f = false;
                    rv_list.addItemDecoration(new GridItemDecoration(c4053a2));
                }
            }
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>(span, this, outItem, layout) { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$setRecyclerView$1
                public final /* synthetic */ int $layout;
                public final /* synthetic */ HomeTabBean $outItem;
                public final /* synthetic */ int $span;
                public final /* synthetic */ HomeListFragment this$0;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(layout, null, 2, null);
                    this.$layout = layout;
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                @RequiresApi(23)
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    if (this.$span == 0) {
                        Context requireContext = this.this$0.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        VideoItemShowKt.showVideoItemMsgNew(requireContext, helper, item, (r23 & 8) != 0, (r23 & 16) != 0, (r23 & 32) != 0, (r23 & 64) != 0 ? true : true, (r23 & 128) != 0 ? false : false, (r23 & 256) != 0, (r23 & 512) != 0 ? false : false);
                    } else {
                        Context requireContext2 = this.this$0.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                        VideoItemShowKt.showVideoItemMsgNew(requireContext2, helper, item, (r23 & 8) != 0 ? true : true, (r23 & 16) != 0, (r23 & 32) != 0, (r23 & 64) != 0 ? true : true, (r23 & 128) != 0 ? false : false, (r23 & 256) != 0, (r23 & 512) != 0 ? false : false);
                    }
                    if (!helper.m3914d(R.id.space_left)) {
                        return;
                    }
                    helper.m3912b(R.id.space_left).setVisibility(8);
                    int size = getData().size();
                    if (size <= 0) {
                        return;
                    }
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        if (Intrinsics.areEqual(getData().get(i2), item) && i2 == 0) {
                            helper.m3912b(R.id.space_left).setVisibility(0);
                            helper.m3912b(R.id.space_left).setTag(this.$outItem);
                        }
                        if (i3 >= size) {
                            return;
                        } else {
                            i2 = i3;
                        }
                    }
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.k.e
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    HomeListFragment.m5831setRecyclerView$lambda8$lambda7(HomeListFragment.this, outItem, baseQuickAdapter2, view, i2);
                }
            });
            rv_list.setAdapter(baseQuickAdapter);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: setRecyclerView$lambda-8$lambda-7, reason: not valid java name */
    public static final void m5831setRecyclerView$lambda8$lambda7(HomeListFragment this$0, HomeTabBean outItem, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(outItem, "$outItem");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoItemBean");
        VideoItemBean videoItemBean = (VideoItemBean) obj;
        if (videoItemBean.getIsAd()) {
            C0840d.a aVar = C0840d.f235a;
            Context requireContext = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            AdBean adBean = videoItemBean.f9999ad;
            Intrinsics.checkNotNullExpressionValue(adBean, "item.ad");
            aVar.m176b(requireContext, adBean);
            return;
        }
        if (!videoItemBean.isShort()) {
            MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
            Context requireContext2 = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
            String str = videoItemBean.f10000id;
            if (str == null) {
                str = "";
            }
            companion.start(requireContext2, str);
            return;
        }
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(videoItemBean.realPage));
        HashMap<String, String> mParams = this$0.getMParams();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry<String, String> entry : mParams.entrySet()) {
            if (!TextUtils.equals(entry.getKey(), "page")) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        for (Map.Entry entry2 : linkedHashMap.entrySet()) {
            hashMap.put(entry2.getKey(), entry2.getValue());
        }
        hashMap.put("canvas", "short");
        String str2 = outItem.f10017id;
        Intrinsics.checkNotNullExpressionValue(str2, "outItem.id");
        hashMap.put("module_id", str2);
        PlayListActivity.Companion companion2 = PlayListActivity.INSTANCE;
        Context requireContext3 = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext3, "requireContext()");
        companion2.start(requireContext3, (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
    }

    private final void showAD(BaseViewHolder outHelper, HomeTabBean outItem) {
        final AdBean adBean = outItem.f10016ad;
        C2354n.m2463c2(this).m3298p(adBean == null ? null : adBean.content).m3295i0().m757R((ImageView) outHelper.m3912b(R.id.iv_img));
        C2354n.m2374A(outHelper.m3912b(R.id.ll_adParent_new), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$showAD$1$1
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
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = HomeListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                AdBean ad = adBean;
                Intrinsics.checkNotNullExpressionValue(ad, "ad");
                aVar.m176b(requireContext, ad);
            }
        }, 1);
    }

    @SuppressLint({"SuspiciousIndentation"})
    private final void showVideoList(final BaseViewHolder outHelper, final HomeTabBean outItem, int layout, int mainSpan) {
        if (outHelper.m3914d(R.id.v_listDivider)) {
            outHelper.m3916f(R.id.v_listDivider, false);
        }
        ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_modulename_left);
        if (outItem.ico.equals("")) {
            outHelper.m3916f(R.id.iv_modulename_left, true);
        } else {
            outHelper.m3916f(R.id.iv_modulename_left, false);
            if (outItem.ico.equals(BloggerOrderBean.order_new)) {
                imageView.setImageResource(R.drawable.icon_module_new);
            }
        }
        String str = outItem.name;
        outHelper.m3919i(R.id.tv_title_module, str != null ? str : "");
        C2354n.m2374A((ImageTextView) outHelper.m3912b(R.id.itv_header_more), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$showVideoList$1$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                HomeListFragment.this.goToModuleDetail(outItem);
            }
        }, 1);
        final ProgressChangeButton progressChangeButton = (ProgressChangeButton) outHelper.m3912b(R.id.pcb_change);
        MyThemeFragment.fadeWhenTouch$default(this, progressChangeButton, 0.0f, 1, null);
        C2354n.m2533z(progressChangeButton, 500L, new Function1<ProgressChangeButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$showVideoList$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ProgressChangeButton progressChangeButton2) {
                invoke2(progressChangeButton2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ProgressChangeButton it) {
                Intrinsics.checkNotNullParameter(it, "it");
                HomeListFragment.this.onChangeClick(progressChangeButton, outItem, outHelper.getLayoutPosition());
            }
        });
        C2354n.m2533z(outHelper.m3912b(R.id.ll_footer_more), 500L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$showVideoList$1$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull View it) {
                Intrinsics.checkNotNullParameter(it, "it");
                HomeListFragment.this.goToModuleDetail(outItem);
            }
        });
        RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setNestedScrollingEnabled(false);
        setRecyclerView(recyclerView, outItem, layout, mainSpan);
        ArrayList<VideoItemBean> arrayList = outItem.items;
        Intrinsics.checkNotNullExpressionValue(arrayList, "outItem.items");
        List mutableList = CollectionsKt___CollectionsKt.toMutableList((Collection) arrayList);
        recyclerView.setTag(mutableList);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        Objects.requireNonNull(adapter, "null cannot be cast to non-null type com.chad.library.adapter.base.BaseQuickAdapter<com.jbzd.media.movecartoons.bean.response.VideoItemBean, com.chad.library.adapter.base.viewholder.BaseViewHolder>");
        ((BaseQuickAdapter) adapter).setNewData(mutableList);
        if (outHelper.m3914d(R.id.rv_list1)) {
            RecyclerView recyclerView2 = (RecyclerView) outHelper.m3912b(R.id.rv_list1);
            setRecyclerView(recyclerView2, outItem, R.layout.video_long_item1, 1);
            ArrayList<VideoItemBean> arrayList2 = outItem.items;
            Intrinsics.checkNotNullExpressionValue(arrayList2, "outItem.items");
            List mutableList2 = CollectionsKt___CollectionsKt.toMutableList((Collection) arrayList2);
            if (mutableList.size() > 0) {
                mutableList.remove(0);
            }
            mutableList2.removeAll(mutableList);
            recyclerView2.setTag(mutableList2);
            RecyclerView.Adapter adapter2 = recyclerView2.getAdapter();
            Objects.requireNonNull(adapter2, "null cannot be cast to non-null type com.chad.library.adapter.base.BaseQuickAdapter<com.jbzd.media.movecartoons.bean.response.VideoItemBean, com.chad.library.adapter.base.viewholder.BaseViewHolder>");
            ((BaseQuickAdapter) adapter2).setNewData(mutableList2);
        }
        if (outItem.f10016ad == null) {
            outHelper.m3916f(R.id.ll_adParent_bottom, true);
            return;
        }
        outHelper.m3916f(R.id.ll_adParent_bottom, false);
        final AdBean adBean = outItem.f10016ad;
        C2354n.m2463c2(this).m3298p(adBean != null ? adBean.content : null).m3295i0().m757R((ImageView) outHelper.m3912b(R.id.iv_img_bottom));
        View view = outHelper.m3912b(R.id.iv_img_bottom);
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(6.0d));
        view.setClipToOutline(true);
        C2354n.m2374A(outHelper.m3912b(R.id.banner_parent), 0L, new Function1<ScaleRelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$showVideoList$1$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ScaleRelativeLayout scaleRelativeLayout) {
                invoke2(scaleRelativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ScaleRelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = HomeListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                AdBean ad = adBean;
                Intrinsics.checkNotNullExpressionValue(ad, "ad");
                aVar.m176b(requireContext, ad);
            }
        }, 1);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @Nullable
    public HashMap<Integer, Integer> getAllItemType() {
        HashMap<Integer, Integer> hashMap = new HashMap<>();
        hashMap.put(1, Integer.valueOf(R.layout.block_style_module_double));
        hashMap.put(2, Integer.valueOf(R.layout.block_style_module_simple_horizontal));
        Integer valueOf = Integer.valueOf(R.layout.block_style_module_simple);
        hashMap.put(3, valueOf);
        Integer valueOf2 = Integer.valueOf(R.layout.block_style_module_portrait_grid);
        hashMap.put(4, valueOf2);
        hashMap.put(5, valueOf);
        hashMap.put(6, Integer.valueOf(R.layout.block_style_module_simple_long));
        hashMap.put(7, valueOf2);
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public String getEmptyTips() {
        if (getMIsFollow()) {
            return "一个关注都没有";
        }
        String string = getString(R.string.empty_no_data);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.empty_no_data)");
        return string;
    }

    public final boolean getHasShowMoreGood() {
        return this.hasShowMoreGood;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        getLifecycle().removeObserver(this.mAdAdapter);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
        getLifecycle().addObserver(this.mAdAdapter);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        if (getCurrentPage() == 1) {
            this.hasShowMoreGood = false;
        }
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (getMTabBean() != null) {
            String mPosition = getMPosition();
            if (mPosition != null) {
            }
            MainMenusBean mTabBean = getMTabBean();
            Intrinsics.checkNotNull(mTabBean);
            hashMap.put("code", mTabBean.code);
            hashMap.put("page", String.valueOf(getCurrentPage()));
            hashMap.put("page_size", "6");
        }
        Unit unit = Unit.INSTANCE;
        return C0917a.m221e(c0917a, "movie/home", HomeTabBean.class, hashMap, new Function1<HomeTabBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(HomeTabBean homeTabBean) {
                invoke2(homeTabBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable HomeTabBean homeTabBean) {
                ArrayList arrayList = new ArrayList();
                if (homeTabBean != null) {
                    Iterator<HomeBlockBean> it = homeTabBean.block.iterator();
                    while (it.hasNext()) {
                        HomeBlockBean next = it.next();
                        HomeTabBean homeTabBean2 = new HomeTabBean();
                        homeTabBean2.f10017id = next.f9955id;
                        homeTabBean2.name = next.name;
                        homeTabBean2.filter = next.filter;
                        homeTabBean2.style = next.style;
                        homeTabBean2.items = next.items;
                        homeTabBean2.f10016ad = next.f9954ad;
                        homeTabBean2.page_size = next.page_size;
                        homeTabBean2.block = CollectionsKt__CollectionsKt.arrayListOf(next);
                        arrayList.add(homeTabBean2);
                    }
                    ArrayList<AdBean> arrayList2 = homeTabBean.banner;
                    if (arrayList2 != null && arrayList2.size() > 0 && arrayList.size() > 0) {
                        ((HomeTabBean) arrayList.get(0)).banner = homeTabBean.banner;
                    }
                }
                HomeListFragment.this.didRequestComplete(arrayList);
            }
        }, null, false, false, null, false, 496);
    }

    public final void setHasShowMoreGood(boolean z) {
        this.hasShowMoreGood = z;
    }

    public final void updateOrderBy(@Nullable String orderBy) {
        HashMap<String, String> mParams = getMParams();
        if (orderBy == null) {
            orderBy = "";
        }
        mParams.put("order_by", orderBy);
        reset();
    }

    public final void updateTags(@Nullable String tagIds) {
        if (getMIsPersonalCustomize()) {
            HashMap<String, String> mParams = getMParams();
            if (tagIds == null) {
                tagIds = "";
            }
            mParams.put("tag_id", tagIds);
            reset();
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull HomeTabBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).setVisibility(8);
        if (helper.getAdapterPosition() == 0) {
            initBannerView((ViewGroup) helper.m3912b(R.id.banner_view), (Banner) helper.m3912b(R.id.banner_video_item), (RecyclerViewAtViewPager2) helper.m3912b(R.id.banner2), item.banner);
            ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).setVisibility(8);
            MyApp myApp = MyApp.f9891f;
            if (MyApp.m4185f().movie_notice != null) {
                ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).setVisibility(0);
                ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).setText(MyApp.m4185f().movie_notice.content);
                ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).m4583c();
            }
        } else {
            ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).setVisibility(8);
            initBannerGone((ViewGroup) helper.m3912b(R.id.banner_view));
        }
        switch (item.getItemType()) {
            case 1:
                showVideoList(helper, item, R.layout.video_long_item1, 2);
                break;
            case 2:
                showVideoList(helper, item, R.layout.video_long_item1, 2);
                break;
            case 3:
                showVideoList(helper, item, R.layout.video_long_item1, 1);
                break;
            case 4:
                showVideoList(helper, item, R.layout.video_short_item1, 2);
                break;
            case 5:
                int size = item.items.size();
                if (size > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        if (i2 == item.items.size() - 1) {
                            item.items.get(i2).module_id = item.f10017id;
                            item.items.get(i2).module_name = item.name;
                            item.items.get(i2).canvas = item.more_canvas;
                            item.items.get(i2).mHomeTabBean = item;
                        }
                        if (i3 < size) {
                            i2 = i3;
                        }
                    }
                }
                showVideoList(helper, item, R.layout.video_short_item_fixed, 0);
                break;
            case 6:
                int size2 = item.items.size();
                if (size2 > 0) {
                    int i4 = 0;
                    while (true) {
                        int i5 = i4 + 1;
                        if (i4 == item.items.size() - 1) {
                            item.items.get(i4).module_id = item.f10017id;
                            item.items.get(i4).module_name = item.name;
                            item.items.get(i4).canvas = item.more_canvas;
                            item.items.get(i4).mHomeTabBean = item;
                        }
                        if (i5 < size2) {
                            i4 = i5;
                        }
                    }
                }
                showVideoList(helper, item, R.layout.video_long_item3, 0);
                break;
            case 7:
                showVideoList(helper, item, R.layout.video_short_item1, 3);
                break;
        }
    }
}
