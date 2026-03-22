package com.jbzd.media.movecartoons.p396ui.index.home;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.RequiresApi;
import androidx.core.view.GravityCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.home.HomeTabBean;
import com.jbzd.media.movecartoons.bean.response.home.HomeTabComicsBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailActivity;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeListComicsFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity;
import com.jbzd.media.movecartoons.p396ui.search.ComicsBlockListActivity;
import com.jbzd.media.movecartoons.p396ui.search.ComicsDayInfoActivity;
import com.jbzd.media.movecartoons.p396ui.search.ComicsModuleDetailActivity;
import com.jbzd.media.movecartoons.utils.GravitySnapHelper;
import com.jbzd.media.movecartoons.utils.MyAdAdapter;
import com.jbzd.media.movecartoons.utils.SpaceViewItemLine;
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
import java.util.List;
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
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.Typography;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0096\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 R2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001RB\u0007¢\u0006\u0004\bQ\u00101J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J?\u0010\u000f\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u00032\u000e\u0010\t\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\b2\u0006\u0010\u000b\u001a\u00020\n2\u000e\u0010\u000e\u001a\n\u0012\u0004\u0012\u00020\r\u0018\u00010\fH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J/\u0010\u0017\u001a\u00020\u00052\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u0014H\u0002¢\u0006\u0004\b\u0017\u0010\u0018J/\u0010\u001c\u001a\u00020\u00052\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u0013\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u001b\u001a\u00020\u0014H\u0003¢\u0006\u0004\b\u001c\u0010\u001dJ\u001f\u0010\u001f\u001a\u00020\u00052\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u0013\u001a\u00020\u001eH\u0002¢\u0006\u0004\b\u001f\u0010 J'\u0010$\u001a\u00020\u00052\u0006\u0010\"\u001a\u00020!2\u0006\u0010\u0013\u001a\u00020\u001e2\u0006\u0010#\u001a\u00020\u0014H\u0002¢\u0006\u0004\b$\u0010%J\u000f\u0010'\u001a\u00020&H\u0016¢\u0006\u0004\b'\u0010(J/\u0010+\u001a\"\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0014\u0018\u00010)j\u0010\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0014\u0018\u0001`*H\u0016¢\u0006\u0004\b+\u0010,J\u000f\u0010.\u001a\u00020-H\u0016¢\u0006\u0004\b.\u0010/J\u000f\u00100\u001a\u00020\u0005H\u0016¢\u0006\u0004\b0\u00101J!\u00104\u001a\u00020\u00052\u0006\u0010\"\u001a\u00020!2\b\u00103\u001a\u0004\u0018\u000102H\u0016¢\u0006\u0004\b4\u00105J\u001f\u00108\u001a\u00020\u00052\u0006\u00106\u001a\u00020\u00192\u0006\u00107\u001a\u00020\u0002H\u0016¢\u0006\u0004\b8\u00109R\u001d\u0010?\u001a\u00020:8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b;\u0010<\u001a\u0004\b=\u0010>R\u001d\u0010B\u001a\u00020:8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b@\u0010<\u001a\u0004\bA\u0010>R\u0016\u0010D\u001a\u00020C8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bD\u0010ER9\u0010H\u001a\u001e\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020&0)j\u000e\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020&`*8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bF\u0010<\u001a\u0004\bG\u0010,R\u001f\u0010M\u001a\u0004\u0018\u00010I8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010<\u001a\u0004\bK\u0010LR\u001f\u0010P\u001a\u0004\u0018\u00010&8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bN\u0010<\u001a\u0004\bO\u0010(¨\u0006S"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeListComicsFragment;", "Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabComicsBean;", "Landroid/view/ViewGroup;", "parentView", "", "initBannerGone", "(Landroid/view/ViewGroup;)V", "Lcom/youth/banner/Banner;", "bannerView", "Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;", "rv", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "banners", "initBannerView", "(Landroid/view/ViewGroup;Lcom/youth/banner/Banner;Lcom/jbzd/media/movecartoons/view/RecyclerViewAtViewPager2;Ljava/util/List;)V", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list", "outItem", "", "layout", "span", "setRecyclerView", "(Landroidx/recyclerview/widget/RecyclerView;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabComicsBean;II)V", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "outHelper", "mainSpan", "showComicsList", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabComicsBean;II)V", "Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;", "showAD", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;)V", "Landroid/view/View;", "view", "layoutPosition", "onChangeClick", "(Landroid/view/View;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;I)V", "", "getEmptyTips", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "getAllItemType", "()Ljava/util/HashMap;", "Lc/a/d1;", "request", "()Lc/a/d1;", "onDestroyView", "()V", "Landroid/os/Bundle;", "savedInstanceState", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabComicsBean;)V", "", "mIsFollow$delegate", "Lkotlin/Lazy;", "getMIsFollow", "()Z", "mIsFollow", "mIsPersonalCustomize$delegate", "getMIsPersonalCustomize", "mIsPersonalCustomize", "Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "mAdAdapter", "Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "mParams$delegate", "getMParams", "mParams", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "mInto$delegate", "getMInto", "mInto", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeListComicsFragment extends BaseMutiListFragment<HomeTabComicsBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_IS_FOLLOW = "is_follow";

    @NotNull
    private static final String KEY_TAB = "tab_bean";

    @NotNull
    private static final String KEY_TYPE = "into_type";

    /* renamed from: mInto$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInto = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$mInto$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeListComicsFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("into");
        }
    });

    /* renamed from: mIsFollow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIsFollow = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$mIsFollow$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Boolean invoke() {
            return Boolean.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final boolean invoke2() {
            Bundle arguments = HomeListComicsFragment.this.getArguments();
            if (arguments == null) {
                return false;
            }
            return arguments.getBoolean(VideoListActivity.KEY_IS_FOLLOW, false);
        }
    });

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = HomeListComicsFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: mIsPersonalCustomize$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIsPersonalCustomize = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$mIsPersonalCustomize$2
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
            mTabBean = HomeListComicsFragment.this.getMTabBean();
            if (mTabBean == null) {
                return false;
            }
            return mTabBean.isPersonalCustomize();
        }
    });

    /* renamed from: mParams$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mParams = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$mParams$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return new HashMap<>();
        }
    });

    @NotNull
    private final MyAdAdapter mAdAdapter = new MyAdAdapter();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J-\u0010\t\u001a\u00020\b2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u0006¢\u0006\u0004\b\t\u0010\nR\u0016\u0010\u000b\u001a\u00020\u00068\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\u00068\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\r\u0010\fR\u0016\u0010\u000e\u001a\u00020\u00068\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000e\u0010\f¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeListComicsFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "", "isFollow", "", "into", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeListComicsFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;ZLjava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/home/HomeListComicsFragment;", "KEY_IS_FOLLOW", "Ljava/lang/String;", "KEY_TAB", "KEY_TYPE", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ HomeListComicsFragment newInstance$default(Companion companion, MainMenusBean mainMenusBean, boolean z, String str, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                z = false;
            }
            if ((i2 & 4) != 0) {
                str = null;
            }
            return companion.newInstance(mainMenusBean, z, str);
        }

        @NotNull
        public final HomeListComicsFragment newInstance(@Nullable MainMenusBean tabBean, boolean isFollow, @Nullable String into) {
            HomeListComicsFragment homeListComicsFragment = new HomeListComicsFragment();
            Bundle bundle = new Bundle();
            bundle.putBoolean("is_follow", isFollow);
            bundle.putSerializable("tab_bean", tabBean);
            bundle.putString("into", into);
            Unit unit = Unit.INSTANCE;
            homeListComicsFragment.setArguments(bundle);
            return homeListComicsFragment;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-4$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5829bindItem$lambda4$lambda3$lambda2(HomeListComicsFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.home.HomeTabComicsBean.Buttons");
        HomeTabComicsBean.Buttons buttons = (HomeTabComicsBean.Buttons) obj;
        if (buttons.getShow_type().equals("block")) {
            ComicsBlockListActivity.Companion companion = ComicsBlockListActivity.INSTANCE;
            Context requireContext = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            String name = buttons.getName();
            Intrinsics.checkNotNullExpressionValue(name, "itemButton.name");
            String filter = buttons.getFilter();
            Intrinsics.checkNotNullExpressionValue(filter, "itemButton.filter");
            companion.start(requireContext, name, filter);
            return;
        }
        if (buttons.getShow_type().equals("day")) {
            ComicsDayInfoActivity.Companion companion2 = ComicsDayInfoActivity.INSTANCE;
            Context requireContext2 = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
            String filter2 = buttons.getFilter();
            Intrinsics.checkNotNullExpressionValue(filter2, "itemButton.filter");
            companion2.start(requireContext2, filter2);
            return;
        }
        ComicsModuleDetailActivity.Companion companion3 = ComicsModuleDetailActivity.INSTANCE;
        Context requireContext3 = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext3, "requireContext()");
        String name2 = buttons.getName();
        Intrinsics.checkNotNullExpressionValue(name2, "itemButton.name");
        String filter3 = buttons.getFilter();
        Intrinsics.checkNotNullExpressionValue(filter3, "itemButton.filter");
        String show_type = buttons.getShow_type();
        Intrinsics.checkNotNullExpressionValue(show_type, "itemButton.show_type");
        companion3.start(requireContext3, name2, filter3, show_type);
    }

    private final String getMInto() {
        return (String) this.mInto.getValue();
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

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
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

    private final void onChangeClick(View view, final HomeTabBean outItem, final int layoutPosition) {
        String str = outItem.block.get(0).filter;
        HashMap hashMap = new HashMap();
        if (!(str == null || str.length() == 0)) {
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
        C0917a.m222f(C0917a.f372a, "movie/search", VideoItemBean.class, hashMap, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$onChangeClick$1
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
                try {
                    if (C2354n.m2414N0(list)) {
                        HomeTabBean homeTabBean = HomeTabBean.this;
                        Objects.requireNonNull(list, "null cannot be cast to non-null type java.util.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean>{ kotlin.collections.TypeAliasesKt.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean> }");
                        homeTabBean.items = (ArrayList) list;
                        homeTabBean.nextPage++;
                        this.getAdapter().notifyItemChanged(layoutPosition);
                    } else {
                        HomeTabBean homeTabBean2 = HomeTabBean.this;
                        if (homeTabBean2.nextPage != 1) {
                            homeTabBean2.nextPage = 1;
                        }
                    }
                } catch (Exception unused) {
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$onChangeClick$2
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

    private final void setRecyclerView(RecyclerView rv_list, final HomeTabComicsBean outItem, final int layout, int span) {
        if (rv_list.getAdapter() == null) {
            if (span == 0) {
                rv_list.setLayoutManager(new LinearLayoutManager(requireContext(), 0, false));
            } else {
                rv_list.setLayoutManager(new GridLayoutManager(requireContext(), span));
            }
            if (rv_list.getItemDecorationCount() == 0) {
                if (outItem.getItemType() == 1) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
                    c4053a.m4576a(R.color.transparent);
                    c4053a.f10336d = C2354n.m2437V(getContext(), 1.0d);
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
            BaseQuickAdapter<HomeComicsBlockBean.ComicsItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<HomeComicsBlockBean.ComicsItemBean, BaseViewHolder>(outItem, layout) { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$setRecyclerView$1
                public final /* synthetic */ int $layout;
                public final /* synthetic */ HomeTabComicsBean $outItem;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(layout, null, 2, null);
                    this.$layout = layout;
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                @RequiresApi(23)
                public void convert(@NotNull BaseViewHolder helper, @NotNull HomeComicsBlockBean.ComicsItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    C2354n.m2463c2(HomeListComicsFragment.this).m3298p(item.img).m3292f0().m757R((ImageView) helper.m3912b(R.id.img_cover));
                    View view = helper.m3912b(R.id.img_cover);
                    Intrinsics.checkNotNullParameter(view, "view");
                    view.setOutlineProvider(new C0859m0(6.0d));
                    view.setClipToOutline(true);
                    helper.m3919i(R.id.tv_comics_name, item.name);
                    helper.m3919i(R.id.tv_comics_category_subtitle, item.category + Typography.middleDot + ((Object) item.sub_title));
                    ImageView imageView = (ImageView) helper.m3912b(R.id.iv_ico_type);
                    imageView.setVisibility(!item.ico.equals("") ? 0 : 8);
                    if (item.ico.equals(VideoTypeBean.video_type_free)) {
                        C2354n.m2463c2(HomeListComicsFragment.this).m3297o(Integer.valueOf(R.drawable.icon_mh_free)).m3295i0().m757R(imageView);
                    } else if (item.ico.equals(BloggerOrderBean.order_new)) {
                        C2354n.m2463c2(HomeListComicsFragment.this).m3297o(Integer.valueOf(R.drawable.icon_mh_new)).m3295i0().m757R(imageView);
                    } else {
                        C2354n.m2463c2(HomeListComicsFragment.this).m3297o(Integer.valueOf(R.drawable.icon_mh_hot)).m3295i0().m757R(imageView);
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
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.k.c
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    HomeListComicsFragment.m5830setRecyclerView$lambda6$lambda5(HomeListComicsFragment.this, baseQuickAdapter2, view, i2);
                }
            });
            rv_list.setAdapter(baseQuickAdapter);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: setRecyclerView$lambda-6$lambda-5, reason: not valid java name */
    public static final void m5830setRecyclerView$lambda6$lambda5(HomeListComicsFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean.ComicsItemBean");
        HomeComicsBlockBean.ComicsItemBean comicsItemBean = (HomeComicsBlockBean.ComicsItemBean) obj;
        if (StringsKt__StringsJVMKt.equals$default(this$0.getMInto(), "bcy_home_novel", false, 2, null)) {
            NovelDetailActivity.Companion companion = NovelDetailActivity.INSTANCE;
            Context requireContext = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            String str = comicsItemBean.f9958id;
            Intrinsics.checkNotNullExpressionValue(str, "mComicsItemBean.id");
            companion.start(requireContext, str);
            return;
        }
        ComicsDetailActivity.Companion companion2 = ComicsDetailActivity.INSTANCE;
        Context requireContext2 = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
        String str2 = comicsItemBean.f9958id;
        Intrinsics.checkNotNullExpressionValue(str2, "mComicsItemBean.id");
        companion2.start(requireContext2, str2);
    }

    private final void showAD(BaseViewHolder outHelper, HomeTabBean outItem) {
        final AdBean adBean = outItem.f10016ad;
        C2354n.m2463c2(this).m3298p(adBean == null ? null : adBean.content).m3295i0().m757R((ImageView) outHelper.m3912b(R.id.iv_img));
        C2354n.m2374A(outHelper.m3912b(R.id.ll_adParent_new), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$showAD$1$1
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
                Context requireContext = HomeListComicsFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                AdBean ad = adBean;
                Intrinsics.checkNotNullExpressionValue(ad, "ad");
                aVar.m176b(requireContext, ad);
            }
        }, 1);
    }

    @SuppressLint({"SuspiciousIndentation"})
    private final void showComicsList(BaseViewHolder outHelper, final HomeTabComicsBean outItem, int layout, int mainSpan) {
        if (outHelper.m3914d(R.id.v_listDivider)) {
            outHelper.m3916f(R.id.v_listDivider, false);
        }
        ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_modulename_left);
        if (outItem.ico.equals(BloggerOrderBean.order_new)) {
            C2354n.m2463c2(this).m3297o(Integer.valueOf(R.drawable.icon_module_new)).m3295i0().m757R(imageView);
        } else if (outItem.ico.equals("hot")) {
            C2354n.m2463c2(this).m3297o(Integer.valueOf(R.drawable.icon_module_hot)).m3295i0().m757R(imageView);
        } else {
            C2354n.m2463c2(this).m3297o(Integer.valueOf(R.drawable.icon_module_star)).m3295i0().m757R(imageView);
        }
        String str = outItem.name;
        if (str == null) {
            str = "";
        }
        outHelper.m3919i(R.id.tv_title_module, str);
        C2354n.m2374A((ImageTextView) outHelper.m3912b(R.id.itv_header_more), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$showComicsList$1$1$1
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
                ComicsModuleDetailActivity.Companion companion = ComicsModuleDetailActivity.INSTANCE;
                Context requireContext = HomeListComicsFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str2 = outItem.name;
                Intrinsics.checkNotNullExpressionValue(str2, "outItem.name");
                String str3 = outItem.filter;
                Intrinsics.checkNotNullExpressionValue(str3, "outItem.filter");
                companion.start(requireContext, str2, str3, "");
            }
        }, 1);
        RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setNestedScrollingEnabled(false);
        setRecyclerView(recyclerView, outItem, layout, mainSpan);
        ArrayList<HomeComicsBlockBean.ComicsItemBean> arrayList = outItem.items;
        Intrinsics.checkNotNullExpressionValue(arrayList, "outItem.items");
        List mutableList = CollectionsKt___CollectionsKt.toMutableList((Collection) arrayList);
        recyclerView.setTag(mutableList);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        Objects.requireNonNull(adapter, "null cannot be cast to non-null type com.chad.library.adapter.base.BaseQuickAdapter<com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean.ComicsItemBean, com.chad.library.adapter.base.viewholder.BaseViewHolder>");
        ((BaseQuickAdapter) adapter).setNewData(mutableList);
        if (outItem.f10018ad == null) {
            outHelper.m3916f(R.id.ll_adParent_bottom, true);
            return;
        }
        outHelper.m3916f(R.id.ll_adParent_bottom, false);
        final AdBean adBean = outItem.f10018ad;
        C2354n.m2463c2(this).m3298p(adBean == null ? null : adBean.content).m3295i0().m757R((ImageView) outHelper.m3912b(R.id.iv_img_bottom));
        C2354n.m2374A(outHelper.m3912b(R.id.banner_parent), 0L, new Function1<ScaleRelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$showComicsList$1$2
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
                Context requireContext = HomeListComicsFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str2 = adBean.link;
                Intrinsics.checkNotNullExpressionValue(str2, "ad.link");
                aVar.m175a(requireContext, str2);
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
        hashMap.put(1, Integer.valueOf(R.layout.block_style_module_simple));
        Integer valueOf = Integer.valueOf(R.layout.block_style_module_portrait_grid);
        hashMap.put(2, valueOf);
        hashMap.put(3, valueOf);
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public String getEmptyTips() {
        return getMIsFollow() ? "一个关注都没有" : "人家也是有底线的啦…";
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
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (getMTabBean() != null) {
            MainMenusBean mTabBean = getMTabBean();
            Intrinsics.checkNotNull(mTabBean);
            hashMap.put("code", mTabBean.code);
            hashMap.put("page", String.valueOf(getCurrentPage()));
        }
        Unit unit = Unit.INSTANCE;
        return C0917a.m221e(c0917a, "comics/home", HomeTabComicsBean.class, hashMap, new Function1<HomeTabComicsBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(HomeTabComicsBean homeTabComicsBean) {
                invoke2(homeTabComicsBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable HomeTabComicsBean homeTabComicsBean) {
                ArrayList arrayList = new ArrayList();
                if (homeTabComicsBean != null) {
                    Iterator<HomeComicsBlockBean> it = homeTabComicsBean.block.iterator();
                    while (it.hasNext()) {
                        HomeComicsBlockBean next = it.next();
                        HomeTabComicsBean homeTabComicsBean2 = new HomeTabComicsBean();
                        homeTabComicsBean2.f10019id = next.f9957id;
                        homeTabComicsBean2.name = next.name;
                        homeTabComicsBean2.filter = next.filter;
                        homeTabComicsBean2.style = next.style;
                        homeTabComicsBean2.ico = next.ico;
                        homeTabComicsBean2.buttons = homeTabComicsBean.buttons;
                        homeTabComicsBean2.items = next.items;
                        homeTabComicsBean2.f10018ad = next.f9956ad;
                        homeTabComicsBean2.page_size = next.page_size;
                        homeTabComicsBean2.block = CollectionsKt__CollectionsKt.arrayListOf(next);
                        arrayList.add(homeTabComicsBean2);
                    }
                    ArrayList<AdBean> arrayList2 = homeTabComicsBean.banner;
                    if (arrayList2 != null && arrayList2.size() > 0 && arrayList.size() > 0) {
                        ((HomeTabComicsBean) arrayList.get(0)).banner = homeTabComicsBean.banner;
                    }
                }
                HomeListComicsFragment.this.didRequestComplete(arrayList);
            }
        }, null, false, false, null, false, 496);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull HomeTabComicsBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        if (helper.getAdapterPosition() == 0) {
            ((MarqueeTextView) helper.m3912b(R.id.tv_user_new_tips_video)).setVisibility(8);
            RecyclerView recyclerView = (RecyclerView) helper.m3912b(R.id.rv_list_function);
            if (item.buttons.isEmpty()) {
                recyclerView.setVisibility(8);
            } else {
                recyclerView.setVisibility(0);
                if (recyclerView.getAdapter() == null) {
                    recyclerView.setLayoutManager(new GridLayoutManager(requireContext(), 4));
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
                    c4053a.m4576a(R.color.transparent);
                    c4053a.f10336d = C2354n.m2437V(getContext(), 2.0d);
                    c4053a.f10337e = C2354n.m2437V(getContext(), 3.0d);
                    c4053a.f10339g = false;
                    c4053a.f10340h = false;
                    c4053a.f10338f = false;
                    recyclerView.addItemDecoration(new GridItemDecoration(c4053a));
                    BaseQuickAdapter<HomeTabComicsBean.Buttons, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<HomeTabComicsBean.Buttons, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeListComicsFragment$bindItem$1$1
                        @Override // com.chad.library.adapter.base.BaseQuickAdapter
                        @RequiresApi(23)
                        public void convert(@NotNull BaseViewHolder helper2, @NotNull HomeTabComicsBean.Buttons item2) {
                            Intrinsics.checkNotNullParameter(helper2, "helper");
                            Intrinsics.checkNotNullParameter(item2, "item");
                            TextView textView = (TextView) helper2.m3912b(R.id.itv_function_name);
                            ImageView imageView = (ImageView) helper2.m3912b(R.id.icon_function_comics);
                            textView.setText(item2.getName());
                            if (item2.getIco().equals("special")) {
                                C2354n.m2455a2(getContext()).m3297o(Integer.valueOf(R.drawable.ic_comics_special)).m3295i0().m757R(imageView);
                                return;
                            }
                            if (item2.getIco().equals(VideoTypeBean.video_type_free)) {
                                C2354n.m2455a2(getContext()).m3297o(Integer.valueOf(R.drawable.ic_comics_free)).m3295i0().m757R(imageView);
                            } else if (item2.getIco().equals("day")) {
                                C2354n.m2455a2(getContext()).m3297o(Integer.valueOf(R.drawable.ic_comics_day)).m3295i0().m757R(imageView);
                            } else {
                                C2354n.m2455a2(getContext()).m3297o(Integer.valueOf(R.drawable.ic_comics_end)).m3295i0().m757R(imageView);
                            }
                        }
                    };
                    baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.k.d
                        @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                        public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                            HomeListComicsFragment.m5829bindItem$lambda4$lambda3$lambda2(HomeListComicsFragment.this, baseQuickAdapter2, view, i2);
                        }
                    });
                    recyclerView.setAdapter(baseQuickAdapter);
                }
                RecyclerView.Adapter adapter = recyclerView.getAdapter();
                Objects.requireNonNull(adapter, "null cannot be cast to non-null type com.chad.library.adapter.base.BaseQuickAdapter<com.jbzd.media.movecartoons.bean.response.home.HomeTabComicsBean.Buttons, com.chad.library.adapter.base.viewholder.BaseViewHolder>");
                ((BaseQuickAdapter) adapter).setNewData(item.buttons);
            }
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
            ((RecyclerView) helper.m3912b(R.id.rv_list_function)).setVisibility(8);
            initBannerGone((ViewGroup) helper.m3912b(R.id.banner_view));
        }
        int itemType = item.getItemType();
        if (itemType == 1) {
            showComicsList(helper, item, R.layout.item_comic_layout_vertical, 0);
        } else if (itemType == 2) {
            showComicsList(helper, item, R.layout.item_comic_layout, 3);
        } else {
            if (itemType != 3) {
                return;
            }
            showComicsList(helper, item, R.layout.item_comic_layout, 2);
        }
    }
}
