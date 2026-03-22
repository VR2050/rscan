package com.jbzd.media.movecartoons.p396ui.index.home;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.BottomTab;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeListFragment;
import com.jbzd.media.movecartoons.p396ui.mine.favority.FavoriteActivity;
import com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.welfare.SignInAndWelfareTasksPage;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000p\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 L2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001LB\u0007¢\u0006\u0004\bK\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bR\u001d\u0010\u000e\u001a\u00020\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u001d\u0010\u0013\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\u0012R\u001d\u0010\u0016\u001a\u00020\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u000b\u001a\u0004\b\u0015\u0010\rR#\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00180\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u000b\u001a\u0004\b\u001a\u0010\u001bR#\u0010 \u001a\b\u0012\u0004\u0012\u00020\u001d0\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u000b\u001a\u0004\b\u001f\u0010\u001bR\u001d\u0010#\u001a\u00020\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u000b\u001a\u0004\b\"\u0010\rR\u001f\u0010(\u001a\u0004\u0018\u00010$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u000b\u001a\u0004\b&\u0010'R\u001d\u0010-\u001a\u00020)8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b*\u0010\u000b\u001a\u0004\b+\u0010,R%\u00100\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010$0\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u000b\u001a\u0004\b/\u0010\u001bR#\u00104\u001a\b\u0012\u0004\u0012\u0002010\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b2\u0010\u000b\u001a\u0004\b3\u0010\u001bR\u001d\u00109\u001a\u0002058B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u000b\u001a\u0004\b7\u00108R\u001f\u0010=\u001a\u0004\u0018\u00010\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b:\u0010\u000b\u001a\u0004\b;\u0010<R\u001d\u0010B\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u000b\u001a\u0004\b@\u0010AR\u001d\u0010G\u001a\u00020C8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bD\u0010\u000b\u001a\u0004\bE\u0010FR\u001f\u0010J\u001a\u0004\u0018\u00010\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bH\u0010\u000b\u001a\u0004\bI\u0010<¨\u0006M"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeTabFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getLayout", "()I", "", "initViews", "()V", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_favorite$delegate", "Lkotlin/Lazy;", "getItv_favorite", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_favorite", "Lcom/noober/background/view/BLTextView;", "tv_search$delegate", "getTv_search", "()Lcom/noober/background/view/BLTextView;", "tv_search", "itv_vip_buy$delegate", "getItv_vip_buy", "itv_vip_buy", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "tabEntities$delegate", "getTabEntities", "()Ljava/util/List;", "tabEntities", "", "tabNames$delegate", "getTabNames", "tabNames", "itv_signin$delegate", "getItv_signin", "itv_signin", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "mTabBeanSecond$delegate", "getMTabBeanSecond", "mTabBeanSecond", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "mFragments$delegate", "getMFragments", "mFragments", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab$delegate", "getMBottomTab", "()Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab", "mInto$delegate", "getMInto", "()Ljava/lang/String;", "mInto", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "mPosition$delegate", "getMPosition", "mPosition", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeTabFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_BOTTOM_TAB = "bottom_tab";

    @NotNull
    public static final String KEY_POSITION = "position";

    @NotNull
    private static final String KEY_TAB = "tab_bean";

    /* renamed from: mBottomTab$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBottomTab = LazyKt__LazyJVMKt.lazy(new Function0<BottomTab>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$mBottomTab$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final BottomTab invoke() {
            Bundle arguments = HomeTabFragment.this.getArguments();
            BottomTab bottomTab = arguments == null ? null : (BottomTab) arguments.getParcelable("bottom_tab");
            return bottomTab == null ? BottomTab.HomeTab.INSTANCE : bottomTab;
        }
    });

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$mPosition$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeTabFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("position");
        }
    });

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = HomeTabFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: mInto$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInto = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$mInto$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeTabFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("into");
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List mFragments;
            FragmentManager childFragmentManager = HomeTabFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            mFragments = HomeTabFragment.this.getMFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) mFragments, 0, 4, null);
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends TagBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$tabEntities$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends TagBean> invoke() {
            return CollectionsKt__CollectionsJVMKt.listOf(new TagBean());
        }
    });

    /* renamed from: tabNames$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabNames = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$tabNames$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            List tabEntities;
            tabEntities = HomeTabFragment.this.getTabEntities();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntities, 10));
            Iterator it = tabEntities.iterator();
            while (it.hasNext()) {
                String str = ((TagBean) it.next()).name;
                if (str == null) {
                    str = "";
                }
                arrayList.add(str);
            }
            return arrayList;
        }
    });

    /* renamed from: mTabBeanSecond$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBeanSecond = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$mTabBeanSecond$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends MainMenusBean> invoke() {
            List<TagBean> tabEntities;
            MainMenusBean mTabBean;
            tabEntities = HomeTabFragment.this.getTabEntities();
            HomeTabFragment homeTabFragment = HomeTabFragment.this;
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntities, 10));
            for (TagBean tagBean : tabEntities) {
                mTabBean = homeTabFragment.getMTabBean();
                MainMenusBean mainMenusBean = (MainMenusBean) (mTabBean == null ? null : mTabBean.clone());
                if (mainMenusBean == null) {
                    mainMenusBean = homeTabFragment.getMTabBean();
                }
                arrayList.add(mainMenusBean);
            }
            return arrayList;
        }
    });

    /* renamed from: mFragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends HomeListFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$mFragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends HomeListFragment> invoke() {
            List mTabBeanSecond;
            MainMenusBean mTabBean;
            String mPosition;
            mTabBeanSecond = HomeTabFragment.this.getMTabBeanSecond();
            int size = mTabBeanSecond.size();
            HomeTabFragment homeTabFragment = HomeTabFragment.this;
            ArrayList arrayList = new ArrayList(size);
            for (int i2 = 0; i2 < size; i2++) {
                HomeListFragment.Companion companion = HomeListFragment.INSTANCE;
                mTabBean = homeTabFragment.getMTabBean();
                mPosition = homeTabFragment.getMPosition();
                arrayList.add(HomeListFragment.Companion.newInstance$default(companion, mTabBean, mPosition, false, null, 0, 24, null));
            }
            return arrayList;
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            View view = HomeTabFragment.this.getView();
            ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$tabLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = HomeTabFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: tv_search$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_search = LazyKt__LazyJVMKt.lazy(new Function0<BLTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$tv_search$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final BLTextView invoke() {
            View view = HomeTabFragment.this.getView();
            BLTextView bLTextView = view == null ? null : (BLTextView) view.findViewById(R.id.tv_search);
            Intrinsics.checkNotNull(bLTextView);
            return bLTextView;
        }
    });

    /* renamed from: itv_vip_buy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_vip_buy = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$itv_vip_buy$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = HomeTabFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_vip_buy);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$itv_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = HomeTabFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_signin$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_signin = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$itv_signin$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = HomeTabFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_signin);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\t\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J)\u0010\t\u001a\u00020\b2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\t\u0010\nR\u0016\u0010\u000b\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\r\u0010\fR\u0016\u0010\u000e\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u000e\u0010\f¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeTabFragment$Companion;", "", "", "position", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "bottomTab", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeTabFragment;", "newInstance", "(Ljava/lang/String;Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;Lcom/jbzd/media/movecartoons/ui/index/BottomTab;)Lcom/jbzd/media/movecartoons/ui/index/home/HomeTabFragment;", "KEY_BOTTOM_TAB", "Ljava/lang/String;", SearchHomeActivity.key_position, "KEY_TAB", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final HomeTabFragment newInstance(@Nullable String position, @Nullable MainMenusBean tabBean, @NotNull BottomTab bottomTab) {
            Intrinsics.checkNotNullParameter(bottomTab, "bottomTab");
            HomeTabFragment homeTabFragment = new HomeTabFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("position", position);
            bundle.putSerializable("tab_bean", tabBean);
            bundle.putParcelable("bottom_tab", bottomTab);
            Unit unit = Unit.INSTANCE;
            homeTabFragment.setArguments(bundle);
            return homeTabFragment;
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    private final BottomTab getMBottomTab() {
        return (BottomTab) this.mBottomTab.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<HomeListFragment> getMFragments() {
        return (List) this.mFragments.getValue();
    }

    private final String getMInto() {
        return (String) this.mInto.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<MainMenusBean> getMTabBeanSecond() {
        return (List) this.mTabBeanSecond.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<TagBean> getTabEntities() {
        return (List) this.tabEntities.getValue();
    }

    private final List<String> getTabNames() {
        return (List) this.tabNames.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final ImageTextView getItv_favorite() {
        return (ImageTextView) this.itv_favorite.getValue();
    }

    @NotNull
    public final ImageTextView getItv_signin() {
        return (ImageTextView) this.itv_signin.getValue();
    }

    @NotNull
    public final ImageTextView getItv_vip_buy() {
        return (ImageTextView) this.itv_vip_buy.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_home_tab;
    }

    @NotNull
    public final SlidingTabLayout getTabLayout() {
        return (SlidingTabLayout) this.tabLayout.getValue();
    }

    @NotNull
    public final BLTextView getTv_search() {
        return (BLTextView) this.tv_search.getValue();
    }

    @NotNull
    public final ViewPager getVp_content() {
        return (ViewPager) this.vp_content.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getTabEntities().size());
        vp_content.setAdapter(getAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$initViews$1$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
            }
        });
        SlidingTabLayout tabLayout = getTabLayout();
        ViewPager vp_content2 = getVp_content();
        Object[] array = getTabNames().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tabLayout.m4011e(vp_content2, (String[]) array);
        String str = getTabEntities().get(0).name;
        if (str == null || str.length() == 0) {
            getTabLayout().setVisibility(8);
        }
        getTv_search().setHint("搜索更多视频");
        C2354n.m2374A(getTv_search(), 0L, new Function1<BLTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$initViews$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(BLTextView bLTextView) {
                invoke2(bLTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull BLTextView it) {
                String mPosition;
                Intrinsics.checkNotNullParameter(it, "it");
                mPosition = HomeTabFragment.this.getMPosition();
                if (mPosition == null) {
                    return;
                }
                HomeTabFragment homeTabFragment = HomeTabFragment.this;
                SearchHomeActivity.Companion companion = SearchHomeActivity.Companion;
                Context requireContext = homeTabFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, mPosition);
            }
        }, 1);
        MyThemeFragment.fadeWhenTouch$default(this, getItv_vip_buy(), 0.0f, 1, null);
        C2354n.m2374A(getItv_vip_buy(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$initViews$4
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
                BuyActivity.Companion companion = BuyActivity.INSTANCE;
                Context requireContext = HomeTabFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        C2354n.m2374A(getItv_favorite(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$initViews$5
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
                String mPosition;
                Intrinsics.checkNotNullParameter(it, "it");
                mPosition = HomeTabFragment.this.getMPosition();
                if (mPosition == null) {
                    return;
                }
                HomeTabFragment homeTabFragment = HomeTabFragment.this;
                FavoriteActivity.Companion companion = FavoriteActivity.INSTANCE;
                Context requireContext = homeTabFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, mPosition);
            }
        }, 1);
        MyThemeFragment.fadeWhenTouch$default(this, getItv_signin(), 0.0f, 1, null);
        C2354n.m2374A(getItv_signin(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeTabFragment$initViews$6
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
                SignInAndWelfareTasksPage.Companion companion = SignInAndWelfareTasksPage.Companion;
                Context requireContext = HomeTabFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
    }
}
