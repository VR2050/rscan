package com.jbzd.media.movecartoons.p396ui.index.home;

import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.LinearLayout;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.BottomTab;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeTabFragment;
import com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000l\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010 \n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 E2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001EB\u0007¢\u0006\u0004\bD\u0010\tJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\f\u001a\u00020\u00072\b\u0010\u000b\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u000e\u0010\tR\u001f\u0010\u0014\u001a\u0004\u0018\u00010\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0011\u001a\u0004\b\u0017\u0010\u0018R-\u0010 \u001a\u0012\u0012\u0004\u0012\u00020\u001b0\u001aj\b\u0012\u0004\u0012\u00020\u001b`\u001c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u0011\u001a\u0004\b\u001e\u0010\u001fR\u001d\u0010%\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u0011\u001a\u0004\b#\u0010$R\u001d\u0010*\u001a\u00020&8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u0011\u001a\u0004\b(\u0010)R\u001d\u0010-\u001a\u00020&8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u0011\u001a\u0004\b,\u0010)R+\u00103\u001a\u0010\u0012\f\u0012\n /*\u0004\u0018\u00010\n0\n0.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0011\u001a\u0004\b1\u00102R%\u00107\u001a\n\u0012\u0006\u0012\u0004\u0018\u0001040.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b5\u0010\u0011\u001a\u0004\b6\u00102R\u001f\u0010;\u001a\u0004\u0018\u00010\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b8\u0010\u0011\u001a\u0004\b9\u0010:R\u001f\u0010>\u001a\u0004\u0018\u00010\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b<\u0010\u0011\u001a\u0004\b=\u0010:R\u001d\u0010C\u001a\u00020?8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b@\u0010\u0011\u001a\u0004\bA\u0010B¨\u0006F"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getDefaultTabPosition", "()I", "getLayout", "", "initViews", "()V", "", "tabId", "showTab", "(Ljava/lang/String;)V", "onResume", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab$delegate", "Lkotlin/Lazy;", "getMBottomTab", "()Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "mBottomTab", "Landroid/widget/LinearLayout;", "ll_top$delegate", "getLl_top", "()Landroid/widget/LinearLayout;", "ll_top", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "Lkotlin/collections/ArrayList;", "tabEntityBeans$delegate", "getTabEntityBeans", "()Ljava/util/ArrayList;", "tabEntityBeans", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "tabLayout_deep_dark$delegate", "getTabLayout_deep_dark", "tabLayout_deep_dark", "", "kotlin.jvm.PlatformType", "tabEntities$delegate", "getTabEntities", "()Ljava/util/List;", "tabEntities", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeTabFragment;", "fragments$delegate", "getFragments", "fragments", "mPosition$delegate", "getMPosition", "()Ljava/lang/String;", "mPosition", "mInto$delegate", "getMInto", "mInto", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_BOTTOM_TAB = "bottom_tab";

    @NotNull
    public static final String KEY_INTO = "into";

    @NotNull
    public static final String KEY_POSITION = "position";

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List fragments;
            FragmentManager childFragmentManager = HomeFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            fragments = HomeFragment.this.getFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragments, 0, 4, null);
        }
    });

    /* renamed from: mBottomTab$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mBottomTab = LazyKt__LazyJVMKt.lazy(new Function0<BottomTab>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$mBottomTab$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final BottomTab invoke() {
            Bundle arguments = HomeFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return (BottomTab) arguments.getParcelable("bottom_tab");
        }
    });

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$mPosition$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("position");
        }
    });

    /* renamed from: mInto$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInto = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$mInto$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("into");
        }
    });

    /* renamed from: tabEntityBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntityBeans = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$tabEntityBeans$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MainMenusBean> invoke() {
            BottomTab mBottomTab;
            List<MainMenusBean> list;
            ArrayList<MainMenusBean> arrayList = new ArrayList<>();
            mBottomTab = HomeFragment.this.getMBottomTab();
            if (Intrinsics.areEqual(mBottomTab, BottomTab.HomeTab1.INSTANCE)) {
                MyApp myApp = MyApp.f9891f;
                list = MyApp.m4185f().cartoon_video_nav;
            } else if (Intrinsics.areEqual(mBottomTab, BottomTab.Tab1.INSTANCE)) {
                MyApp myApp2 = MyApp.f9891f;
                list = MyApp.m4185f().normal_video_nav;
            } else if (Intrinsics.areEqual(mBottomTab, BottomTab.HomeTab3.INSTANCE)) {
                MyApp myApp3 = MyApp.f9891f;
                list = MyApp.m4185f().short_nav;
            } else {
                MyApp myApp4 = MyApp.f9891f;
                list = MyApp.m4185f().dark_video_nav;
            }
            if (C2354n.m2414N0(list)) {
                arrayList.addAll(list);
            }
            return arrayList;
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = HomeFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            Iterator it = tabEntityBeans.iterator();
            while (it.hasNext()) {
                arrayList.add(((MainMenusBean) it.next()).name);
            }
            return arrayList;
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends HomeTabFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends HomeTabFragment> invoke() {
            ArrayList<MainMenusBean> tabEntityBeans;
            String mInto;
            String mPosition;
            BottomTab mBottomTab;
            HomeTabFragment newInstance;
            tabEntityBeans = HomeFragment.this.getTabEntityBeans();
            HomeFragment homeFragment = HomeFragment.this;
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            for (MainMenusBean mainMenusBean : tabEntityBeans) {
                mInto = homeFragment.getMInto();
                if (mInto == null) {
                    newInstance = null;
                } else {
                    HomeTabFragment.Companion companion = HomeTabFragment.INSTANCE;
                    mPosition = homeFragment.getMPosition();
                    mBottomTab = homeFragment.getMBottomTab();
                    Intrinsics.checkNotNull(mBottomTab);
                    newInstance = companion.newInstance(mPosition, mainMenusBean, mBottomTab);
                }
                arrayList.add(newInstance);
            }
            return arrayList;
        }
    });

    /* renamed from: ll_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_top = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$ll_top$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = HomeFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_top);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            View view = HomeFragment.this.getView();
            ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$tabLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = HomeFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: tabLayout_deep_dark$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout_deep_dark = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$tabLayout_deep_dark$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = HomeFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout_deep_dark);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ%\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0002¢\u0006\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\u000bR\u0016\u0010\f\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\f\u0010\u000bR\u0016\u0010\r\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\r\u0010\u000b¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeFragment$Companion;", "", "", "position", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "bottomTab", "into", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeFragment;", "newInstance", "(Ljava/lang/String;Lcom/jbzd/media/movecartoons/ui/index/BottomTab;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/home/HomeFragment;", "KEY_BOTTOM_TAB", "Ljava/lang/String;", "KEY_INTO", SearchHomeActivity.key_position, "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final HomeFragment newInstance(@NotNull String position, @NotNull BottomTab bottomTab, @NotNull String into) {
            Intrinsics.checkNotNullParameter(position, "position");
            Intrinsics.checkNotNullParameter(bottomTab, "bottomTab");
            Intrinsics.checkNotNullParameter(into, "into");
            HomeFragment homeFragment = new HomeFragment();
            Bundle bundle = new Bundle();
            bundle.putParcelable("bottom_tab", bottomTab);
            Unit unit = Unit.INSTANCE;
            bundle.putString("position", position);
            bundle.putString("into", into);
            homeFragment.setArguments(bundle);
            return homeFragment;
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    private final int getDefaultTabPosition() {
        Iterator<MainMenusBean> it = getTabEntityBeans().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (it.next().isDefaultTab()) {
                return i2;
            }
            i2 = i3;
        }
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<HomeTabFragment> getFragments() {
        return (List) this.fragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final BottomTab getMBottomTab() {
        return (BottomTab) this.mBottomTab.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMInto() {
        return (String) this.mInto.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    private final List<String> getTabEntities() {
        return (List) this.tabEntities.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<MainMenusBean> getTabEntityBeans() {
        return (ArrayList) this.tabEntityBeans.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_home;
    }

    @NotNull
    public final LinearLayout getLl_top() {
        return (LinearLayout) this.ll_top.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTabLayout() {
        return (SlidingTabLayout) this.tabLayout.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTabLayout_deep_dark() {
        return (SlidingTabLayout) this.tabLayout_deep_dark.getValue();
    }

    @NotNull
    public final ViewPager getVp_content() {
        return (ViewPager) this.vp_content.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        int statusBarHeight = ImmersionBar.getStatusBarHeight(this);
        String mInto = getMInto();
        if (mInto == null || mInto.length() == 0) {
            getLl_top().setPadding(0, statusBarHeight + 30, 0, 0);
        }
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getTabEntities().size());
        vp_content.setAdapter(getAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeFragment$initViews$2$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                Intrinsics.checkNotNullParameter("home_top_tab", "act");
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                linkedHashMap.put("act", "home_top_tab");
                C0917a.m221e(C0917a.f372a, "system/doLogs", Object.class, linkedHashMap, C0846g.f248c, null, false, false, null, false, 432);
            }
        });
        getTabLayout().setVisibility(0);
        if (Intrinsics.areEqual(getMPosition(), "dark")) {
            getTabLayout().setVisibility(8);
            getTabLayout_deep_dark().setVisibility(0);
            SlidingTabLayout tabLayout_deep_dark = getTabLayout_deep_dark();
            ViewPager vp_content2 = getVp_content();
            Object[] array = getTabEntities().toArray(new String[0]);
            Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
            tabLayout_deep_dark.m4011e(vp_content2, (String[]) array);
        } else {
            getTabLayout_deep_dark().setVisibility(8);
            getTabLayout().setVisibility(0);
            SlidingTabLayout tabLayout = getTabLayout();
            if (!getTabEntities().isEmpty()) {
                ViewPager vp_content3 = getVp_content();
                Object[] array2 = getTabEntities().toArray(new String[0]);
                Objects.requireNonNull(array2, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
                tabLayout.m4011e(vp_content3, (String[]) array2);
            } else {
                C2354n.m2449Z("暂无数据，请配置");
            }
        }
        if (!getTabEntities().isEmpty()) {
            getVp_content().setCurrentItem(getDefaultTabPosition());
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
    }

    public final void showTab(@Nullable String tabId) {
        Iterator<MainMenusBean> it = getTabEntityBeans().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10030id, tabId)) {
                getVp_content().setCurrentItem(i2);
                return;
            }
            i2 = i3;
        }
    }
}
