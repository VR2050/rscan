package com.jbzd.media.movecartoons.p396ui.index.home;

import android.content.Context;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.view.ContextThemeWrapper;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.angcyo.tablayout.DslTabLayout;
import com.angcyo.tablayout.DslTabLayoutConfig;
import com.angcyo.tablayout.delegate.ViewPager1Delegate;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.BottomTab;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeComicNovelFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeFragment;
import com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.welfare.SignInAndWelfareTasksPage;
import com.jbzd.media.movecartoons.view.CommonFragmentAdapter;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseFragment;
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
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0082\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010!\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 I2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001IB\u0007¢\u0006\u0004\bH\u0010\u000eJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\t\u001a\u00020\b2\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u000b\u0010\u0005J\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000f\u0010\u000eR\u001d\u0010\u0015\u001a\u00020\u00108F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R\u001d\u0010\u001a\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0012\u001a\u0004\b\u0018\u0010\u0019R\u001c\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00060\u001b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001c\u0010\u001dR\u001d\u0010\"\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0012\u001a\u0004\b \u0010!R+\u0010'\u001a\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00010#8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0012\u001a\u0004\b%\u0010&R+\u0010+\u001a\u0010\u0012\f\u0012\n (*\u0004\u0018\u00010\u00060\u00060#8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0012\u001a\u0004\b*\u0010&R\u001d\u00100\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0012\u001a\u0004\b.\u0010/R&\u00104\u001a\u0012\u0012\u0004\u0012\u00020201j\b\u0012\u0004\u0012\u000202`38\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b4\u00105R\u001d\u0010:\u001a\u0002068F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u0012\u001a\u0004\b8\u00109R\u001d\u0010?\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b<\u0010\u0012\u001a\u0004\b=\u0010>R\u001d\u0010D\u001a\u00020@8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bA\u0010\u0012\u001a\u0004\bB\u0010CR\u001d\u0010G\u001a\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u0012\u001a\u0004\bF\u0010>¨\u0006J"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeBCYFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getDefaultTabPosition", "()I", "", "content", "Landroid/view/View;", "createTab", "(Ljava/lang/String;)Landroid/view/View;", "getLayout", "", "initViews", "()V", "onResume", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "Lkotlin/Lazy;", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "Landroid/widget/TextView;", "iv_home_new_search$delegate", "getIv_home_new_search", "()Landroid/widget/TextView;", "iv_home_new_search", "", "titleList", "Ljava/util/List;", "Landroid/widget/LinearLayout;", "ll_top$delegate", "getLl_top", "()Landroid/widget/LinearLayout;", "ll_top", "", "fragmentList$delegate", "getFragmentList", "()Ljava/util/List;", "fragmentList", "kotlin.jvm.PlatformType", "tabEntities$delegate", "getTabEntities", "tabEntities", "Lcom/angcyo/tablayout/DslTabLayout;", "tabLayout_bcy$delegate", "getTabLayout_bcy", "()Lcom/angcyo/tablayout/DslTabLayout;", "tabLayout_bcy", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "Lkotlin/collections/ArrayList;", "tabEntityBeans", "Ljava/util/ArrayList;", "Landroidx/viewpager/widget/ViewPager;", "vp_content_bcy$delegate", "getVp_content_bcy", "()Landroidx/viewpager/widget/ViewPager;", "vp_content_bcy", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "iv_home_new_vip$delegate", "getIv_home_new_vip", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "iv_home_new_vip", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "iv_home_new_sign$delegate", "getIv_home_new_sign", "iv_home_new_sign", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeBCYFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter;

    /* renamed from: fragmentList$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragmentList;

    /* renamed from: iv_home_new_search$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_home_new_search;

    /* renamed from: iv_home_new_sign$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_home_new_sign;

    /* renamed from: iv_home_new_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_home_new_vip;

    /* renamed from: ll_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_top;

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities;

    @NotNull
    private final ArrayList<MainMenusBean> tabEntityBeans;

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout;

    /* renamed from: tabLayout_bcy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout_bcy;

    @NotNull
    private final List<String> titleList;

    /* renamed from: vp_content_bcy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content_bcy;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeBCYFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeBCYFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/home/HomeBCYFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final HomeBCYFragment newInstance() {
            return new HomeBCYFragment();
        }
    }

    public HomeBCYFragment() {
        ArrayList arrayList = new ArrayList();
        this.titleList = arrayList;
        this.adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$adapter$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPagerAdapter invoke() {
                List fragmentList;
                FragmentManager childFragmentManager = HomeBCYFragment.this.getChildFragmentManager();
                Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
                fragmentList = HomeBCYFragment.this.getFragmentList();
                return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragmentList, 0, 4, null);
            }
        });
        this.tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$tabEntities$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final List<? extends String> invoke() {
                ArrayList arrayList2;
                arrayList2 = HomeBCYFragment.this.tabEntityBeans;
                ArrayList arrayList3 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList2, 10));
                Iterator it = arrayList2.iterator();
                while (it.hasNext()) {
                    arrayList3.add(((MainMenusBean) it.next()).name);
                }
                return arrayList3;
            }
        });
        ArrayList<MainMenusBean> arrayList2 = new ArrayList<>();
        MainMenusBean mainMenusBean = new MainMenusBean();
        mainMenusBean.code = "comics";
        mainMenusBean.name = "漫画";
        Intrinsics.checkNotNullExpressionValue("漫画", "name");
        arrayList.add("漫画");
        Unit unit = Unit.INSTANCE;
        arrayList2.add(mainMenusBean);
        MainMenusBean mainMenusBean2 = new MainMenusBean();
        mainMenusBean2.code = "cartoon";
        mainMenusBean2.name = "动漫";
        Intrinsics.checkNotNullExpressionValue("动漫", "name");
        arrayList.add("动漫");
        arrayList2.add(mainMenusBean2);
        MainMenusBean mainMenusBean3 = new MainMenusBean();
        mainMenusBean3.code = "novel";
        mainMenusBean3.name = "小说";
        Intrinsics.checkNotNullExpressionValue("小说", "name");
        arrayList.add("小说");
        arrayList2.add(mainMenusBean3);
        this.tabEntityBeans = arrayList2;
        this.fragmentList = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends MyThemeFragment<Object>>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$fragmentList$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final List<? extends MyThemeFragment<Object>> invoke() {
                ArrayList<MainMenusBean> arrayList3;
                BaseFragment newInstance;
                arrayList3 = HomeBCYFragment.this.tabEntityBeans;
                ArrayList arrayList4 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList3, 10));
                for (MainMenusBean mainMenusBean4 : arrayList3) {
                    if (mainMenusBean4.code.equals("comics")) {
                        HomeComicNovelFragment.Companion companion = HomeComicNovelFragment.INSTANCE;
                        BottomTab.HomeTab homeTab = BottomTab.HomeTab.INSTANCE;
                        String str = mainMenusBean4.code;
                        Intrinsics.checkNotNullExpressionValue(str, "it.code");
                        newInstance = companion.newInstance(homeTab, str);
                    } else if (mainMenusBean4.code.equals("cartoon")) {
                        HomeFragment.Companion companion2 = HomeFragment.INSTANCE;
                        BottomTab.HomeTab1 homeTab1 = BottomTab.HomeTab1.INSTANCE;
                        String str2 = mainMenusBean4.code;
                        Intrinsics.checkNotNullExpressionValue(str2, "it.code");
                        newInstance = companion2.newInstance("cartoon", homeTab1, str2);
                    } else {
                        HomeComicNovelFragment.Companion companion3 = HomeComicNovelFragment.INSTANCE;
                        BottomTab.HomeTab2 homeTab2 = BottomTab.HomeTab2.INSTANCE;
                        String str3 = mainMenusBean4.code;
                        Intrinsics.checkNotNullExpressionValue(str3, "it.code");
                        newInstance = companion3.newInstance(homeTab2, str3);
                    }
                    arrayList4.add(newInstance);
                }
                return arrayList4;
            }
        });
        this.ll_top = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$ll_top$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = HomeBCYFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_top);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.iv_home_new_search = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$iv_home_new_search$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = HomeBCYFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.iv_home_new_search);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$tabLayout$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final SlidingTabLayout invoke() {
                View view = HomeBCYFragment.this.getView();
                SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                Intrinsics.checkNotNull(slidingTabLayout);
                return slidingTabLayout;
            }
        });
        this.iv_home_new_vip = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$iv_home_new_vip$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageTextView invoke() {
                View view = HomeBCYFragment.this.getView();
                ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.iv_home_new_vip);
                Intrinsics.checkNotNull(imageTextView);
                return imageTextView;
            }
        });
        this.iv_home_new_sign = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$iv_home_new_sign$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageTextView invoke() {
                View view = HomeBCYFragment.this.getView();
                ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.iv_home_new_sign);
                Intrinsics.checkNotNull(imageTextView);
                return imageTextView;
            }
        });
        this.tabLayout_bcy = LazyKt__LazyJVMKt.lazy(new Function0<DslTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$tabLayout_bcy$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final DslTabLayout invoke() {
                View view = HomeBCYFragment.this.getView();
                DslTabLayout dslTabLayout = view == null ? null : (DslTabLayout) view.findViewById(R.id.tabLayout_bcy);
                Intrinsics.checkNotNull(dslTabLayout);
                return dslTabLayout;
            }
        });
        this.vp_content_bcy = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$vp_content_bcy$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewPager invoke() {
                View view = HomeBCYFragment.this.getView();
                ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content_bcy);
                Intrinsics.checkNotNull(viewPager);
                return viewPager;
            }
        });
    }

    private final View createTab(String content) {
        AppCompatTextView appCompatTextView = new AppCompatTextView(new ContextThemeWrapper(requireActivity(), R.style.homePageTabStyle1));
        appCompatTextView.setText(content);
        appCompatTextView.setGravity(17);
        return appCompatTextView;
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    private final int getDefaultTabPosition() {
        Iterator<MainMenusBean> it = this.tabEntityBeans.iterator();
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
    public final List<MyThemeFragment<Object>> getFragmentList() {
        return (List) this.fragmentList.getValue();
    }

    private final List<String> getTabEntities() {
        return (List) this.tabEntities.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final TextView getIv_home_new_search() {
        return (TextView) this.iv_home_new_search.getValue();
    }

    @NotNull
    public final ImageTextView getIv_home_new_sign() {
        return (ImageTextView) this.iv_home_new_sign.getValue();
    }

    @NotNull
    public final ImageTextView getIv_home_new_vip() {
        return (ImageTextView) this.iv_home_new_vip.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.fragment_home_new;
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
    public final DslTabLayout getTabLayout_bcy() {
        return (DslTabLayout) this.tabLayout_bcy.getValue();
    }

    @NotNull
    public final ViewPager getVp_content_bcy() {
        return (ViewPager) this.vp_content_bcy.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        getLl_top().setPadding(0, ImmersionBar.getStatusBarHeight(this), 0, 0);
        C2354n.m2374A(getIv_home_new_search(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$initViews$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                int currentTab = HomeBCYFragment.this.getTabLayout().getCurrentTab();
                if (currentTab == 0) {
                    SearchHomeActivity.Companion companion = SearchHomeActivity.Companion;
                    Context requireContext = HomeBCYFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    companion.start(requireContext, "comics");
                    return;
                }
                if (currentTab == 1) {
                    SearchHomeActivity.Companion companion2 = SearchHomeActivity.Companion;
                    Context requireContext2 = HomeBCYFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion2.start(requireContext2, "cartoon");
                    return;
                }
                if (currentTab != 2) {
                    return;
                }
                SearchHomeActivity.Companion companion3 = SearchHomeActivity.Companion;
                Context requireContext3 = HomeBCYFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext3, "requireContext()");
                companion3.start(requireContext3, "novel");
            }
        }, 1);
        C2354n.m2374A(getIv_home_new_vip(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$initViews$3
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
                Context requireContext = HomeBCYFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        C2354n.m2374A(getIv_home_new_sign(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$initViews$4
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
                SignInAndWelfareTasksPage.Companion companion = SignInAndWelfareTasksPage.INSTANCE;
                Context requireContext = HomeBCYFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        getTabLayout_bcy().removeAllViews();
        Iterator<String> it = this.titleList.iterator();
        while (it.hasNext()) {
            getTabLayout_bcy().addView(createTab(it.next()));
        }
        DslTabLayout tabLayout_bcy = getTabLayout_bcy();
        HomeBCYFragment$initViews$5 config = new Function1<DslTabLayoutConfig, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$initViews$5
            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull DslTabLayoutConfig configTabLayoutConfig) {
                Intrinsics.checkNotNullParameter(configTabLayoutConfig, "$this$configTabLayoutConfig");
                configTabLayoutConfig.f1670t = 43.0f;
                configTabLayoutConfig.f1671u = 52.0f;
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(DslTabLayoutConfig dslTabLayoutConfig) {
                invoke2(dslTabLayoutConfig);
                return Unit.INSTANCE;
            }
        };
        Objects.requireNonNull(tabLayout_bcy);
        Intrinsics.checkNotNullParameter(config, "config");
        if (tabLayout_bcy.f8767m == null) {
            tabLayout_bcy.setTabLayoutConfig(new DslTabLayoutConfig(tabLayout_bcy));
        }
        DslTabLayoutConfig dslTabLayoutConfig = tabLayout_bcy.f8767m;
        if (dslTabLayoutConfig != null) {
            config.invoke((HomeBCYFragment$initViews$5) dslTabLayoutConfig);
        }
        tabLayout_bcy.getDslSelector().m665h();
        ViewPager vp_content_bcy = getVp_content_bcy();
        FragmentManager childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
        vp_content_bcy.setAdapter(new CommonFragmentAdapter(childFragmentManager, getFragmentList(), this.titleList));
        ViewPager viewPager = getVp_content_bcy();
        DslTabLayout tabLayout_bcy2 = getTabLayout_bcy();
        Intrinsics.checkNotNullParameter(viewPager, "viewPager");
        new ViewPager1Delegate(viewPager, tabLayout_bcy2, null);
        getVp_content_bcy().setOffscreenPageLimit(this.titleList.size());
        getVp_content_bcy().addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeBCYFragment$initViews$6
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
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
    }
}
