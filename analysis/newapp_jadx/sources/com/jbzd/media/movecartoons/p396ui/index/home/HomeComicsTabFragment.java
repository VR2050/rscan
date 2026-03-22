package com.jbzd.media.movecartoons.p396ui.index.home;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.BottomTab;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeListComicsFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeListNovelFragment;
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
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0013\u0018\u0000 J2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001JB\u0007¢\u0006\u0004\bI\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bR\u001f\u0010\u000e\u001a\u0004\u0018\u00010\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u001d\u0010\u0013\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\u0012R\u001d\u0010\u0018\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u000b\u001a\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00198F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u000b\u001a\u0004\b\u001b\u0010\u001cR\u001d\u0010\"\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u000b\u001a\u0004\b \u0010!R\u001d\u0010'\u001a\u00020#8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u000b\u001a\u0004\b%\u0010&R#\u0010-\u001a\b\u0012\u0004\u0012\u00020)0(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b*\u0010\u000b\u001a\u0004\b+\u0010,R+\u00102\u001a\u0010\u0012\f\u0012\n\u0012\u0006\b\u0001\u0012\u00020/0.0(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u000b\u001a\u0004\b1\u0010,R\u001d\u00107\u001a\u0002038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u000b\u001a\u0004\b5\u00106R\u001f\u0010<\u001a\u0004\u0018\u0001088B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b9\u0010\u000b\u001a\u0004\b:\u0010;R%\u0010?\u001a\n\u0012\u0006\u0012\u0004\u0018\u0001080(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b=\u0010\u000b\u001a\u0004\b>\u0010,R\u001d\u0010B\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b@\u0010\u000b\u001a\u0004\bA\u0010!R\u001d\u0010E\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010\u000b\u001a\u0004\bD\u0010!R#\u0010H\u001a\b\u0012\u0004\u0012\u00020\t0(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bF\u0010\u000b\u001a\u0004\bG\u0010,¨\u0006K"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeComicsTabFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getLayout", "()I", "", "initViews", "()V", "", "mInto$delegate", "Lkotlin/Lazy;", "getMInto", "()Ljava/lang/String;", "mInto", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "Lcom/noober/background/view/BLTextView;", "tv_search$delegate", "getTv_search", "()Lcom/noober/background/view/BLTextView;", "tv_search", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_favorite$delegate", "getItv_favorite", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_favorite", "Landroidx/constraintlayout/widget/ConstraintLayout;", "ll_search_vip_sign$delegate", "getLl_search_vip_sign", "()Landroidx/constraintlayout/widget/ConstraintLayout;", "ll_search_vip_sign", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "tabEntities$delegate", "getTabEntities", "()Ljava/util/List;", "tabEntities", "Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lb/b/a/a/a/j/a;", "mFragments$delegate", "getMFragments", "mFragments", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "mTabBeanSecond$delegate", "getMTabBeanSecond", "mTabBeanSecond", "itv_signin$delegate", "getItv_signin", "itv_signin", "itv_vip_buy$delegate", "getItv_vip_buy", "itv_vip_buy", "tabNames$delegate", "getTabNames", "tabNames", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeComicsTabFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_BOTTOM_TAB = "bottom_tab";

    @NotNull
    private static final String KEY_TAB = "tab_bean";

    /* renamed from: mInto$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mInto = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$mInto$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = HomeComicsTabFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("into");
        }
    });

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = HomeComicsTabFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List mFragments;
            FragmentManager childFragmentManager = HomeComicsTabFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            mFragments = HomeComicsTabFragment.this.getMFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) mFragments, 0, 4, null);
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends TagBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$tabEntities$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends TagBean> invoke() {
            return CollectionsKt__CollectionsJVMKt.listOf(new TagBean());
        }
    });

    /* renamed from: tabNames$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabNames = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$tabNames$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            List tabEntities;
            tabEntities = HomeComicsTabFragment.this.getTabEntities();
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
    private final Lazy mTabBeanSecond = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$mTabBeanSecond$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends MainMenusBean> invoke() {
            List<TagBean> tabEntities;
            MainMenusBean mTabBean;
            tabEntities = HomeComicsTabFragment.this.getTabEntities();
            HomeComicsTabFragment homeComicsTabFragment = HomeComicsTabFragment.this;
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntities, 10));
            for (TagBean tagBean : tabEntities) {
                mTabBean = homeComicsTabFragment.getMTabBean();
                MainMenusBean mainMenusBean = (MainMenusBean) (mTabBean == null ? null : mTabBean.clone());
                if (mainMenusBean == null) {
                    mainMenusBean = homeComicsTabFragment.getMTabBean();
                }
                arrayList.add(mainMenusBean);
            }
            return arrayList;
        }
    });

    /* renamed from: mFragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends BaseMutiListFragment<? extends InterfaceC1296a>>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$mFragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends BaseMutiListFragment<? extends InterfaceC1296a>> invoke() {
            String mInto;
            List mTabBeanSecond;
            ArrayList arrayList;
            MainMenusBean mTabBean;
            String mInto2;
            List mTabBeanSecond2;
            MainMenusBean mTabBean2;
            String mInto3;
            mInto = HomeComicsTabFragment.this.getMInto();
            if (StringsKt__StringsJVMKt.equals$default(mInto, "comics", false, 2, null)) {
                mTabBeanSecond2 = HomeComicsTabFragment.this.getMTabBeanSecond();
                int size = mTabBeanSecond2.size();
                HomeComicsTabFragment homeComicsTabFragment = HomeComicsTabFragment.this;
                arrayList = new ArrayList(size);
                for (int i2 = 0; i2 < size; i2++) {
                    HomeListComicsFragment.Companion companion = HomeListComicsFragment.Companion;
                    mTabBean2 = homeComicsTabFragment.getMTabBean();
                    mInto3 = homeComicsTabFragment.getMInto();
                    arrayList.add(companion.newInstance(mTabBean2, false, mInto3));
                }
            } else {
                mTabBeanSecond = HomeComicsTabFragment.this.getMTabBeanSecond();
                int size2 = mTabBeanSecond.size();
                HomeComicsTabFragment homeComicsTabFragment2 = HomeComicsTabFragment.this;
                arrayList = new ArrayList(size2);
                for (int i3 = 0; i3 < size2; i3++) {
                    HomeListNovelFragment.Companion companion2 = HomeListNovelFragment.Companion;
                    mTabBean = homeComicsTabFragment2.getMTabBean();
                    mInto2 = homeComicsTabFragment2.getMInto();
                    arrayList.add(companion2.newInstance(mTabBean, false, mInto2));
                }
            }
            return arrayList;
        }
    });

    /* renamed from: ll_search_vip_sign$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_search_vip_sign = LazyKt__LazyJVMKt.lazy(new Function0<ConstraintLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$ll_search_vip_sign$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ConstraintLayout invoke() {
            View view = HomeComicsTabFragment.this.getView();
            ConstraintLayout constraintLayout = view == null ? null : (ConstraintLayout) view.findViewById(R.id.ll_search_vip_sign);
            Intrinsics.checkNotNull(constraintLayout);
            return constraintLayout;
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            View view = HomeComicsTabFragment.this.getView();
            ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$tabLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = HomeComicsTabFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: tv_search$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_search = LazyKt__LazyJVMKt.lazy(new Function0<BLTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$tv_search$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final BLTextView invoke() {
            View view = HomeComicsTabFragment.this.getView();
            BLTextView bLTextView = view == null ? null : (BLTextView) view.findViewById(R.id.tv_search);
            Intrinsics.checkNotNull(bLTextView);
            return bLTextView;
        }
    });

    /* renamed from: itv_vip_buy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_vip_buy = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$itv_vip_buy$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = HomeComicsTabFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_vip_buy);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$itv_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = HomeComicsTabFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_signin$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_signin = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$itv_signin$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = HomeComicsTabFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_signin);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ'\u0010\t\u001a\u00020\b2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\t\u0010\nR\u0016\u0010\u000b\u001a\u00020\u00068\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\u00068\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\r\u0010\f¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeComicsTabFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "Lcom/jbzd/media/movecartoons/ui/index/BottomTab;", "bottomTab", "", "into", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeComicsTabFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;Lcom/jbzd/media/movecartoons/ui/index/BottomTab;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/home/HomeComicsTabFragment;", "KEY_BOTTOM_TAB", "Ljava/lang/String;", "KEY_TAB", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final HomeComicsTabFragment newInstance(@Nullable MainMenusBean tabBean, @NotNull BottomTab bottomTab, @NotNull String into) {
            Intrinsics.checkNotNullParameter(bottomTab, "bottomTab");
            Intrinsics.checkNotNullParameter(into, "into");
            HomeComicsTabFragment homeComicsTabFragment = new HomeComicsTabFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("tab_bean", tabBean);
            bundle.putParcelable("bottom_tab", bottomTab);
            Unit unit = Unit.INSTANCE;
            bundle.putString("into", into);
            homeComicsTabFragment.setArguments(bundle);
            return homeComicsTabFragment;
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<BaseMutiListFragment<? extends InterfaceC1296a>> getMFragments() {
        return (List) this.mFragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMInto() {
        return (String) this.mInto.getValue();
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
    public final ConstraintLayout getLl_search_vip_sign() {
        return (ConstraintLayout) this.ll_search_vip_sign.getValue();
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
        getLl_search_vip_sign().setVisibility(0);
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getTabEntities().size());
        vp_content.setAdapter(getAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$initViews$1$1
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
        C2354n.m2374A(getTv_search(), 0L, new Function1<BLTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$initViews$3
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
                String mInto;
                Intrinsics.checkNotNullParameter(it, "it");
                mInto = HomeComicsTabFragment.this.getMInto();
                if (StringsKt__StringsJVMKt.equals$default(mInto, "novel", false, 2, null)) {
                    SearchHomeActivity.Companion companion = SearchHomeActivity.Companion;
                    Context requireContext = HomeComicsTabFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    companion.start(requireContext, "novel");
                    return;
                }
                SearchHomeActivity.Companion companion2 = SearchHomeActivity.Companion;
                Context requireContext2 = HomeComicsTabFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                companion2.start(requireContext2, "comics");
            }
        }, 1);
        MyThemeFragment.fadeWhenTouch$default(this, getItv_vip_buy(), 0.0f, 1, null);
        C2354n.m2374A(getItv_vip_buy(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$initViews$4
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
                Context requireContext = HomeComicsTabFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        MyThemeFragment.fadeWhenTouch$default(this, getItv_favorite(), 0.0f, 1, null);
        C2354n.m2374A(getItv_favorite(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$initViews$5
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
                String mInto;
                Intrinsics.checkNotNullParameter(it, "it");
                mInto = HomeComicsTabFragment.this.getMInto();
                if (mInto == null) {
                    return;
                }
                HomeComicsTabFragment homeComicsTabFragment = HomeComicsTabFragment.this;
                FavoriteActivity.Companion companion = FavoriteActivity.INSTANCE;
                Context requireContext = homeComicsTabFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, mInto);
            }
        }, 1);
        C2354n.m2374A(getItv_signin(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeComicsTabFragment$initViews$6
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
                Context requireContext = HomeComicsTabFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
    }
}
