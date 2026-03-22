package com.jbzd.media.movecartoons.p396ui.index.show;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
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
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u0000 \"2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001\"B\u0007¢\u0006\u0004\b!\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bR+\u0010\u0010\u001a\u0010\u0012\f\u0012\n \u000b*\u0004\u0018\u00010\n0\n0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR-\u0010\u0017\u001a\u0012\u0012\u0004\u0012\u00020\u00120\u0011j\b\u0012\u0004\u0012\u00020\u0012`\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\r\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001c\u001a\u00020\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\r\u001a\u0004\b\u001a\u0010\u001bR#\u0010 \u001a\b\u0012\u0004\u0012\u00020\u001d0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\r\u001a\u0004\b\u001f\u0010\u000f¨\u0006#"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/show/ShowFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getLayout", "()I", "", "initViews", "()V", "", "", "kotlin.jvm.PlatformType", "tabEntities$delegate", "Lkotlin/Lazy;", "getTabEntities", "()Ljava/util/List;", "tabEntities", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "Lkotlin/collections/ArrayList;", "tabEntityBeans$delegate", "getTabEntityBeans", "()Ljava/util/ArrayList;", "tabEntityBeans", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment;", "fragments$delegate", "getFragments", "fragments", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShowFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List fragments;
            FragmentManager childFragmentManager = ShowFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            fragments = ShowFragment.this.getFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragments, 0, 4, null);
        }
    });

    /* renamed from: tabEntityBeans$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntityBeans = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MainMenusBean>>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowFragment$tabEntityBeans$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MainMenusBean> invoke() {
            ArrayList<MainMenusBean> arrayList = new ArrayList<>();
            MyApp myApp = MyApp.f9891f;
            List<MainMenusBean> list = MyApp.m4185f().short_tabs;
            if (C2354n.m2414N0(list)) {
                arrayList.addAll(list);
            }
            return arrayList;
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends String>>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowFragment$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends String> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = ShowFragment.this.getTabEntityBeans();
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
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends ShortListFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowFragment$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends ShortListFragment> invoke() {
            ArrayList tabEntityBeans;
            tabEntityBeans = ShowFragment.this.getTabEntityBeans();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntityBeans, 10));
            Iterator it = tabEntityBeans.iterator();
            while (it.hasNext()) {
                arrayList.add(ShortListFragment.INSTANCE.newInstance((MainMenusBean) it.next()));
            }
            return arrayList;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/show/ShowFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/show/ShowFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/show/ShowFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ShowFragment newInstance() {
            return new ShowFragment();
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<ShortListFragment> getFragments() {
        return (List) this.fragments.getValue();
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
        return R.layout.frag_show;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        View view = getView();
        C2354n.m2374A(view == null ? null : view.findViewById(R$id.iv_search), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowFragment$initViews$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                SearchHomeActivity.Companion companion = SearchHomeActivity.Companion;
                Context requireContext = ShowFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, "short");
            }
        }, 1);
        View view2 = getView();
        ViewPager viewPager = (ViewPager) (view2 == null ? null : view2.findViewById(R$id.vp_content));
        viewPager.setOffscreenPageLimit(getTabEntities().size());
        viewPager.setAdapter(getAdapter());
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShowFragment$initViews$2$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                View view3 = ShowFragment.this.getView();
                ((SlidingTabLayout) (view3 == null ? null : view3.findViewById(R$id.tabLayout))).setCurrentTab(position);
            }
        });
        View view3 = getView();
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) (view3 == null ? null : view3.findViewById(R$id.tabLayout));
        View view4 = getView();
        View findViewById = view4 != null ? view4.findViewById(R$id.vp_content) : null;
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e((ViewPager) findViewById, (String[]) array);
    }
}
