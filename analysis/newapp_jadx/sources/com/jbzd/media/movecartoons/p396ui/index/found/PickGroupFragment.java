package com.jbzd.media.movecartoons.p396ui.index.found;

import android.view.View;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Deprecated;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Deprecated(message = "没有该页面了")
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000P\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0007\u0018\u0000 '2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001'B\u0007¢\u0006\u0004\b&\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bR\u001d\u0010\u000e\u001a\u00020\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR#\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00100\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u000b\u001a\u0004\b\u0012\u0010\u0013R-\u0010\u001b\u001a\u0012\u0012\u0004\u0012\u00020\u00160\u0015j\b\u0012\u0004\u0012\u00020\u0016`\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u000b\u001a\u0004\b\u0019\u0010\u001aR\u001d\u0010 \u001a\u00020\u001c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u000b\u001a\u0004\b\u001e\u0010\u001fR\u001d\u0010%\u001a\u00020!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u000b\u001a\u0004\b#\u0010$¨\u0006("}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/PickGroupFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getLayout", "()I", "", "initViews", "()V", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "Lkotlin/Lazy;", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "", "Lcom/jbzd/media/movecartoons/ui/index/found/GroupListFragment;", "fragments$delegate", "getFragments", "()Ljava/util/List;", "fragments", "Ljava/util/ArrayList;", "", "Lkotlin/collections/ArrayList;", "tabEntities$delegate", "getTabEntities", "()Ljava/util/ArrayList;", "tabEntities", "Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout$delegate", "getTabLayout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tabLayout", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PickGroupFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String type_hot = "最热";

    @NotNull
    public static final String type_new = "最新";

    @NotNull
    public static final String type_recommend = "推荐";

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.found.PickGroupFragment$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            List fragments;
            FragmentManager childFragmentManager = PickGroupFragment.this.getChildFragmentManager();
            Intrinsics.checkNotNullExpressionValue(childFragmentManager, "childFragmentManager");
            fragments = PickGroupFragment.this.getFragments();
            return new ViewPagerAdapter(childFragmentManager, (ArrayList) fragments, 0, 4, null);
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.PickGroupFragment$tabEntities$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<String> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf(PickGroupFragment.type_recommend, PickGroupFragment.type_new, PickGroupFragment.type_hot);
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<List<? extends GroupListFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.PickGroupFragment$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final List<? extends GroupListFragment> invoke() {
            ArrayList tabEntities;
            tabEntities = PickGroupFragment.this.getTabEntities();
            ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(tabEntities, 10));
            Iterator it = tabEntities.iterator();
            while (it.hasNext()) {
                arrayList.add(GroupListFragment.INSTANCE.newInstance((String) it.next()));
            }
            return arrayList;
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.found.PickGroupFragment$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            View view = PickGroupFragment.this.getView();
            ViewPager viewPager = view == null ? null : (ViewPager) view.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tabLayout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabLayout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.found.PickGroupFragment$tabLayout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            View view = PickGroupFragment.this.getView();
            SlidingTabLayout slidingTabLayout = view == null ? null : (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\n\u0010\u000bJ\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004R\u0016\u0010\u0006\u001a\u00020\u00058\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0006\u0010\u0007R\u0016\u0010\b\u001a\u00020\u00058\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\b\u0010\u0007R\u0016\u0010\t\u001a\u00020\u00058\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\t\u0010\u0007¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/PickGroupFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/found/PickGroupFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/found/PickGroupFragment;", "", "type_hot", "Ljava/lang/String;", "type_new", "type_recommend", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PickGroupFragment newInstance() {
            return new PickGroupFragment();
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<GroupListFragment> getFragments() {
        return (List) this.fragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<String> getTabEntities() {
        return (ArrayList) this.tabEntities.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_pick_group;
    }

    @NotNull
    public final SlidingTabLayout getTabLayout() {
        return (SlidingTabLayout) this.tabLayout.getValue();
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
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.found.PickGroupFragment$initViews$1$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                PickGroupFragment.this.getTabLayout().setCurrentTab(position);
            }
        });
        SlidingTabLayout tabLayout = getTabLayout();
        ViewPager vp_content2 = getVp_content();
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tabLayout.m4011e(vp_content2, (String[]) array);
    }
}
