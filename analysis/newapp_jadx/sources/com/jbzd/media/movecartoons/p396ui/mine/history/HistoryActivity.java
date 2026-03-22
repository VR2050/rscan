package com.jbzd.media.movecartoons.p396ui.mine.history;

import android.content.Context;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.drake.brv.annotaion.DividerOrientation;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.databinding.ActTabPagerBinding;
import com.jbzd.media.movecartoons.p396ui.Builder;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.util.ArrayList;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 \u00182\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0018B\u0007¢\u0006\u0004\b\u0017\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bRA\u0010\u000f\u001a&\u0012\f\u0012\n \n*\u0004\u0018\u00010\u00030\u0003 \n*\u0012\u0012\u000e\b\u0001\u0012\n \n*\u0004\u0018\u00010\u00030\u00030\t0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR-\u0010\u0016\u001a\u0012\u0012\u0004\u0012\u00020\u00110\u0010j\b\u0012\u0004\u0012\u00020\u0011`\u00128B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\f\u001a\u0004\b\u0014\u0010\u0015¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/history/HistoryActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActTabPagerBinding;", "", "getTopBarTitle", "()Ljava/lang/String;", "", "initView", "()V", "", "kotlin.jvm.PlatformType", "tabEntities$delegate", "Lkotlin/Lazy;", "getTabEntities", "()[Ljava/lang/String;", "tabEntities", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "getFragments", "()Ljava/util/ArrayList;", "fragments", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HistoryActivity extends BaseBindingActivity<ActTabPagerBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<String[]>() { // from class: com.jbzd.media.movecartoons.ui.mine.history.HistoryActivity$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String[] invoke() {
            return HistoryActivity.this.getResources().getStringArray(R.array.history_tab_title);
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<Fragment>>() { // from class: com.jbzd.media.movecartoons.ui.mine.history.HistoryActivity$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<Fragment> invoke() {
            String name = HistoryComicsFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name, "HistoryComicsFragment::class.java.name");
            Builder margin = new Builder(name).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(12.0f));
            DividerOrientation dividerOrientation = DividerOrientation.GRID;
            String name2 = HistoryMovieFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name2, "HistoryMovieFragment::class.java.name");
            String name3 = HistoryNovelFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name3, "HistoryNovelFragment::class.java.name");
            return CollectionsKt__CollectionsKt.arrayListOf(margin.orientation(dividerOrientation).spanCount(3).build(), new Builder(name2).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(12.0f)).orientation(dividerOrientation).spanCount(2).build(), new Builder(name3).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(12.0f)).orientation(dividerOrientation).spanCount(3).build());
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/history/HistoryActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, HistoryActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<Fragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String[] getTabEntities() {
        return (String[]) this.tabEntities.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        return "浏览记录";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActTabPagerBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.history.HistoryActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActTabPagerBinding actTabPagerBinding) {
                invoke2(actTabPagerBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActTabPagerBinding bodyBinding) {
                ArrayList fragments;
                String[] tabEntities;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                ViewPager viewPager = bodyBinding.vpContent;
                FragmentManager supportFragmentManager = HistoryActivity.this.getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
                fragments = HistoryActivity.this.getFragments();
                viewPager.setAdapter(new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null));
                SlidingTabLayout slidingTabLayout = bodyBinding.tabLayout;
                ViewPager viewPager2 = bodyBinding.vpContent;
                tabEntities = HistoryActivity.this.getTabEntities();
                slidingTabLayout.m4011e(viewPager2, tabEntities);
                bodyBinding.vpContent.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.mine.history.HistoryActivity$initView$1.1
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
                bodyBinding.vpContent.setCurrentItem(0);
            }
        });
    }
}
