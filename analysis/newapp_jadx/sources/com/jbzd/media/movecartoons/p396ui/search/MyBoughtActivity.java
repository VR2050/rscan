package com.jbzd.media.movecartoons.p396ui.search;

import android.content.Context;
import android.content.Intent;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.drake.brv.annotaion.DividerOrientation;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.databinding.ActTabPagerBinding;
import com.jbzd.media.movecartoons.p396ui.Builder;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.mine.MyBoughtNovelFragment;
import com.jbzd.media.movecartoons.p396ui.search.purchase.PurchaseAiFragment;
import com.jbzd.media.movecartoons.p396ui.search.purchase.PurchaseComicFragment;
import com.jbzd.media.movecartoons.p396ui.search.purchase.PurchasePostFragment;
import com.jbzd.media.movecartoons.p396ui.search.purchase.PurchaseVideoFragment;
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
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0007\u0018\u0000 \u001e2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u001eB\u0007¢\u0006\u0004\b\u001d\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tRA\u0010\u0010\u001a&\u0012\f\u0012\n \u000b*\u0004\u0018\u00010\u00070\u0007 \u000b*\u0012\u0012\u000e\b\u0001\u0012\n \u000b*\u0004\u0018\u00010\u00070\u00070\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR-\u0010\u0017\u001a\u0012\u0012\u0004\u0012\u00020\u00120\u0011j\b\u0012\u0004\u0012\u00020\u0012`\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\r\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001c\u001a\u00020\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\r\u001a\u0004\b\u001a\u0010\u001b¨\u0006\u001f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/MyBoughtActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActTabPagerBinding;", "", "initView", "()V", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "", "kotlin.jvm.PlatformType", "tabEntities$delegate", "Lkotlin/Lazy;", "getTabEntities", "()[Ljava/lang/String;", "tabEntities", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "getFragments", "()Ljava/util/ArrayList;", "fragments", "", "selectIndex$delegate", "getSelectIndex", "()I", "selectIndex", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyBoughtActivity extends BaseBindingActivity<ActTabPagerBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_TAB = "tab";
    public static final int TAB_INDEX_AI = 3;
    public static final int TAB_INDEX_COMIC = 0;
    public static final int TAB_INDEX_POST = 2;
    public static final int TAB_INDEX_VIDEO = 1;

    /* renamed from: selectIndex$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy selectIndex = LazyKt__LazyJVMKt.lazy(new Function0<Integer>() { // from class: com.jbzd.media.movecartoons.ui.search.MyBoughtActivity$selectIndex$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Integer invoke() {
            return Integer.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final int invoke2() {
            return MyBoughtActivity.this.getIntent().getIntExtra(MyBoughtActivity.KEY_TAB, 0);
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<String[]>() { // from class: com.jbzd.media.movecartoons.ui.search.MyBoughtActivity$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String[] invoke() {
            return MyBoughtActivity.this.getResources().getStringArray(R.array.mybought_tab_title);
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<Fragment>>() { // from class: com.jbzd.media.movecartoons.ui.search.MyBoughtActivity$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<Fragment> invoke() {
            String name = PurchaseComicFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name, "PurchaseComicFragment::class.java.name");
            Builder margin = new Builder(name).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(6.0f));
            DividerOrientation dividerOrientation = DividerOrientation.GRID;
            String name2 = PurchaseVideoFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name2, "PurchaseVideoFragment::class.java.name");
            String name3 = MyBoughtNovelFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name3, "MyBoughtNovelFragment::class.java.name");
            Builder divider = new Builder(name3).divider(R.drawable.shape_post_divider);
            DividerOrientation dividerOrientation2 = DividerOrientation.VERTICAL;
            String name4 = PurchasePostFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name4, "PurchasePostFragment::class.java.name");
            String name5 = PurchaseAiFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name5, "PurchaseAiFragment::class.java.name");
            return CollectionsKt__CollectionsKt.arrayListOf(margin.orientation(dividerOrientation).spanCount(3).build(), new Builder(name2).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(6.0f)).orientation(dividerOrientation).spanCount(2).build(), divider.orientation(dividerOrientation2).build(), new Builder(name4).divider(R.drawable.shape_post_divider).orientation(dividerOrientation2).build(), new Builder(name5).divider(R.drawable.shape_post_divider).orientation(dividerOrientation2).build());
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\n\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\u0016\u0010\n\u001a\u00020\t8\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\u000bR\u0016\u0010\f\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\f\u0010\rR\u0016\u0010\u000e\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000e\u0010\rR\u0016\u0010\u000f\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000f\u0010\rR\u0016\u0010\u0010\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0010\u0010\r¨\u0006\u0013"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/MyBoughtActivity$Companion;", "", "Landroid/content/Context;", "context", "", "pagerIndex", "", "start", "(Landroid/content/Context;I)V", "", "KEY_TAB", "Ljava/lang/String;", "TAB_INDEX_AI", "I", "TAB_INDEX_COMIC", "TAB_INDEX_POST", "TAB_INDEX_VIDEO", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, int i2, int i3, Object obj) {
            if ((i3 & 2) != 0) {
                i2 = 0;
            }
            companion.start(context, i2);
        }

        public final void start(@NotNull Context context, int pagerIndex) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) MyBoughtActivity.class);
            intent.putExtra(MyBoughtActivity.KEY_TAB, pagerIndex);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<Fragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int getSelectIndex() {
        return ((Number) this.selectIndex.getValue()).intValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String[] getTabEntities() {
        return (String[]) this.tabEntities.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.mine_buy);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_buy)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActTabPagerBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.MyBoughtActivity$initView$1
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
                int selectIndex;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                ViewPager viewPager = bodyBinding.vpContent;
                FragmentManager supportFragmentManager = MyBoughtActivity.this.getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
                fragments = MyBoughtActivity.this.getFragments();
                viewPager.setAdapter(new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null));
                SlidingTabLayout slidingTabLayout = bodyBinding.tabLayout;
                ViewPager viewPager2 = bodyBinding.vpContent;
                tabEntities = MyBoughtActivity.this.getTabEntities();
                slidingTabLayout.m4011e(viewPager2, tabEntities);
                ViewPager viewPager3 = bodyBinding.vpContent;
                selectIndex = MyBoughtActivity.this.getSelectIndex();
                viewPager3.setCurrentItem(selectIndex);
            }
        });
    }
}
