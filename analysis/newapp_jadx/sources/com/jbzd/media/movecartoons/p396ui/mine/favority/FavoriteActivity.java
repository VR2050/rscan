package com.jbzd.media.movecartoons.p396ui.mine.favority;

import android.content.Context;
import android.content.Intent;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.drake.brv.annotaion.DividerOrientation;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.databinding.ActTabPagerBinding;
import com.jbzd.media.movecartoons.p396ui.BaseListFragment;
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
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0011\n\u0002\b\r\u0018\u0000 %2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001%B\u0007¢\u0006\u0004\b$\u0010\fJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\r\u0010\fR\u001f\u0010\u0011\u001a\u0004\u0018\u00010\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\nR-\u0010\u0018\u001a\u0012\u0012\u0004\u0012\u00020\u00130\u0012j\b\u0012\u0004\u0012\u00020\u0013`\u00148B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u000f\u001a\u0004\b\u0016\u0010\u0017RA\u0010\u001e\u001a&\u0012\f\u0012\n \u001a*\u0004\u0018\u00010\b0\b \u001a*\u0012\u0012\u000e\b\u0001\u0012\n \u001a*\u0004\u0018\u00010\b0\b0\u00190\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u000f\u001a\u0004\b\u001c\u0010\u001dR\"\u0010\u001f\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"\"\u0004\b#\u0010\u0007¨\u0006&"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/favority/FavoriteActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActTabPagerBinding;", "", "position", "", "onFavoriteChange", "(I)V", "", "getTopBarTitle", "()Ljava/lang/String;", "clickRight", "()V", "initView", "mType$delegate", "Lkotlin/Lazy;", "getMType", "mType", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "getFragments", "()Ljava/util/ArrayList;", "fragments", "", "kotlin.jvm.PlatformType", "tabEntities$delegate", "getTabEntities", "()[Ljava/lang/String;", "tabEntities", "pager_position", "I", "getPager_position", "()I", "setPager_position", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FavoriteActivity extends BaseBindingActivity<ActTabPagerBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private int pager_position;

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<String[]>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteActivity$tabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String[] invoke() {
            return FavoriteActivity.this.getResources().getStringArray(R.array.purchase_tab_title);
        }
    });

    /* renamed from: mType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteActivity$mType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Intent intent = FavoriteActivity.this.getIntent();
            if (intent == null) {
                return null;
            }
            return intent.getStringExtra("type");
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<Fragment>>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteActivity$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<Fragment> invoke() {
            String name = FavoriteComicFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name, "FavoriteComicFragment::class.java.name");
            Builder margin = new Builder(name).dividerSpace(C4195m.m4785R(2.0f)).margin(C4195m.m4785R(6.0f));
            DividerOrientation dividerOrientation = DividerOrientation.GRID;
            String name2 = FavoriteMovieFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name2, "FavoriteMovieFragment::class.java.name");
            String name3 = FavoriteNovelFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name3, "FavoriteNovelFragment::class.java.name");
            String name4 = FavoritePostFragment.class.getName();
            Intrinsics.checkNotNullExpressionValue(name4, "FavoritePostFragment::class.java.name");
            return CollectionsKt__CollectionsKt.arrayListOf(margin.orientation(dividerOrientation).spanCount(3).build(), new Builder(name2).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(6.0f)).orientation(dividerOrientation).spanCount(2).build(), new Builder(name3).dividerSpace(C4195m.m4785R(6.0f)).margin(C4195m.m4785R(6.0f)).orientation(dividerOrientation).spanCount(3).build(), new Builder(name4).divider(R.drawable.shape_post_divider).orientation(DividerOrientation.VERTICAL).build());
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/favority/FavoriteActivity$Companion;", "", "Landroid/content/Context;", "context", "", "type", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull String type) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(type, "type");
            Intent intent = new Intent(context, (Class<?>) FavoriteActivity.class);
            intent.putExtra("type", type);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<Fragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    private final String getMType() {
        return (String) this.mType.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String[] getTabEntities() {
        return (String[]) this.tabEntities.getValue();
    }

    private final void onFavoriteChange(int position) {
        Fragment fragment = getFragments().get(position);
        Intrinsics.checkNotNullExpressionValue(fragment, "fragments[position]");
        Fragment fragment2 = fragment;
        if (fragment2 instanceof BaseListFragment) {
            ((BaseListFragment) fragment2).toggle();
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void clickRight() {
        onFavoriteChange(getBodyBinding().vpContent.getCurrentItem());
    }

    public final int getPager_position() {
        return this.pager_position;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.mine_collect);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_collect)");
        return string;
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        String mType;
        if (getMType() != null && (mType = getMType()) != null) {
            switch (mType.hashCode()) {
                case -1354819208:
                    if (mType.equals("comics")) {
                        this.pager_position = 0;
                        break;
                    }
                    break;
                case -1039745817:
                    if (mType.equals("normal")) {
                        this.pager_position = 1;
                        break;
                    }
                    break;
                case 3446944:
                    if (mType.equals("post")) {
                        this.pager_position = 3;
                        break;
                    }
                    break;
                case 105010748:
                    if (mType.equals("novel")) {
                        this.pager_position = 2;
                        break;
                    }
                    break;
                case 554426222:
                    if (mType.equals("cartoon")) {
                        this.pager_position = 1;
                        break;
                    }
                    break;
            }
        }
        bodyBinding(new Function1<ActTabPagerBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteActivity$initView$1
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
                FragmentManager supportFragmentManager = FavoriteActivity.this.getSupportFragmentManager();
                Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
                fragments = FavoriteActivity.this.getFragments();
                viewPager.setAdapter(new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null));
                SlidingTabLayout slidingTabLayout = bodyBinding.tabLayout;
                ViewPager viewPager2 = bodyBinding.vpContent;
                tabEntities = FavoriteActivity.this.getTabEntities();
                slidingTabLayout.m4011e(viewPager2, tabEntities);
                bodyBinding.vpContent.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.mine.favority.FavoriteActivity$initView$1.1
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
                bodyBinding.vpContent.setCurrentItem(FavoriteActivity.this.getPager_position());
            }
        });
        ((TextView) getRightTitleView().findViewById(R.id.tv_titleRight)).setTextColor(ContextCompat.getColor(this, R.color.comic_type_color));
    }

    public final void setPager_position(int i2) {
        this.pager_position = i2;
    }
}
