package com.jbzd.media.movecartoons.p396ui.search;

import android.content.Context;
import android.content.Intent;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u0000 \u001c2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001\u001cB\u0007¢\u0006\u0004\b\u001b\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tR&\u0010\r\u001a\u0012\u0012\u0004\u0012\u00020\u000b0\nj\b\u0012\u0004\u0012\u00020\u000b`\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u000eR&\u0010\u0010\u001a\u0012\u0012\u0004\u0012\u00020\u000f0\nj\b\u0012\u0004\u0012\u00020\u000f`\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010\u000eR\u001d\u0010\u0016\u001a\u00020\u00118B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R\u001f\u0010\u001a\u001a\u0004\u0018\u00010\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0013\u001a\u0004\b\u0018\u0010\u0019¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/SearchHomeActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "setPager", "()V", "bindEvent", "", "getLayoutId", "()I", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragments", "Ljava/util/ArrayList;", "", "tabEntities", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter$delegate", "Lkotlin/Lazy;", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "adapter", "mPosition$delegate", "getMPosition", "()Ljava/lang/String;", "mPosition", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchHomeActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String key_position = "KEY_POSITION";

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchHomeActivity$mPosition$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return SearchHomeActivity.this.getIntent().getStringExtra(SearchHomeActivity.key_position);
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchHomeActivity$adapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList arrayList;
            FragmentManager supportFragmentManager = SearchHomeActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            arrayList = SearchHomeActivity.this.fragments;
            return new ViewPagerAdapter(supportFragmentManager, arrayList, 0, 4, null);
        }
    });

    @NotNull
    private ArrayList<String> tabEntities = new ArrayList<>();

    @NotNull
    private ArrayList<Fragment> fragments = new ArrayList<>();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\u0016\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/SearchHomeActivity$Companion;", "", "Landroid/content/Context;", "context", "", "position", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "key_position", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull String position) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(position, "position");
            Intent intent = new Intent(context, (Class<?>) SearchHomeActivity.class);
            intent.putExtra(SearchHomeActivity.key_position, position);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    private final ViewPagerAdapter getAdapter() {
        return (ViewPagerAdapter) this.adapter.getValue();
    }

    private final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    private final void setPager() {
        int i2 = R$id.vp_content;
        ViewPager viewPager = (ViewPager) findViewById(i2);
        viewPager.setOffscreenPageLimit(this.tabEntities.size());
        viewPager.setAdapter(getAdapter());
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.SearchHomeActivity$setPager$1$1
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
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) findViewById(R$id.tab_layout_searchandmoives);
        ViewPager viewPager2 = (ViewPager) findViewById(i2);
        Object[] array = this.tabEntities.toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e(viewPager2, (String[]) array);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x00ed, code lost:
    
        if (r0.equals("dark") == false) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00f9, code lost:
    
        r0 = r5.fragments;
        r1 = com.jbzd.media.movecartoons.p396ui.search.page.SearchRecommendedPage.INSTANCE;
        r2 = getMPosition();
        kotlin.jvm.internal.Intrinsics.checkNotNull(r2);
        r0.add(r1.newInstance(r2));
        r5.tabEntities.add("片库");
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x00f6, code lost:
    
        if (r0.equals("normal") == false) goto L41;
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void bindEvent() {
        /*
            Method dump skipped, instructions count: 344
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.search.SearchHomeActivity.bindEvent():void");
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_search_home;
    }
}
