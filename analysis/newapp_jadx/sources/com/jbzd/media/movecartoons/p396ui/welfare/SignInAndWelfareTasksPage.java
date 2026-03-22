package com.jbzd.media.movecartoons.p396ui.welfare;

import android.content.Context;
import android.util.TypedValue;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.view.CommonFragmentAdapter;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000P\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 (2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001(B\u0007¢\u0006\u0004\b'\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bR\u001d\u0010\u000e\u001a\u00020\t8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u001c\u0010\u0011\u001a\b\u0012\u0004\u0012\u00020\u00100\u000f8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0011\u0010\u0012R\u001d\u0010\u0017\u001a\u00020\u00138F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u000b\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001c\u001a\u00020\u00188F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u000b\u001a\u0004\b\u001a\u0010\u001bR=\u0010#\u001a\"\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u001e0\u001dj\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u001e`\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u000b\u001a\u0004\b!\u0010\"R\u001d\u0010&\u001a\u00020\u00138F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u000b\u001a\u0004\b%\u0010\u0016¨\u0006)"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/SignInAndWelfareTasksPage;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "bindEvent", "()V", "", "getLayoutId", "()I", "Landroidx/viewpager/widget/ViewPager;", "vp_welfare_points$delegate", "Lkotlin/Lazy;", "getVp_welfare_points", "()Landroidx/viewpager/widget/ViewPager;", "vp_welfare_points", "", "", "titleList", "Ljava/util/List;", "Landroid/widget/RelativeLayout;", "ll_signin_top$delegate", "getLl_signin_top", "()Landroid/widget/RelativeLayout;", "ll_signin_top", "Lcom/flyco/tablayout/SlidingTabLayout;", "tab_welfare_points$delegate", "getTab_welfare_points", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tab_welfare_points", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "getFragments", "()Ljava/util/ArrayList;", "fragments", "ivBack$delegate", "getIvBack", "ivBack", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SignInAndWelfareTasksPage extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private final List<String> titleList = CollectionsKt__CollectionsKt.listOf((Object[]) new String[]{"福利任务", "积分兑换"});

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MyThemeFragment<Object>>>() { // from class: com.jbzd.media.movecartoons.ui.welfare.SignInAndWelfareTasksPage$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MyThemeFragment<Object>> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf(new WelfareTaskFragment(), new ChangeScoreFragment());
        }
    });

    /* renamed from: ivBack$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ivBack = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.welfare.SignInAndWelfareTasksPage$ivBack$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) SignInAndWelfareTasksPage.this.findViewById(R.id.ivBack);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: ll_signin_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_signin_top = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.welfare.SignInAndWelfareTasksPage$ll_signin_top$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) SignInAndWelfareTasksPage.this.findViewById(R.id.ll_signin_top);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: vp_welfare_points$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_welfare_points = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.welfare.SignInAndWelfareTasksPage$vp_welfare_points$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) SignInAndWelfareTasksPage.this.findViewById(R.id.vp_welfare_points);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tab_welfare_points$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tab_welfare_points = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.welfare.SignInAndWelfareTasksPage$tab_welfare_points$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) SignInAndWelfareTasksPage.this.findViewById(R.id.tab_welfare_points);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/SignInAndWelfareTasksPage$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @JvmStatic
        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, SignInAndWelfareTasksPage.class);
        }
    }

    private final ArrayList<MyThemeFragment<Object>> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    @JvmStatic
    public static final void start(@NotNull Context context) {
        INSTANCE.start(context);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        C2354n.m2377B(getIvBack(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.SignInAndWelfareTasksPage$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SignInAndWelfareTasksPage.this.onBackPressed();
            }
        }, 1);
        ViewGroup.LayoutParams layoutParams = getLl_signin_top().getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.widget.LinearLayout.LayoutParams");
        int statusBarHeight = ImmersionBar.getStatusBarHeight(this);
        MyApp myApp = MyApp.f9891f;
        ((LinearLayout.LayoutParams) layoutParams).topMargin = statusBarHeight + ((int) TypedValue.applyDimension(1, 12, MyApp.m4183d().getResources().getDisplayMetrics()));
        ViewPager vp_welfare_points = getVp_welfare_points();
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        vp_welfare_points.setAdapter(new CommonFragmentAdapter(supportFragmentManager, getFragments(), this.titleList));
        getTab_welfare_points().setViewPager(getVp_welfare_points());
    }

    @NotNull
    public final RelativeLayout getIvBack() {
        return (RelativeLayout) this.ivBack.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.frag_felware;
    }

    @NotNull
    public final RelativeLayout getLl_signin_top() {
        return (RelativeLayout) this.ll_signin_top.getValue();
    }

    @NotNull
    public final SlidingTabLayout getTab_welfare_points() {
        return (SlidingTabLayout) this.tab_welfare_points.getValue();
    }

    @NotNull
    public final ViewPager getVp_welfare_points() {
        return (ViewPager) this.vp_welfare_points.getValue();
    }
}
