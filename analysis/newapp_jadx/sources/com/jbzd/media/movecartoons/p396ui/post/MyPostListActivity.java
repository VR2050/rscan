package com.jbzd.media.movecartoons.p396ui.post;

import android.content.Context;
import android.content.Intent;
import android.widget.TextView;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.post.MyPostListFragment;
import com.jbzd.media.movecartoons.p396ui.wallet.BillActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseThemeActivity;
import java.util.ArrayList;
import java.util.Objects;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u0000 ;2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001;B\u0007¢\u0006\u0004\b:\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\t\u0010\u0005J\u000f\u0010\n\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\n\u0010\u0005R\u001d\u0010\u0010\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0013\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\r\u001a\u0004\b\u0012\u0010\u000fR\u001d\u0010\u0018\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\r\u001a\u0004\b\u0016\u0010\u0017R-\u0010\u001f\u001a\u0012\u0012\u0004\u0012\u00020\u001a0\u0019j\b\u0012\u0004\u0012\u00020\u001a`\u001b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\r\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010$\u001a\u00020 8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\r\u001a\u0004\b\"\u0010#R\u001d\u0010'\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\r\u001a\u0004\b&\u0010\u000fR\u001d\u0010*\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\r\u001a\u0004\b)\u0010\u000fR\u001d\u0010/\u001a\u00020+8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\r\u001a\u0004\b-\u0010.R\u001d\u00102\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\r\u001a\u0004\b1\u0010\u000fR-\u00106\u001a\u0012\u0012\u0004\u0012\u0002030\u0019j\b\u0012\u0004\u0012\u000203`\u001b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\r\u001a\u0004\b5\u0010\u001eR\u001d\u00109\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\r\u001a\u0004\b8\u0010\u000f¨\u0006<"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/MyPostListActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "bindEvent", "()V", "", "getLayoutId", "()I", "onResume", "onDestroy", "Landroid/widget/TextView;", "tv_wallet_incomedetail$delegate", "Lkotlin/Lazy;", "getTv_wallet_incomedetail", "()Landroid/widget/TextView;", "tv_wallet_incomedetail", "tv_wallet_withdraw$delegate", "getTv_wallet_withdraw", "tv_wallet_withdraw", "Landroidx/viewpager/widget/ViewPager;", "vp_content_postchild$delegate", "getVp_content_postchild", "()Landroidx/viewpager/widget/ViewPager;", "vp_content_postchild", "Ljava/util/ArrayList;", "", "Lkotlin/collections/ArrayList;", "tabEntities$delegate", "getTabEntities", "()Ljava/util/ArrayList;", "tabEntities", "Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_post_child$delegate", "getTablayout_post_child", "()Lcom/flyco/tablayout/SlidingTabLayout;", "tablayout_post_child", "tv_title$delegate", "getTv_title", "tv_title", "tv_titleRight$delegate", "getTv_titleRight", "tv_titleRight", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "tabAdapter$delegate", "getTabAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "tabAdapter", "txt_current_balance$delegate", "getTxt_current_balance", "txt_current_balance", "Lcom/jbzd/media/movecartoons/ui/post/MyPostListFragment;", "fragments$delegate", "getFragments", "fragments", "txt_total_count$delegate", "getTxt_total_count", "txt_total_count", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyPostListActivity extends MyThemeActivity<Object> {
    private static int mPosition;

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String userId = "";

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MyPostListFragment>>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$fragments$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MyPostListFragment> invoke() {
            MyPostListFragment.Companion companion = MyPostListFragment.INSTANCE;
            return CollectionsKt__CollectionsKt.arrayListOf(companion.newInstance("1"), companion.newInstance("0"), companion.newInstance("2"));
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tabEntities$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<String> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf("已发布", "待审核", "未通过");
        }
    });

    /* renamed from: tabAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tabAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList fragments;
            FragmentManager supportFragmentManager = MyPostListActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            fragments = MyPostListActivity.this.getFragments();
            return new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null);
        }
    });

    /* renamed from: tv_title$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_title = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tv_title$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MyPostListActivity.this.findViewById(R.id.tv_title);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: txt_current_balance$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy txt_current_balance = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$txt_current_balance$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MyPostListActivity.this.findViewById(R.id.txt_current_balance);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: txt_total_count$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy txt_total_count = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$txt_total_count$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MyPostListActivity.this.findViewById(R.id.txt_total_count);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MyPostListActivity.this.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_wallet_incomedetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_wallet_incomedetail = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tv_wallet_incomedetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MyPostListActivity.this.findViewById(R.id.tv_wallet_incomedetail);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_wallet_withdraw$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_wallet_withdraw = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tv_wallet_withdraw$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) MyPostListActivity.this.findViewById(R.id.tv_wallet_withdraw);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: vp_content_postchild$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content_postchild = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$vp_content_postchild$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) MyPostListActivity.this.findViewById(R.id.vp_content_postchild);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: tablayout_post_child$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tablayout_post_child = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$tablayout_post_child$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) MyPostListActivity.this.findViewById(R.id.tablayout_post_child);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u000f\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0016\u0010\u0017J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\n\u001a\u00020\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\"\u0010\u0010\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013\"\u0004\b\u0014\u0010\u0015¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/MyPostListActivity$Companion;", "", "Landroid/content/Context;", "context", "", "position", "", "start", "(Landroid/content/Context;I)V", "", "userId", "Ljava/lang/String;", "getUserId", "()Ljava/lang/String;", "setUserId", "(Ljava/lang/String;)V", "mPosition", "I", "getMPosition", "()I", "setMPosition", "(I)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final int getMPosition() {
            return MyPostListActivity.mPosition;
        }

        @NotNull
        public final String getUserId() {
            return MyPostListActivity.userId;
        }

        public final void setMPosition(int i2) {
            MyPostListActivity.mPosition = i2;
        }

        public final void setUserId(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            MyPostListActivity.userId = str;
        }

        public final void start(@NotNull Context context, int position) {
            Intrinsics.checkNotNullParameter(context, "context");
            setMPosition(position);
            context.startActivity(new Intent(context, (Class<?>) MyPostListActivity.class));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<MyPostListFragment> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    private final ViewPagerAdapter getTabAdapter() {
        return (ViewPagerAdapter) this.tabAdapter.getValue();
    }

    private final ArrayList<String> getTabEntities() {
        return (ArrayList) this.tabEntities.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        getTv_title().setText("我的帖子");
        TextView txt_current_balance = getTxt_current_balance();
        MyApp myApp = MyApp.f9891f;
        txt_current_balance.setText(MyApp.f9892g.balance);
        getTxt_total_count().setText(MyApp.f9892g.income);
        BaseThemeActivity.fadeWhenTouch$default(this, getTv_titleRight(), 0.0f, 1, null);
        C2354n.m2374A(getTv_titleRight(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$bindEvent$2
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
                PostInputActivity.INSTANCE.start(MyPostListActivity.this, 3, "homepage", "post");
            }
        }, 1);
        BaseThemeActivity.fadeWhenTouch$default(this, getTv_wallet_incomedetail(), 0.0f, 1, null);
        C2354n.m2374A(getTv_wallet_incomedetail(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$bindEvent$3
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
                BillActivity.INSTANCE.start(MyPostListActivity.this);
            }
        }, 1);
        BaseThemeActivity.fadeWhenTouch$default(this, getTv_wallet_withdraw(), 0.0f, 1, null);
        C2354n.m2374A(getTv_wallet_withdraw(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$bindEvent$4
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MyApp myApp2 = MyApp.f9891f;
                C2354n.m2525w0(MyApp.m4185f().withdraw_tips);
            }
        }, 1);
        ViewPager vp_content_postchild = getVp_content_postchild();
        vp_content_postchild.setOffscreenPageLimit(getTabEntities().size());
        vp_content_postchild.setAdapter(getTabAdapter());
        vp_content_postchild.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.post.MyPostListActivity$bindEvent$5$1
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
        SlidingTabLayout tablayout_post_child = getTablayout_post_child();
        ViewPager vp_content_postchild2 = getVp_content_postchild();
        Object[] array = getTabEntities().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        tablayout_post_child.m4011e(vp_content_postchild2, (String[]) array);
        getVp_content_postchild().setCurrentItem(mPosition);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_mypost_list;
    }

    @NotNull
    public final SlidingTabLayout getTablayout_post_child() {
        return (SlidingTabLayout) this.tablayout_post_child.getValue();
    }

    @NotNull
    public final TextView getTv_title() {
        return (TextView) this.tv_title.getValue();
    }

    @NotNull
    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }

    @NotNull
    public final TextView getTv_wallet_incomedetail() {
        return (TextView) this.tv_wallet_incomedetail.getValue();
    }

    @NotNull
    public final TextView getTv_wallet_withdraw() {
        return (TextView) this.tv_wallet_withdraw.getValue();
    }

    @NotNull
    public final TextView getTxt_current_balance() {
        return (TextView) this.txt_current_balance.getValue();
    }

    @NotNull
    public final TextView getTxt_total_count() {
        return (TextView) this.txt_total_count.getValue();
    }

    @NotNull
    public final ViewPager getVp_content_postchild() {
        return (ViewPager) this.vp_content_postchild.getValue();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        userId = "";
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        MyApp myApp = MyApp.f9891f;
        if (Intrinsics.areEqual(MyApp.f9893h, "1")) {
            getVp_content_postchild().setCurrentItem(1);
            Intrinsics.checkNotNullParameter("0", "<set-?>");
            MyApp.f9893h = "0";
        }
    }
}
