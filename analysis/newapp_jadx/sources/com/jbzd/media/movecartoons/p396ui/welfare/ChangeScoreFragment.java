package com.jbzd.media.movecartoons.p396ui.welfare;

import android.view.View;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.ScoreBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.welfare.ChangeScoreFragment;
import com.jbzd.media.movecartoons.p396ui.welfare.ChangeScoreFragment$groupAdapter$2;
import com.jbzd.media.movecartoons.view.XRefreshLayout;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2913d;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000S\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\b\b*\u0001-\u0018\u0000 32\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u00013B\u0007¢\u0006\u0004\b2\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\n\u0010\u0005J\u000f\u0010\u000b\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u000b\u0010\u0005R\u001d\u0010\u0011\u001a\u00020\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010R\u0018\u0010\u0013\u001a\u0004\u0018\u00010\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0013\u0010\u0014R\u001d\u0010\u0019\u001a\u00020\u00158F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u000e\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u001a8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u000e\u001a\u0004\b\u001c\u0010\u001dR\u001d\u0010#\u001a\u00020\u001f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u000e\u001a\u0004\b!\u0010\"R\u0016\u0010$\u001a\u00020\u00078\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b$\u0010%R\u001d\u0010(\u001a\u00020\u001f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u000e\u001a\u0004\b'\u0010\"R\u0016\u0010)\u001a\u00020\u00078\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010%R\u0018\u0010+\u001a\u0004\u0018\u00010*8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b+\u0010,R\u001d\u00101\u001a\u00020-8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u000e\u001a\u0004\b/\u00100¨\u00064"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "getInfo", "()V", "doExchange", "", "getLayout", "()I", "onDestroy", "initViews", "Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "iv_user_avatar_score$delegate", "Lkotlin/Lazy;", "getIv_user_avatar_score", "()Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "iv_user_avatar_score", "Lc/a/d1;", "job", "Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_group$delegate", "getRv_group", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_group", "Lcom/jbzd/media/movecartoons/view/XRefreshLayout;", "refresh_layout_changestore$delegate", "getRefresh_layout_changestore", "()Lcom/jbzd/media/movecartoons/view/XRefreshLayout;", "refresh_layout_changestore", "Landroid/widget/TextView;", "tv_watch_num$delegate", "getTv_watch_num", "()Landroid/widget/TextView;", "tv_watch_num", "score", "I", "tv_role_score_name$delegate", "getTv_role_score_name", "tv_role_score_name", "userScore", "Lcom/jbzd/media/movecartoons/bean/response/ScoreBean$ExchangeItem;", "mProductsBean", "Lcom/jbzd/media/movecartoons/bean/response/ScoreBean$ExchangeItem;", "com/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment$groupAdapter$2$1", "groupAdapter$delegate", "getGroupAdapter", "()Lcom/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment$groupAdapter$2$1;", "groupAdapter", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ChangeScoreFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private InterfaceC3053d1 job;

    @Nullable
    private ScoreBean.ExchangeItem mProductsBean;
    private int score;
    private int userScore;

    /* renamed from: groupAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy groupAdapter = LazyKt__LazyJVMKt.lazy(new ChangeScoreFragment$groupAdapter$2(this));

    /* renamed from: iv_user_avatar_score$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_user_avatar_score = LazyKt__LazyJVMKt.lazy(new Function0<CircleImageView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$iv_user_avatar_score$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CircleImageView invoke() {
            View view = ChangeScoreFragment.this.getView();
            CircleImageView circleImageView = view == null ? null : (CircleImageView) view.findViewById(R.id.iv_user_avatar_score);
            Intrinsics.checkNotNull(circleImageView);
            return circleImageView;
        }
    });

    /* renamed from: refresh_layout_changestore$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy refresh_layout_changestore = LazyKt__LazyJVMKt.lazy(new Function0<XRefreshLayout>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$refresh_layout_changestore$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final XRefreshLayout invoke() {
            View view = ChangeScoreFragment.this.getView();
            XRefreshLayout xRefreshLayout = view == null ? null : (XRefreshLayout) view.findViewById(R.id.refresh_layout_changestore);
            Intrinsics.checkNotNull(xRefreshLayout);
            return xRefreshLayout;
        }
    });

    /* renamed from: tv_role_score_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_role_score_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$tv_role_score_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = ChangeScoreFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_role_score_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_watch_num$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_watch_num = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$tv_watch_num$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = ChangeScoreFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_watch_num);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rv_group$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_group = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$rv_group$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View view = ChangeScoreFragment.this.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_group);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @JvmStatic
        @NotNull
        public final ChangeScoreFragment newInstance() {
            return new ChangeScoreFragment();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void doExchange() {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        ScoreBean.ExchangeItem exchangeItem = this.mProductsBean;
        hashMap.put("num", String.valueOf(exchangeItem == null ? null : Integer.valueOf(exchangeItem.num)));
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(c0917a, "user/doExchange", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$doExchange$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                int i2;
                ScoreBean.ExchangeItem exchangeItem2;
                C2354n.m2409L1("VIP兑换成功");
                TextView tv_watch_num = ChangeScoreFragment.this.getTv_watch_num();
                i2 = ChangeScoreFragment.this.userScore;
                exchangeItem2 = ChangeScoreFragment.this.mProductsBean;
                Integer valueOf = exchangeItem2 == null ? null : Integer.valueOf(exchangeItem2.num);
                Intrinsics.checkNotNull(valueOf);
                tv_watch_num.setText(Intrinsics.stringPlus("累计积分：", Integer.valueOf(i2 - valueOf.intValue())));
            }
        }, null, false, false, null, false, 496);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ChangeScoreFragment$groupAdapter$2.C39051 getGroupAdapter() {
        return (ChangeScoreFragment$groupAdapter$2.C39051) this.groupAdapter.getValue();
    }

    private final void getInfo() {
        this.job = C0917a.m221e(C0917a.f372a, "user/exchangeInfo", ScoreBean.class, new HashMap(), new Function1<ScoreBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$getInfo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ScoreBean scoreBean) {
                invoke2(scoreBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable ScoreBean scoreBean) {
                ChangeScoreFragment$groupAdapter$2.C39051 groupAdapter;
                ChangeScoreFragment$groupAdapter$2.C39051 groupAdapter2;
                if (scoreBean == null) {
                    return;
                }
                ChangeScoreFragment changeScoreFragment = ChangeScoreFragment.this;
                C2354n.m2467d2(changeScoreFragment.requireActivity()).m3298p(scoreBean.user.img).m3288b0().m757R(changeScoreFragment.getIv_user_avatar_score());
                changeScoreFragment.getRefresh_layout_changestore().finishRefresh();
                changeScoreFragment.getTv_role_score_name().setText(scoreBean.user.nickname);
                String str = scoreBean.user.integral;
                Intrinsics.checkNotNullExpressionValue(str, "it.user.integral");
                changeScoreFragment.userScore = Integer.parseInt(str);
                changeScoreFragment.getTv_watch_num().setText(Intrinsics.stringPlus("累计积分：", scoreBean.user.integral));
                groupAdapter = changeScoreFragment.getGroupAdapter();
                groupAdapter.setNewData(scoreBean.exchange_items);
                groupAdapter2 = changeScoreFragment.getGroupAdapter();
                changeScoreFragment.mProductsBean = groupAdapter2.getItem(0);
            }
        }, null, false, false, null, false, 496);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-0, reason: not valid java name */
    public static final void m6023initViews$lambda0(ChangeScoreFragment this$0, InterfaceC2900i it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(it, "it");
        this$0.getInfo();
    }

    @JvmStatic
    @NotNull
    public static final ChangeScoreFragment newInstance() {
        return INSTANCE.newInstance();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final CircleImageView getIv_user_avatar_score() {
        return (CircleImageView) this.iv_user_avatar_score.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_change_score;
    }

    @NotNull
    public final XRefreshLayout getRefresh_layout_changestore() {
        return (XRefreshLayout) this.refresh_layout_changestore.getValue();
    }

    @NotNull
    public final RecyclerView getRv_group() {
        return (RecyclerView) this.rv_group.getValue();
    }

    @NotNull
    public final TextView getTv_role_score_name() {
        return (TextView) this.tv_role_score_name.getValue();
    }

    @NotNull
    public final TextView getTv_watch_num() {
        return (TextView) this.tv_watch_num.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getInfo();
        getRefresh_layout_changestore().setOnRefreshListener(new InterfaceC2913d() { // from class: b.a.a.a.t.t.a
            @Override // p005b.p340x.p354b.p355a.p360f.InterfaceC2913d
            /* renamed from: b */
            public final void mo302b(InterfaceC2900i interfaceC2900i) {
                ChangeScoreFragment.m6023initViews$lambda0(ChangeScoreFragment.this, interfaceC2900i);
            }
        });
        RecyclerView rv_group = getRv_group();
        if (rv_group.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_group.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_group, 10.0d);
            c4053a.f10337e = C2354n.m2437V(rv_group.getContext(), 10.0d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, rv_group);
        }
        rv_group.setAdapter(getGroupAdapter());
        rv_group.setLayoutManager(new GridLayoutManager(rv_group.getContext(), 3));
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }
}
