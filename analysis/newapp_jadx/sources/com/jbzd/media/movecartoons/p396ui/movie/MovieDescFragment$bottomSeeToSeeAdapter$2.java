package com.jbzd.media.movecartoons.p396ui.movie;

import android.content.Context;
import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment$bottomSeeToSeeAdapter$2;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/movie/MovieDescFragment$bottomSeeToSeeAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment$bottomSeeToSeeAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieDescFragment$bottomSeeToSeeAdapter$2 extends Lambda implements Function0<C38181> {
    public final /* synthetic */ MovieDescFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MovieDescFragment$bottomSeeToSeeAdapter$2(MovieDescFragment movieDescFragment) {
        super(0);
        this.this$0 = movieDescFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5874invoke$lambda1$lambda0(MovieDescFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoDetailBean");
        MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        companion.start(requireContext, ((VideoDetailBean) item).f10000id);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$bottomSeeToSeeAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C38181 invoke() {
        ?? r0 = new BaseQuickAdapter<VideoDetailBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$bottomSeeToSeeAdapter$2.1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull VideoDetailBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                VideoItemShowKt.showVideoItemMsgNew(getContext(), helper, item, (r23 & 8) != 0, (r23 & 16) != 0, (r23 & 32) != 0, (r23 & 64) != 0, (r23 & 128) != 0 ? false : false, (r23 & 256) != 0, (r23 & 512) != 0 ? false : false);
                helper.m3916f(R.id.ll_money_vip, Intrinsics.areEqual(item.ico, VideoTypeBean.video_type_free));
                helper.m3922l(R.id.iv_ico_type, Intrinsics.areEqual(item.ico, VideoTypeBean.video_type_free));
            }
        };
        final MovieDescFragment movieDescFragment = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.i.g
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                MovieDescFragment$bottomSeeToSeeAdapter$2.m5874invoke$lambda1$lambda0(MovieDescFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
