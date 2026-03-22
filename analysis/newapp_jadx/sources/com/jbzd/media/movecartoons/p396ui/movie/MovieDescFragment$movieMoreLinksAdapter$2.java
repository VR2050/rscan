package com.jbzd.media.movecartoons.p396ui.movie;

import android.content.res.Resources;
import android.view.View;
import android.widget.TextView;
import androidx.fragment.app.FragmentActivity;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment$movieMoreLinksAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/movie/MovieDescFragment$movieMoreLinksAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment$movieMoreLinksAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieDescFragment$movieMoreLinksAdapter$2 extends Lambda implements Function0<C38271> {
    public final /* synthetic */ MovieDescFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MovieDescFragment$movieMoreLinksAdapter$2(MovieDescFragment movieDescFragment) {
        super(0);
        this.this$0 = movieDescFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5875invoke$lambda1$lambda0(MovieDescFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        String mVideoId;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.setFirst(false);
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoDetailBean.MultiLinks");
        String link_id = ((VideoDetailBean.MultiLinks) obj).f9994id;
        FragmentActivity activity = this$0.getActivity();
        Objects.requireNonNull(activity, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        MovieDetailsViewModel viewModel = ((MovieDetailsActivity) activity).getViewModel();
        mVideoId = this$0.getMVideoId();
        Intrinsics.checkNotNullExpressionValue(link_id, "link_id");
        viewModel.loadMovie(mVideoId, link_id);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$movieMoreLinksAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C38271 invoke() {
        final MovieDescFragment movieDescFragment = this.this$0;
        ?? r0 = new BaseQuickAdapter<VideoDetailBean.MultiLinks, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$movieMoreLinksAdapter$2.1
            {
                super(R.layout.item_movie_morelink, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull VideoDetailBean.MultiLinks item) {
                Resources resources;
                int i2;
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                MovieDescFragment movieDescFragment2 = MovieDescFragment.this;
                TextView textView = (TextView) helper.m3912b(R.id.tv_morelink_name);
                if (movieDescFragment2.getIsFirst()) {
                    textView.setSelected(helper.getAdapterPosition() == 0);
                } else {
                    textView.setSelected(Intrinsics.areEqual(item.is_select, "y"));
                }
                helper.m3919i(R.id.tv_morelink_name, item.name);
                if (textView.isSelected()) {
                    resources = movieDescFragment2.getResources();
                    i2 = R.color.black;
                } else {
                    resources = movieDescFragment2.getResources();
                    i2 = R.color.black40;
                }
                helper.m3920j(R.id.tv_morelink_name, resources.getColor(i2));
            }
        };
        final MovieDescFragment movieDescFragment2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.i.i
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                MovieDescFragment$movieMoreLinksAdapter$2.m5875invoke$lambda1$lambda0(MovieDescFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
