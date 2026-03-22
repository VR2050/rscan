package com.jbzd.media.movecartoons.p396ui.novel;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailInfoFragment;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailInfoFragment$bottomSeeToSeeAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/novel/NovelDetailInfoFragment$bottomSeeToSeeAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelDetailInfoFragment$bottomSeeToSeeAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelDetailInfoFragment$bottomSeeToSeeAdapter$2 extends Lambda implements Function0<C38371> {
    public final /* synthetic */ NovelDetailInfoFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NovelDetailInfoFragment$bottomSeeToSeeAdapter$2(NovelDetailInfoFragment novelDetailInfoFragment) {
        super(0);
        this.this$0 = novelDetailInfoFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5925invoke$lambda1$lambda0(NovelDetailInfoFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean");
        NovelDetailActivity.Companion companion = NovelDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String id = ((NovelItemsBean) item).getId();
        Intrinsics.checkNotNullExpressionValue(id, "mNovelItemsBean.id");
        companion.start(requireContext, id);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.novel.NovelDetailInfoFragment$bottomSeeToSeeAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C38371 invoke() {
        final NovelDetailInfoFragment novelDetailInfoFragment = this.this$0;
        ?? r0 = new BaseQuickAdapter<NovelItemsBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelDetailInfoFragment$bottomSeeToSeeAdapter$2.1
            {
                super(R.layout.item_horizontal_scroll, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull NovelItemsBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                C2354n.m2463c2(NovelDetailInfoFragment.this).m3298p(item.getImg()).m3292f0().m757R((ImageView) helper.m3912b(R.id.iv_video));
                View view = helper.m3912b(R.id.iv_video);
                Intrinsics.checkNotNullParameter(view, "view");
                view.setOutlineProvider(new C0859m0(6.0d));
                view.setClipToOutline(true);
                helper.m3919i(R.id.tv_name, item.getName());
                helper.m3919i(R.id.tv_video_click, item.getCategory_name() + Typography.middleDot + ((Object) item.getSub_title()));
                helper.m3916f(R.id.iv_novel_audio, item.getIco().equals("audio") ^ true);
            }
        };
        final NovelDetailInfoFragment novelDetailInfoFragment2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.j.o
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                NovelDetailInfoFragment$bottomSeeToSeeAdapter$2.m5925invoke$lambda1$lambda0(NovelDetailInfoFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
