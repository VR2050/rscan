package com.jbzd.media.movecartoons.p396ui.novel;

import android.view.View;
import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity$novelContentAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$novelContentAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$novelContentAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelChapterViewActivity$novelContentAdapter$2 extends Lambda implements Function0<C38351> {
    public final /* synthetic */ NovelChapterViewActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NovelChapterViewActivity$novelContentAdapter$2(NovelChapterViewActivity novelChapterViewActivity) {
        super(0);
        this.this$0 = novelChapterViewActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5915invoke$lambda1$lambda0(NovelChapterViewActivity this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.settingTools();
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$novelContentAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C38351 invoke() {
        final NovelChapterViewActivity novelChapterViewActivity = this.this$0;
        ?? r0 = new BaseQuickAdapter<String, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$novelContentAdapter$2.1
            {
                super(R.layout.item_chapteritem_txt, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull String content) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(content, "content");
                NovelChapterViewActivity novelChapterViewActivity2 = NovelChapterViewActivity.this;
                novelChapterViewActivity2.setTv_chapteritem_txt((TextView) helper.m3912b(R.id.tv_chapteritem_txt));
                novelChapterViewActivity2.getTv_chapteritem_txt().setText(content);
                novelChapterViewActivity2.getTv_chapteritem_txt().setTextSize(novelChapterViewActivity2.getContentSize());
                if (novelChapterViewActivity2.getDarkModel()) {
                    novelChapterViewActivity2.getTv_chapteritem_txt().setBackgroundColor(novelChapterViewActivity2.getResources().getColor(R.color.black));
                    novelChapterViewActivity2.getTv_chapteritem_txt().setTextColor(novelChapterViewActivity2.getResources().getColor(R.color.white));
                } else {
                    novelChapterViewActivity2.getTv_chapteritem_txt().setBackgroundColor(novelChapterViewActivity2.getDaynightColorBg());
                    novelChapterViewActivity2.getTv_chapteritem_txt().setTextColor(novelChapterViewActivity2.getDaynightColorConent());
                }
            }
        };
        final NovelChapterViewActivity novelChapterViewActivity2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.j.j
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                NovelChapterViewActivity$novelContentAdapter$2.m5915invoke$lambda1$lambda0(NovelChapterViewActivity.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
