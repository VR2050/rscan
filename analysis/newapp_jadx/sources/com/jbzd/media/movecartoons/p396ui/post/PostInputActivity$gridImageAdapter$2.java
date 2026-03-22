package com.jbzd.media.movecartoons.p396ui.post;

import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.trade.MediaSelectAdapter;
import com.jbzd.media.movecartoons.p396ui.post.PostInputActivity;
import com.jbzd.media.movecartoons.p396ui.post.PostInputActivity$gridImageAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/index/darkplay/trade/MediaSelectAdapter;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostInputActivity$gridImageAdapter$2 extends Lambda implements Function0<MediaSelectAdapter> {
    public final /* synthetic */ PostInputActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PostInputActivity$gridImageAdapter$2(PostInputActivity postInputActivity) {
        super(0);
        this.this$0 = postInputActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-2$lambda-0, reason: not valid java name */
    public static final void m5944invoke$lambda2$lambda0(PostInputActivity this$0, BaseQuickAdapter noName_0, View noName_1, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(noName_0, "$noName_0");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        this$0.selectImage();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5945invoke$lambda2$lambda1(PostInputActivity this$0, MediaSelectAdapter this_apply, BaseQuickAdapter adapter, View view, int i2) {
        int i3;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        if (view.getId() == R.id.iv_delete) {
            this$0.removeItem(this_apply, i2);
            if (adapter.getData().size() == 1) {
                i3 = this$0.mChosenMediaType;
                if (i3 == 1) {
                    this$0.restoreDefaultState();
                }
            }
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final MediaSelectAdapter invoke() {
        final MediaSelectAdapter mediaSelectAdapter = new MediaSelectAdapter();
        final PostInputActivity postInputActivity = this.this$0;
        mediaSelectAdapter.setupMedia(MediaSelectAdapter.MediaType.Image.INSTANCE);
        mediaSelectAdapter.addChildClickViewIds(R.id.iv_delete);
        mediaSelectAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.k.c
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                PostInputActivity$gridImageAdapter$2.m5944invoke$lambda2$lambda0(PostInputActivity.this, baseQuickAdapter, view, i2);
            }
        });
        mediaSelectAdapter.setOnItemChildClickListener(new InterfaceC1302b() { // from class: b.a.a.a.t.k.b
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1302b
            /* renamed from: a */
            public final void mo215a(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                PostInputActivity$gridImageAdapter$2.m5945invoke$lambda2$lambda1(PostInputActivity.this, mediaSelectAdapter, baseQuickAdapter, view, i2);
            }
        });
        return mediaSelectAdapter;
    }
}
