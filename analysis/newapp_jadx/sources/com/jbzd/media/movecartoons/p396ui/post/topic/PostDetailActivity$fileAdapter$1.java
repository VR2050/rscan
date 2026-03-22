package com.jbzd.media.movecartoons.p396ui.post.topic;

import android.os.Handler;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostDetailBean;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity$fileAdapter$1;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.jbzd.media.movecartoons.view.video.MyVideoAllCallback;
import com.qnmd.adnnm.da0yzo.R;
import java.io.File;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001d\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/post/topic/PostDetailActivity$fileAdapter$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean$FilesBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean$FilesBean;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostDetailActivity$fileAdapter$1 extends BaseQuickAdapter<PostDetailBean.FilesBean, BaseViewHolder> {
    public final /* synthetic */ PostDetailActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PostDetailActivity$fileAdapter$1(PostDetailActivity postDetailActivity) {
        super(R.layout.item_postdetail_file, null, 2, null);
        this.this$0 = postDetailActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: convert$lambda-3$lambda-2$lambda-0, reason: not valid java name */
    public static final void m5971convert$lambda3$lambda2$lambda0(PostDetailActivity this$0, FullPlayerView this_run, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        FullPlayerView player_postdetail = this$0.getPlayer_postdetail();
        Intrinsics.checkNotNull(player_postdetail);
        player_postdetail.startWindowFullscreen(this_run.getContext(), false, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: convert$lambda-3$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5972convert$lambda3$lambda2$lambda1(FullPlayerView this_run) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this_run.startPlayLogic();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull PostDetailBean.FilesBean item) {
        Map<String, String> videoPlayHeader;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        final PostDetailActivity postDetailActivity = this.this$0;
        ImageView imageView = (ImageView) helper.m3912b(R.id.iv_itemfile_img);
        LinearLayout linearLayout = (LinearLayout) helper.m3912b(R.id.ll_itemfile_video);
        postDetailActivity.setPlayer_postdetail((FullPlayerView) helper.m3912b(R.id.player_postdetail));
        if (!Intrinsics.areEqual(item.type, "video")) {
            imageView.setVisibility(0);
            linearLayout.setVisibility(8);
            String str = item.image;
            Intrinsics.checkNotNullExpressionValue(str, "item.image");
            postDetailActivity.loadPreviewImage(postDetailActivity, str, imageView);
            return;
        }
        imageView.setVisibility(8);
        linearLayout.setVisibility(0);
        if (Intrinsics.areEqual(item.tips, "")) {
            ((TextView) helper.m3912b(R.id.tv_tips_video_coin)).setVisibility(8);
        } else {
            ((TextView) helper.m3912b(R.id.tv_tips_video_coin)).setVisibility(0);
            ((TextView) helper.m3912b(R.id.tv_tips_video_coin)).setText(item.tips);
        }
        final FullPlayerView player_postdetail = postDetailActivity.getPlayer_postdetail();
        if (player_postdetail == null) {
            return;
        }
        player_postdetail.playerImage.setVisibility(0);
        String str2 = item.image;
        if (str2 == null) {
            str2 = "";
        }
        player_postdetail.loadCoverImage(str2);
        player_postdetail.setBottomShow(true);
        postDetailActivity.getBack().setVisibility(8);
        String str3 = item.video_link;
        String str4 = str3 == null ? "" : str3;
        videoPlayHeader = postDetailActivity.getVideoPlayHeader();
        player_postdetail.setUp(str4, true, (File) null, videoPlayHeader, "");
        player_postdetail.setSeekOnStart(0L);
        player_postdetail.setVideoAllCallBack(new MyVideoAllCallback() { // from class: com.jbzd.media.movecartoons.ui.post.topic.PostDetailActivity$fileAdapter$1$convert$1$1$1
            @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
            public void onPlayError(@Nullable String url, @NotNull Object... objects) {
                Intrinsics.checkNotNullParameter(objects, "objects");
            }

            @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
            public void onPrepared(@Nullable String url, @NotNull Object... objects) {
                Intrinsics.checkNotNullParameter(objects, "objects");
            }
        });
        player_postdetail.getFullscreenButton().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.k.f.w
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PostDetailActivity$fileAdapter$1.m5971convert$lambda3$lambda2$lambda0(PostDetailActivity.this, player_postdetail, view);
            }
        });
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.k.f.v
            @Override // java.lang.Runnable
            public final void run() {
                PostDetailActivity$fileAdapter$1.m5972convert$lambda3$lambda2$lambda1(FullPlayerView.this);
            }
        }, 500L);
    }
}
