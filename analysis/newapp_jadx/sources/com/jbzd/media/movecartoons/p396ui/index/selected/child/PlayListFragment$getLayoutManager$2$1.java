package com.jbzd.media.movecartoons.p396ui.index.selected.child;

import android.os.Handler;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment$getLayoutManager$2$1;
import com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.OnViewPagerListener;
import com.jbzd.media.movecartoons.view.video.ListPlayerView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0007*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u001f\u0010\t\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\t\u0010\nJ\u001f\u0010\f\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\f\u0010\r¨\u0006\u000e"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$getLayoutManager$2$1", "Lcom/jbzd/media/movecartoons/view/layoutmanagergroup/viewpager/OnViewPagerListener;", "", "onInitComplete", "()V", "", "isNext", "", "position", "onPageRelease", "(ZI)V", "isBottom", "onPageSelected", "(IZ)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PlayListFragment$getLayoutManager$2$1 implements OnViewPagerListener {
    public final /* synthetic */ PlayListFragment this$0;

    public PlayListFragment$getLayoutManager$2$1(PlayListFragment playListFragment) {
        this.this$0 = playListFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onInitComplete$lambda-0, reason: not valid java name */
    public static final void m5852onInitComplete$lambda0(PlayListFragment this$0) {
        int i2;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        i2 = this$0.mPosition;
        this$0.playVideo(i2);
    }

    @Override // com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.OnViewPagerListener
    public void onInitComplete() {
        Handler handler = new Handler();
        final PlayListFragment playListFragment = this.this$0;
        handler.postDelayed(new Runnable() { // from class: b.a.a.a.t.g.m.a.e
            @Override // java.lang.Runnable
            public final void run() {
                PlayListFragment$getLayoutManager$2$1.m5852onInitComplete$lambda0(PlayListFragment.this);
            }
        }, 300L);
    }

    @Override // com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.OnViewPagerListener
    public void onPageRelease(boolean isNext, int position) {
        try {
            this.this$0.addHistory(this.this$0.getAdapter().getData().get(position));
        } catch (Exception unused) {
        }
        Intrinsics.stringPlus("position=", Integer.valueOf(position));
    }

    @Override // com.jbzd.media.movecartoons.view.layoutmanagergroup.viewpager.OnViewPagerListener
    public void onPageSelected(int position, boolean isBottom) {
        int i2;
        ListPlayerView currentPlayer = this.this$0.getCurrentPlayer();
        if (currentPlayer != null) {
            currentPlayer.release();
        }
        i2 = this.this$0.previous;
        if (i2 == position) {
            return;
        }
        this.this$0.previous = position;
        this.this$0.mPosition = position;
        this.this$0.playVideo(position);
    }
}
