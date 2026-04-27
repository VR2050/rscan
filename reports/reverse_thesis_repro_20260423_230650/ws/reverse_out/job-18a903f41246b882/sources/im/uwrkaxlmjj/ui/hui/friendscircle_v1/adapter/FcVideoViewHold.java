package im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter;

import android.view.View;
import android.widget.AdapterView;
import im.uwrkaxlmjj.ui.hui.adapter.SmartViewHolder;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.AutoPlayItemInterface;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.FcVideoPlayerView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcVideoViewHold extends SmartViewHolder implements AutoPlayItemInterface {
    private View itemView;
    private final FcVideoPlayerView rlFcDetailVideo;

    public FcVideoViewHold(View itemView, AdapterView.OnItemClickListener mListener) {
        super(itemView, mListener);
        this.itemView = itemView;
        this.rlFcDetailVideo = (FcVideoPlayerView) itemView.findViewById(R.attr.view_video);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.AutoPlayItemInterface
    public void setActive() {
        FcVideoPlayerView fcVideoPlayerView = this.rlFcDetailVideo;
        if (fcVideoPlayerView != null) {
            if (!fcVideoPlayerView.isViewPlaying()) {
                this.rlFcDetailVideo.newStartplay(this.itemView);
            } else if (!this.rlFcDetailVideo.getVideoPlayerMgr().isPlaying()) {
                this.rlFcDetailVideo.getVideoPlayerMgr().play();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.AutoPlayItemInterface
    public void deactivate() {
        FcVideoPlayerView fcVideoPlayerView = this.rlFcDetailVideo;
        if (fcVideoPlayerView != null && fcVideoPlayerView.isViewPlaying()) {
            this.rlFcDetailVideo.getVideoPlayerMgr().stop();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.AutoPlayItemInterface
    public View getAutoPlayView() {
        return this.rlFcDetailVideo;
    }
}
