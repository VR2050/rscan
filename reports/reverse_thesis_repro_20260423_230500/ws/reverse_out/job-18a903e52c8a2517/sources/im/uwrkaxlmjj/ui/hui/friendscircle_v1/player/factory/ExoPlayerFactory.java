package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory;

import android.content.Context;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.AbsBaseVideoPlayer;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.ExoVideoPlayer;

/* JADX INFO: loaded from: classes5.dex */
public class ExoPlayerFactory implements IVideoPlayerFactory {
    private Context mContext;
    private boolean mEnableLog;

    public ExoPlayerFactory(Context context) {
        this.mContext = context;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.IVideoPlayerFactory
    public AbsBaseVideoPlayer create() {
        return new ExoVideoPlayer(this.mContext, this.mEnableLog);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.IVideoPlayerFactory
    public void logEnable(boolean enableLog) {
        this.mEnableLog = enableLog;
    }
}
