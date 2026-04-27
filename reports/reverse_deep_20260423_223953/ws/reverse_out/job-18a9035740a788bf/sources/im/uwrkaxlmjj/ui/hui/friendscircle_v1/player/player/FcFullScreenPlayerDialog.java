package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.view.Display;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.utils.Utils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.FcVideoPlayerView;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcFullScreenPlayerDialog extends Dialog implements View.OnTouchListener, SeekBar.OnSeekBarChangeListener {
    private static final int PROGRESS_UPDATE_INITIAL_INTERVAL = 100;
    private static final int PROGRESS_UPDATE_INTERNAL = 300;
    private boolean blnMute;
    Context context;
    public ImageView iv_mute;
    public ImageView iv_play;
    private LinearLayout ll_state_bar;
    private LinearLayout ll_title_bar;
    private int mDuration;
    private final ScheduledExecutorService mExecutorService;
    private ScheduledFuture<?> mScheduleFuture;
    private final Runnable mUpdateProgressTask;
    private VideoPlayerManager mVideoPlayerManager;
    DismissListener mdismissListener;
    RelativeLayout root_view;
    private TextView tv_current_time;
    private TextView tv_title;
    private TextView tv_total_time;
    private SeekBar videoPlayerSeekbar;

    public interface DismissListener {
        void doDismissCallback();
    }

    public FcFullScreenPlayerDialog(final Context context, FcVideoPlayerView player, float Ratio, String strTitle, DismissListener Listener) {
        super(context, R.plurals.DialogTheme);
        this.blnMute = false;
        this.mExecutorService = Executors.newSingleThreadScheduledExecutor();
        this.mUpdateProgressTask = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$4CFKh0lVh8HVQEXYukQkwVbQU1E
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$6$FcFullScreenPlayerDialog();
            }
        };
        this.mdismissListener = Listener;
        this.context = context;
        View view = getLayoutInflater().inflate(R.layout.dialog_fc_full_screen_player, (ViewGroup) null);
        this.root_view = (RelativeLayout) view.findViewById(R.attr.root_view);
        this.videoPlayerSeekbar = (SeekBar) view.findViewById(R.attr.fl_seekbar);
        this.tv_total_time = (TextView) view.findViewById(R.attr.tv_total_time);
        this.tv_current_time = (TextView) view.findViewById(R.attr.tv_current_time);
        this.iv_play = (ImageView) view.findViewById(R.attr.iv_play);
        this.iv_mute = (ImageView) view.findViewById(R.attr.iv_mute);
        this.ll_title_bar = (LinearLayout) view.findViewById(R.attr.ll_title_bar);
        this.ll_state_bar = (LinearLayout) view.findViewById(R.attr.ll_state_bar);
        this.tv_title = (TextView) view.findViewById(R.attr.tv_title);
        setContentView(view);
        getWindow().setLayout(-1, -1);
        Display display = ((Activity) context).getWindowManager().getDefaultDisplay();
        int width = display.getWidth();
        display.getHeight();
        int mVideoHeight = (int) (width / Ratio);
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(-1, mVideoHeight == 0 ? -2 : mVideoHeight, 17);
        this.root_view.addView(player, lp);
        this.ll_state_bar.setVisibility(0);
        this.ll_title_bar.setVisibility(0);
        VideoPlayerManager videoPlayerMgr = player.getVideoPlayerMgr();
        this.mVideoPlayerManager = videoPlayerMgr;
        this.mDuration = videoPlayerMgr.getDuration();
        this.tv_title.setText(strTitle);
        startVideoProgressUpdate();
        setCanceledOnTouchOutside(false);
        view.findViewById(R.attr.ll_return).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$oT-WtGZmoln_e9fp2CH8svh0Ndo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$0$FcFullScreenPlayerDialog(view2);
            }
        });
        view.findViewById(R.attr.colse_fullscreen).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$-xk0eR852GJst5Ko2KbXvYigBoA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$1$FcFullScreenPlayerDialog(view2);
            }
        });
        player.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.FcFullScreenPlayerDialog.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcFullScreenPlayerDialog.this.iv_play.getVisibility() == 8) {
                    FcFullScreenPlayerDialog.this.showControllerView();
                } else {
                    FcFullScreenPlayerDialog.this.hideControllerView();
                }
            }
        });
        this.iv_play.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$Yq_h1TPZ0Bixb6yW83FkVWsbpeI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$2$FcFullScreenPlayerDialog(view2);
            }
        });
        this.iv_mute.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$wAdxGxE1Xnw8JoUDbb6GVKh0koc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$3$FcFullScreenPlayerDialog(view2);
            }
        });
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$DRP9M-0Qh6mSr8Mp4K_7Cn1xw24
            @Override // java.lang.Runnable
            public final void run() {
                ((Activity) context).setRequestedOrientation(1);
            }
        }, 1000L);
        this.tv_total_time.setText(String.format("%02d:%02d", Integer.valueOf((this.mDuration / 1000) / 60), Integer.valueOf((this.mDuration / 1000) % 60)));
        this.videoPlayerSeekbar.setOnTouchListener(this);
        this.videoPlayerSeekbar.setOnSeekBarChangeListener(this);
    }

    public /* synthetic */ void lambda$new$0$FcFullScreenPlayerDialog(View v) {
        dismiss();
    }

    public /* synthetic */ void lambda$new$1$FcFullScreenPlayerDialog(View v) {
        dismiss();
    }

    public /* synthetic */ void lambda$new$2$FcFullScreenPlayerDialog(View v) {
        if (this.mVideoPlayerManager.getState() == 2) {
            this.mVideoPlayerManager.pause();
            this.iv_play.setImageResource(R.id.iv_pc_agent_description_video_btn_play);
        } else if (this.mVideoPlayerManager.getState() == 4) {
            this.mVideoPlayerManager.play();
            this.iv_play.setImageResource(R.id.iv_pc_agent_description_video_btn_stop);
            hideControllerView();
        }
    }

    public /* synthetic */ void lambda$new$3$FcFullScreenPlayerDialog(View v) {
        if (this.blnMute) {
            this.mVideoPlayerManager.setVolume(4);
            this.iv_mute.setImageResource(R.id.ic_game_share_unmute);
            this.blnMute = false;
        } else {
            this.mVideoPlayerManager.setVolume(0);
            this.iv_mute.setImageResource(R.id.ic_game_share_mute);
            this.blnMute = true;
        }
    }

    public void changeControllerState() {
        if (this.iv_play.getVisibility() == 8) {
            showControllerView();
        } else {
            hideControllerView();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showControllerView() {
        this.ll_title_bar.setVisibility(0);
        this.ll_state_bar.setVisibility(0);
        this.iv_play.setVisibility(0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideControllerView() {
        this.ll_title_bar.setVisibility(8);
        this.ll_state_bar.setVisibility(8);
        this.iv_play.setVisibility(8);
    }

    public View getView() {
        stopVideoProgressUpdate();
        View view = this.root_view.getChildAt(0);
        this.root_view.removeAllViews();
        dismiss();
        return view;
    }

    private void startVideoProgressUpdate() {
        stopVideoProgressUpdate();
        if (!this.mExecutorService.isShutdown()) {
            this.mScheduleFuture = this.mExecutorService.scheduleAtFixedRate(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FcFullScreenPlayerDialog$ulsnIJvD0OCVaRmv9KUUyGY-6fg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$startVideoProgressUpdate$5$FcFullScreenPlayerDialog();
                }
            }, 100L, 300L, TimeUnit.MILLISECONDS);
        }
    }

    public /* synthetic */ void lambda$startVideoProgressUpdate$5$FcFullScreenPlayerDialog() {
        AndroidUtilities.runOnUIThread(this.mUpdateProgressTask);
    }

    private void stopVideoProgressUpdate() {
        ScheduledFuture<?> scheduledFuture = this.mScheduleFuture;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
        }
    }

    public /* synthetic */ void lambda$new$6$FcFullScreenPlayerDialog() {
        VideoPlayerManager videoPlayerManager = this.mVideoPlayerManager;
        if (videoPlayerManager != null) {
            int position = videoPlayerManager.getCurrentPosition();
            updateProgress(position);
        }
    }

    private void updateProgress(int position) {
        this.tv_current_time.setText(Utils.formatVideoTimeLength(position));
        int i = position * 100;
        int i2 = this.mDuration;
        if (i2 == 0) {
            i2 = 1;
        }
        int progress = i / i2;
        this.videoPlayerSeekbar.setProgress(progress);
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        if (this.root_view.getChildAt(0) != null) {
            this.mdismissListener.doDismissCallback();
        }
        this.root_view.removeAllViews();
        super.dismiss();
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View v, MotionEvent event) {
        return false;
    }

    @Override // android.widget.SeekBar.OnSeekBarChangeListener
    public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
        if (fromUser) {
            int seekToTime = (seekBar.getProgress() * this.mDuration) / 100;
            this.mVideoPlayerManager.seekTo(seekToTime);
        }
    }

    @Override // android.widget.SeekBar.OnSeekBarChangeListener
    public void onStartTrackingTouch(SeekBar seekBar) {
    }

    @Override // android.widget.SeekBar.OnSeekBarChangeListener
    public void onStopTrackingTouch(SeekBar seekBar) {
    }
}
